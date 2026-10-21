using System.Text.Json;
using System.Text.Json.Serialization;
using OpcSuite.Crypto;

namespace OpcSuite.Server.Security;

/// <summary>A user that may log in, as listed by <see cref="UserStore"/>. Holds no secrets.</summary>
public sealed record UserAccount(string Name, IReadOnlyList<UserRole> Roles, bool HasPassword, IReadOnlyList<string> CertificateSha256);

/// <summary>
/// The users of the server, kept in one JSON file. Passwords are stored as salted PBKDF2-SHA256 hashes and user
/// certificates by their SHA-256 fingerprint, so the file holds nothing that lets someone log in; it should still be
/// readable only by the server's account (it is created that way on Linux and macOS).
/// The file is read again whenever it changes, so users added with <c>opcserver user add</c> can log in without a restart.
/// </summary>
public sealed class UserStore
{
    public const int MinimumPasswordLength = 8;
    private const int MaxNameLength = 64;

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    // checked when the user does not exist, so that a wrong name takes as long as a wrong password
    private static readonly Lazy<string> DummyHash = new(() => PasswordHash.Create("no such user"));

    private readonly Lock _lock = new();
    private Snapshot? _snapshot;

    public UserStore(string filePath) => FilePath = Path.GetFullPath(filePath);

    public string FilePath { get; }

    public IReadOnlyList<UserAccount> List() => Current().Select(ToAccount).ToList();

    public UserAccount? Find(string name) => Current().FirstOrDefault(u => SameName(u.Name, name)) is { } entry ? ToAccount(entry) : null;

    /// <summary>Adds a user. Without a password the user can only log in with a certificate added later.</summary>
    public UserAccount Add(string name, string? password, IEnumerable<UserRole> roles) => Modify(users =>
    {
        ValidateName(name);
        if (users.Any(u => SameName(u.Name, name)))
        {
            throw new InvalidOperationException($"A user named '{users.First(u => SameName(u.Name, name)).Name}' already exists.");
        }
        var entry = new UserEntry { Name = name, Roles = RoleNames(roles), Password = password is null ? null : HashPassword(password) };
        users.Add(entry);
        return entry;
    });

    /// <summary>Sets a new password; <c>null</c> removes it, so the user can only log in with a certificate.</summary>
    public UserAccount SetPassword(string name, string? password) => Modify(users =>
    {
        var entry = Get(users, name);
        entry.Password = password is null ? null : HashPassword(password);
        return entry;
    });

    public UserAccount SetRoles(string name, IEnumerable<UserRole> roles) => Modify(users =>
    {
        var entry = Get(users, name);
        entry.Roles = RoleNames(roles);
        return entry;
    });

    /// <summary>Lets the user log in with the certificate that has this SHA-256 fingerprint.</summary>
    public UserAccount AddCertificate(string name, string sha256Fingerprint) => Modify(users =>
    {
        var fingerprint = Fingerprint.Normalize(sha256Fingerprint);
        if (fingerprint.Length != 64)
        {
            throw new ArgumentException($"Expected the full SHA-256 fingerprint (64 hex digits), got '{sha256Fingerprint}'.");
        }
        var entry = Get(users, name);
        if (users.FirstOrDefault(u => u.Certificates.Contains(fingerprint)) is { } owner && owner != entry)
        {
            throw new InvalidOperationException($"This certificate already belongs to user '{owner.Name}'.");
        }
        if (!entry.Certificates.Contains(fingerprint))
        {
            entry.Certificates.Add(fingerprint);
        }
        return entry;
    });

    /// <summary>Removes one of the user's certificates. <paramref name="fingerprint"/> may be a unique prefix of 8+ hex digits.</summary>
    public UserAccount RemoveCertificate(string name, string fingerprint) => Modify(users =>
    {
        var wanted = Fingerprint.Normalize(fingerprint);
        if (wanted.Length < 8)
        {
            throw new ArgumentException("Give at least the first 8 hex digits of the SHA-256 fingerprint.");
        }
        var entry = Get(users, name);
        var matches = entry.Certificates.Where(c => c.StartsWith(wanted, StringComparison.Ordinal)).ToList();
        entry.Certificates.Remove(matches.Count switch
        {
            1 => matches[0],
            0 => throw new KeyNotFoundException($"User '{entry.Name}' has no certificate matching '{fingerprint}'."),
            _ => throw new ArgumentException($"'{fingerprint}' matches {matches.Count} certificates of '{entry.Name}'; use a longer prefix."),
        });
        return entry;
    });

    public UserAccount Remove(string name) => Modify(users =>
    {
        var entry = Get(users, name);
        users.Remove(entry);
        return entry;
    });

    /// <summary>The user with this name and password, or <c>null</c>. Takes as long for unknown users as for wrong passwords.</summary>
    public UserAccount? CheckPassword(string name, ReadOnlySpan<byte> passwordUtf8)
    {
        var entry = Current().FirstOrDefault(u => SameName(u.Name, name));
        var matches = PasswordHash.Verify(passwordUtf8, entry?.Password ?? DummyHash.Value);
        return matches && entry?.Password is not null ? ToAccount(entry) : null;
    }

    /// <summary>The user who registered the certificate with this SHA-256 fingerprint, or <c>null</c>.</summary>
    public UserAccount? FindByCertificate(string sha256Fingerprint)
    {
        var fingerprint = Fingerprint.Normalize(sha256Fingerprint);
        return Current().FirstOrDefault(u => u.Certificates.Contains(fingerprint)) is { } entry ? ToAccount(entry) : null;
    }

    private IReadOnlyList<UserEntry> Current()
    {
        lock (_lock)
        {
            var file = new FileInfo(FilePath);
            var stamp = file.Exists ? (file.LastWriteTimeUtc, file.Length) : (DateTime.MinValue, -1L);
            if (_snapshot is null || _snapshot.Stamp != stamp)
            {
                _snapshot = new Snapshot(stamp, Read());
            }
            return _snapshot.Users;
        }
    }

    private UserAccount Modify(Func<List<UserEntry>, UserEntry> change)
    {
        lock (_lock)
        {
            // always start from the file, which another process (the CLI, the server) may have changed
            var users = Read();
            var changed = change(users);
            Write(users);
            _snapshot = null;
            return ToAccount(changed);
        }
    }

    private List<UserEntry> Read()
    {
        if (!File.Exists(FilePath))
        {
            return [];
        }

        UserFile? content;
        try
        {
            content = JsonSerializer.Deserialize<UserFile>(File.ReadAllText(FilePath), Json);
        }
        catch (JsonException ex)
        {
            throw Invalid($"not a valid users file: {ex.Message}");
        }

        var users = content?.Users ?? [];
        foreach (var user in users)
        {
            user.Name = user.Name?.Trim() ?? "";
            user.Roles ??= [];
            user.Certificates ??= [];
            try
            {
                ValidateName(user.Name);
                user.Roles = RoleNames(user.Roles.Select(UserRoles.Parse));
                user.Certificates = user.Certificates.Select(Fingerprint.Normalize).ToList();
            }
            catch (ArgumentException ex)
            {
                throw Invalid($"user '{user.Name}': {ex.Message}");
            }
            if (user.Password is not null && !PasswordHash.IsWellFormed(user.Password))
            {
                throw Invalid($"user '{user.Name}': the password hash is not in the pbkdf2-sha256 format.");
            }
            if (user.Certificates.FirstOrDefault(c => c.Length != 64) is { } bad)
            {
                throw Invalid($"user '{user.Name}': '{bad}' is not a SHA-256 fingerprint.");
            }
        }
        if (users.GroupBy(u => u.Name, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1) is { } twice)
        {
            throw Invalid($"user '{twice.Key}' is listed more than once.");
        }
        if (users.SelectMany(u => u.Certificates.Select(c => (u.Name, Certificate: c)))
                .GroupBy(x => x.Certificate).FirstOrDefault(g => g.Count() > 1) is { } shared)
        {
            throw Invalid($"certificate {shared.Key[..16]}... belongs to several users ({string.Join(", ", shared.Select(x => x.Name))}).");
        }
        return users;
    }

    private void Write(List<UserEntry> users)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
        var temporary = FilePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(new UserFile { Users = users }, Json));
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(temporary, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        // replace in one step, so a server reading the file never sees half of it
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                File.Move(temporary, FilePath, overwrite: true);
                return;
            }
            catch (IOException) when (attempt < 5)
            {
                // on Windows the server may be reading the file at this very moment
                Thread.Sleep(50);
            }
        }
    }

    private static UserEntry Get(List<UserEntry> users, string name) =>
        users.FirstOrDefault(u => SameName(u.Name, name)) ?? throw new KeyNotFoundException($"There is no user named '{name}'.");

    private static bool SameName(string a, string b) => string.Equals(a, b?.Trim(), StringComparison.OrdinalIgnoreCase);

    private static void ValidateName(string name)
    {
        if (string.IsNullOrWhiteSpace(name) || name.Length > MaxNameLength
            || !name.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '@'))
        {
            throw new ArgumentException(
                $"'{name}' is not a valid user name: use 1 to {MaxNameLength} letters, digits and . _ - @");
        }
    }

    private static string HashPassword(string password)
    {
        if (password.Length < MinimumPasswordLength)
        {
            throw new ArgumentException($"Passwords need at least {MinimumPasswordLength} characters.");
        }
        return PasswordHash.Create(password);
    }

    private static List<string> RoleNames(IEnumerable<UserRole> roles)
    {
        var list = roles.Distinct().Order().ToList();
        foreach (var role in list.Where(r => !r.IsAssignable()))
        {
            throw new ArgumentException($"{role} cannot be given to a user; it is implied (every logged-in user is an AuthenticatedUser).");
        }
        return list.Select(r => r.ToString()).ToList();
    }

    private static UserAccount ToAccount(UserEntry entry) => new(
        entry.Name,
        entry.Roles.Select(UserRoles.Parse).ToList(),
        entry.Password is not null,
        entry.Certificates.ToList());

    private InvalidDataException Invalid(string problem) => new($"{FilePath}: {problem}");

    private sealed record Snapshot((DateTime, long) Stamp, IReadOnlyList<UserEntry> Users);

    private sealed class UserFile
    {
        public List<UserEntry> Users { get; set; } = [];
    }

    private sealed class UserEntry
    {
        public string Name { get; set; } = "";
        public List<string> Roles { get; set; } = [];
        public string? Password { get; set; }
        public List<string> Certificates { get; set; } = [];
    }
}
