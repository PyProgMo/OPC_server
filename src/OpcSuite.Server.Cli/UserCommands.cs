using System.CommandLine;
using System.Security.Cryptography.X509Certificates;
using OpcSuite.Cli;
using OpcSuite.Crypto;
using OpcSuite.Server.Security;

namespace OpcSuite.Server.Cli;

/// <summary>The <c>user</c> commands: who may log in, how, and with which roles. Changes apply to a running server at once.</summary>
internal static class UserCommands
{
    public static Option<string> CreateUsersOption() => new("--users")
    {
        Description = "File with the users who may log in (managed with 'opcserver user ...')",
        DefaultValueFactory = _ => CliDefaults.DefaultFile("server", "users.json"),
        Recursive = true,
    };

    public static Command Create(Option<string> usersOption)
    {
        var user = new Command("user", "Manage who may log in, how, and with which roles");

        var list = new Command("list", "Show the users, their roles and how they log in");
        list.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var accounts = store.List();
            Console.WriteLine($"Users in {store.FilePath}: {(accounts.Count == 0 ? "none" : accounts.Count)}");
            foreach (var account in accounts)
            {
                Console.WriteLine($"  {account.Name,-20} {Roles(account),-28} {Logins(account)}");
            }
            Console.WriteLine("Every user also has the role AuthenticatedUser.");
            return 0;
        });

        var add = new Command("add", $"Add a user; the password is asked for, or read from {Passwords.EnvironmentVariable}");
        var addName = NameArgument();
        var addRoles = RolesOption();
        var noPassword = new Option<bool>("--no-password") { Description = "Certificate login only (add one with 'opcserver user cert add')" };
        add.Arguments.Add(addName);
        add.Options.Add(addRoles);
        add.Options.Add(noPassword);
        add.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var name = parseResult.GetValue(addName)!;
            var roles = ParseRoles(parseResult.GetValue(addRoles));
            if (store.Find(name) is not null)
            {
                throw new InvalidOperationException($"A user named '{name}' already exists.");
            }
            var password = parseResult.GetValue(noPassword) ? null : Passwords.Read($"Password for {name}: ", confirm: true);
            var account = store.Add(name, password, roles);
            Console.WriteLine($"Added {account.Name}: {Roles(account)}, logs in with {Logins(account)}");
            return 0;
        });

        var passwd = new Command("passwd", $"Set a user's password; asked for, or read from {Passwords.EnvironmentVariable}");
        var passwdName = NameArgument();
        var removePassword = new Option<bool>("--remove") { Description = "Remove the password: the user can then only log in with a certificate" };
        passwd.Arguments.Add(passwdName);
        passwd.Options.Add(removePassword);
        passwd.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var name = parseResult.GetValue(passwdName)!;
            var account = store.Find(name) ?? throw new KeyNotFoundException($"There is no user named '{name}'.");
            var password = parseResult.GetValue(removePassword) ? null : Passwords.Read($"New password for {account.Name}: ", confirm: true);
            account = store.SetPassword(name, password);
            Console.WriteLine($"{account.Name} now logs in with {Logins(account)}");
            return 0;
        });

        var roles = new Command("roles", "Replace a user's roles (none given: only AuthenticatedUser)");
        var rolesName = NameArgument();
        var rolesList = new Argument<string[]>("roles")
        {
            Description = $"Roles: {string.Join(", ", UserRoles.Assignable)}",
            Arity = ArgumentArity.ZeroOrMore,
        };
        roles.Arguments.Add(rolesName);
        roles.Arguments.Add(rolesList);
        roles.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var account = store.SetRoles(parseResult.GetValue(rolesName)!, ParseRoles(parseResult.GetValue(rolesList)));
            Console.WriteLine($"{account.Name}: {Roles(account)}");
            return 0;
        });

        var remove = new Command("remove", "Remove a user; it cannot log in any more (open sessions stay until they end)");
        var removeName = NameArgument();
        remove.Arguments.Add(removeName);
        remove.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var account = store.Remove(parseResult.GetValue(removeName)!);
            Console.WriteLine($"Removed {account.Name}");
            return 0;
        });

        user.Subcommands.Add(list);
        user.Subcommands.Add(add);
        user.Subcommands.Add(passwd);
        user.Subcommands.Add(roles);
        user.Subcommands.Add(remove);
        user.Subcommands.Add(CreateCert(usersOption));
        return user;
    }

    private static Command CreateCert(Option<string> usersOption)
    {
        var cert = new Command("cert", "Manage the user certificates a user can log in with");

        var add = new Command("add", "Let a user log in with a certificate (made on the client with 'opcctl user-cert create')");
        var addName = NameArgument();
        var certificate = new Argument<string>("certificate")
        {
            Description = "The certificate's SHA-256 fingerprint (as printed by opcctl, verified with the user), or its .der/.pem file",
        };
        add.Arguments.Add(addName);
        add.Arguments.Add(certificate);
        add.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var given = parseResult.GetValue(certificate)!;
            var fingerprint = given;
            if (File.Exists(given))
            {
                using var loaded = X509CertificateLoader.LoadCertificateFromFile(given);
                fingerprint = Fingerprint.Sha256(loaded);
                Console.WriteLine($"Certificate {loaded.Subject}, valid until {loaded.NotAfter.ToUniversalTime():yyyy-MM-dd}");
            }
            var account = store.AddCertificate(parseResult.GetValue(addName)!, fingerprint);
            Console.WriteLine($"{account.Name} can now log in with the certificate SHA-256 {Fingerprint.Format(Fingerprint.Normalize(fingerprint))}");
            return 0;
        });

        var remove = new Command("remove", "Stop a user from logging in with one of its certificates");
        var removeName = NameArgument();
        var removeFingerprint = new Argument<string>("fingerprint") { Description = "SHA-256 fingerprint, or at least its first 8 hex digits" };
        remove.Arguments.Add(removeName);
        remove.Arguments.Add(removeFingerprint);
        remove.SetAction(parseResult =>
        {
            var store = new UserStore(parseResult.GetValue(usersOption)!);
            var account = store.RemoveCertificate(parseResult.GetValue(removeName)!, parseResult.GetValue(removeFingerprint)!);
            Console.WriteLine($"{account.Name} now logs in with {Logins(account)}");
            return 0;
        });

        cert.Subcommands.Add(add);
        cert.Subcommands.Add(remove);
        return cert;
    }

    private static Argument<string> NameArgument() => new("name") { Description = "User name" };

    private static Option<string[]> RolesOption() => new("--role", "-r")
    {
        Description = $"Give the user a role (repeat for several): {string.Join(", ", UserRoles.Assignable)}",
        AllowMultipleArgumentsPerToken = true,
    };

    private static IReadOnlyList<UserRole> ParseRoles(string[]? names) =>
        (names ?? [])
            .Select(n => UserRoles.TryParse(n, out var role) && role.IsAssignable()
                ? role
                : throw new ArgumentException($"'{n}' is not a role a user can have. Roles: {string.Join(", ", UserRoles.Assignable)}."))
            .ToList();

    private static string Roles(UserAccount account) =>
        account.Roles.Count == 0 ? "no roles" : "roles " + string.Join(", ", account.Roles);

    private static string Logins(UserAccount account)
    {
        var logins = new List<string>();
        if (account.HasPassword)
        {
            logins.Add("password");
        }
        logins.AddRange(account.CertificateSha256.Select(c => $"certificate {c[..16]}"));
        return logins.Count == 0 ? "nothing yet (cannot log in)" : string.Join(", ", logins);
    }
}
