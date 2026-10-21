using System.Text;
using OpcSuite.Server.Security;
using Xunit;

namespace OpcSuite.Tests;

public sealed class SecurityUnitTests : IDisposable
{
    private readonly string _folder = Path.Combine(Path.GetTempPath(), "opcsuite-unit-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_folder))
        {
            Directory.Delete(_folder, recursive: true);
        }
    }

    [Fact]
    public void Password_hashes_are_salted_and_only_match_the_password()
    {
        var first = PasswordHash.Create("s3cret password", iterations: 1000);
        var second = PasswordHash.Create("s3cret password", iterations: 1000);

        Assert.NotEqual(first, second);
        Assert.StartsWith("pbkdf2-sha256$1000$", first);
        Assert.True(PasswordHash.Verify("s3cret password"u8, first));
        Assert.False(PasswordHash.Verify("s3cret Password"u8, first));
        Assert.False(PasswordHash.Verify("s3cret password"u8, "pbkdf2-sha256$1000$not base64$x"));
        Assert.False(PasswordHash.IsWellFormed("plain text"));
    }

    [Theory]
    [InlineData("operator", true)]
    [InlineData(" Engineer ", true)]
    [InlineData("3", false)]
    [InlineData("Operator,Engineer", false)]
    [InlineData("Admin", false)]
    public void Role_names_are_parsed_strictly(string text, bool expected) =>
        Assert.Equal(expected, UserRoles.TryParse(text, out _));

    [Fact]
    public void The_rule_with_the_longest_matching_path_decides_alone()
    {
        var policy = AccessPolicy.Parse("""
            {
              "default": { "AuthenticatedUser": "read" },
              "nodes": {
                "/Pump/": { "Operator": "write" },
                "Pump/Limits": { "Engineer": "write", "Operator": "read" }
              }
            }
            """);

        Assert.Equal(NodePermission.Read, policy.RuleFor("Demo/Counter").For(UserRole.AuthenticatedUser));
        Assert.Equal(NodePermission.Write, policy.RuleFor("Pump/Speed").For(UserRole.Operator));
        // a rule replaces the one above it completely: the default's AuthenticatedUser read does not carry over
        Assert.Equal(NodePermission.None, policy.RuleFor("Pump/Speed").For(UserRole.AuthenticatedUser));
        Assert.Equal(NodePermission.Read, policy.RuleFor("Pump/Limits/Max").For(UserRole.Operator));
        Assert.Equal(NodePermission.Write, policy.RuleFor("Pump/Limits/Max").For(UserRole.Engineer));
        // "Pump/Limit" is not below "Pump/Limits"
        Assert.Equal(NodePermission.Write, policy.RuleFor("Pump/Limit").For(UserRole.Operator));
    }

    [Theory]
    [InlineData("""{ "nodes": { "Demo": { "Admin": "read" } } }""", "unknown role 'Admin'")]
    [InlineData("""{ "nodes": { "Demo": { "Operator": "rw" } } }""", "must be \"none\", \"read\" or \"write\"")]
    [InlineData("""{ "rules": {} }""", "unknown setting \"rules\"")]
    [InlineData("""{ "nodes": { "": { } } }""", "empty node path")]
    [InlineData("""[]""", "expected an object")]
    public void Mistakes_in_the_access_rules_are_reported(string json, string message)
    {
        var error = Assert.Throws<InvalidDataException>(() => AccessPolicy.Parse(json, "access.json"));
        Assert.Contains(message, error.Message);
        Assert.StartsWith("access.json: ", error.Message);
    }

    [Fact]
    public void Login_throttle_locks_a_name_after_repeated_failures()
    {
        var time = new ManualTime();
        var throttle = new LoginThrottle(maxFailures: 3, lockout: TimeSpan.FromMinutes(1), time);

        for (var i = 0; i < 3; i++)
        {
            Assert.False(throttle.IsLockedOut("Alice", out _));
            throttle.RecordFailure("alice");
        }
        Assert.True(throttle.IsLockedOut("ALICE", out var remaining));
        Assert.Equal(TimeSpan.FromMinutes(1), remaining);
        Assert.False(throttle.IsLockedOut("bob", out _));

        // after the lockout one more attempt is allowed; failing it locks again at once
        time.Advance(TimeSpan.FromSeconds(61));
        Assert.False(throttle.IsLockedOut("alice", out _));
        throttle.RecordFailure("alice");
        Assert.True(throttle.IsLockedOut("alice", out _));

        // a success forgets the failures
        time.Advance(TimeSpan.FromSeconds(61));
        throttle.RecordSuccess("alice");
        throttle.RecordFailure("alice");
        Assert.False(throttle.IsLockedOut("alice", out _));

        // so does a quiet quarter of an hour
        throttle.RecordFailure("alice");
        throttle.RecordFailure("alice");
        Assert.True(throttle.IsLockedOut("alice", out _));
        time.Advance(TimeSpan.FromMinutes(16));
        throttle.RecordFailure("alice");
        Assert.False(throttle.IsLockedOut("alice", out _));
    }

    [Fact]
    public void User_store_keeps_users_with_roles_passwords_and_certificates()
    {
        var store = new UserStore(Path.Combine(_folder, "users.json"));
        store.Add("Alice", "first password", [UserRole.Operator, UserRole.Operator]);
        store.Add("bob", password: null, []);
        var certificate = new string('A', 64);
        store.AddCertificate("bob", certificate.ToLowerInvariant());

        // a second store on the same file, as the CLI and the running server have
        var other = new UserStore(store.FilePath);
        var alice = Assert.IsType<UserAccount>(other.Find("alice"));
        Assert.Equal("Alice", alice.Name);
        Assert.Equal(new[] { UserRole.Operator }, alice.Roles);
        Assert.NotNull(other.CheckPassword("ALICE", "first password"u8));
        Assert.Null(other.CheckPassword("alice", "First password"u8));
        Assert.Null(other.CheckPassword("bob", ""u8));
        Assert.Equal("bob", other.FindByCertificate(certificate)?.Name);

        store.SetPassword("alice", "second password");
        Assert.Null(other.CheckPassword("alice", "first password"u8));
        Assert.NotNull(other.CheckPassword("alice", Encoding.UTF8.GetBytes("second password")));

        store.RemoveCertificate("bob", "aaaaaaaa");
        Assert.Null(other.FindByCertificate(certificate));
        store.Remove("bob");
        Assert.Single(other.List());

        // the file holds hashes, never the passwords
        Assert.DoesNotContain("second password", File.ReadAllText(store.FilePath));
    }

    [Fact]
    public void User_store_refuses_what_would_be_ambiguous_or_weak()
    {
        var store = new UserStore(Path.Combine(_folder, "users.json"));
        store.Add("alice", "long enough", [UserRole.Engineer]);
        store.Add("bob", "long enough", []);
        store.AddCertificate("alice", new string('B', 64));

        Assert.Throws<InvalidOperationException>(() => store.Add("ALICE", "long enough", []));
        Assert.Throws<InvalidOperationException>(() => store.AddCertificate("bob", new string('B', 64)));
        Assert.Throws<ArgumentException>(() => store.Add("carol", "short", []));
        Assert.Throws<ArgumentException>(() => store.Add("bad name", "long enough", []));
        Assert.Throws<ArgumentException>(() => store.SetRoles("bob", [UserRole.AuthenticatedUser]));
        Assert.Throws<ArgumentException>(() => store.AddCertificate("bob", "ABCD"));
        Assert.Throws<KeyNotFoundException>(() => store.Remove("dave"));
    }

    [Fact]
    public void A_broken_users_file_is_reported_with_its_name()
    {
        var file = Path.Combine(_folder, "users.json");
        Directory.CreateDirectory(_folder);
        File.WriteAllText(file, """{ "users": [ { "name": "eve", "roles": ["Root"] } ] }""");

        var error = Assert.Throws<InvalidDataException>(() => new UserStore(file).List());
        Assert.Contains(file, error.Message);
        Assert.Contains("Unknown role 'Root'", error.Message);
    }

    private sealed class ManualTime : TimeProvider
    {
        private DateTimeOffset _now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

        public override DateTimeOffset GetUtcNow() => _now;

        public void Advance(TimeSpan by) => _now += by;
    }
}
