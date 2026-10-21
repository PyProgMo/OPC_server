using System.CommandLine;
using OpcSuite.Crypto;

namespace OpcSuite.Client.Cli;

/// <summary><c>opcctl user-cert</c>: make and list the certificates a user can log in with instead of a password.</summary>
internal static class UserCertCommand
{
    public static Command Create(GlobalOptions options)
    {
        var userCert = new Command("user-cert", "Manage user certificates (log in with --user-cert instead of a password)");

        var create = new Command("create", "Make a key pair and certificate for a user; only its fingerprint goes to the server operator");
        var name = new Argument<string>("name") { Description = "Name of the certificate, normally the user name on the server" };
        var days = new Option<int>("--days") { Description = "How long the certificate is valid", DefaultValueFactory = _ => 365 };
        create.Arguments.Add(name);
        create.Options.Add(days);
        create.SetAction(parseResult =>
        {
            var directory = UserCertificates.DirectoryOf(PkiLayout.In(parseResult.GetValue(options.Pki)!));
            var label = parseResult.GetValue(name)!;
            using var certificate = UserCertificates.Create(directory, label, TimeSpan.FromDays(parseResult.GetValue(days)));
            var fingerprint = Fingerprint.Sha256(certificate);
            Console.WriteLine($"Created user certificate '{label}'  {certificate.Subject}");
            Console.WriteLine($"  SHA-256   {Fingerprint.Format(fingerprint)}");
            Console.WriteLine($"  valid     until {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd}");
            Console.WriteLine($"  files     {directory} ({label}.pfx holds the private key - keep it here)");
            Console.WriteLine();
            Console.WriteLine("Ask the server operator to register it for your user (compare the SHA-256 with them):");
            Console.WriteLine($"  opcserver user cert add {label} {fingerprint}");
            Console.WriteLine($"Then log in with: opcctl --user-cert {label} ...");
            return 0;
        });

        var list = new Command("list", "Show the user certificates of this client");
        list.SetAction(parseResult =>
        {
            var directory = UserCertificates.DirectoryOf(PkiLayout.In(parseResult.GetValue(options.Pki)!));
            var certificates = UserCertificates.List(directory);
            Console.WriteLine($"User certificates in {directory}: {(certificates.Count == 0 ? "none" : certificates.Count)}");
            foreach (var (label, c) in certificates)
            {
                Console.WriteLine($"  {label}  {c.Subject}  valid until {c.NotAfterUtc:yyyy-MM-dd}");
                Console.WriteLine($"    {Fingerprint.Format(c.Sha256Fingerprint)}");
            }
            return 0;
        });

        userCert.Subcommands.Add(create);
        userCert.Subcommands.Add(list);
        return userCert;
    }
}
