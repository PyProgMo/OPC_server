using System.CommandLine;
using OpcSuite.Crypto;

namespace OpcSuite.Cli;

/// <summary>The <c>trust</c> and <c>cert</c> commands, identical for server and client.</summary>
public static class TrustCommands
{
    public static Option<string> CreatePkiOption(string role) => new("--pki")
    {
        Description = "Folder holding this application's certificates and trust lists",
        DefaultValueFactory = _ => CliDefaults.DefaultPki(role),
        Recursive = true,
    };

    public static Command CreateTrust(Option<string> pkiOption)
    {
        var trust = new Command("trust", "Manage which peer certificates are trusted");

        var list = new Command("list", "Show the trusted and the rejected certificates");
        list.SetAction(async (parseResult, ct) =>
        {
            var store = OpenStore(parseResult.GetValue(pkiOption)!);
            Print("Trusted", await store.ListAsync(TrustList.Trusted, ct));
            Print("Rejected (peers that tried to connect but are not trusted yet)", await store.ListAsync(TrustList.Rejected, ct));
            return 0;
        });

        var accept = new Command("accept", "Trust a rejected certificate after verifying its fingerprint out-of-band");
        var acceptFingerprint = FingerprintArgument();
        accept.Arguments.Add(acceptFingerprint);
        accept.SetAction(async (parseResult, ct) =>
        {
            var store = OpenStore(parseResult.GetValue(pkiOption)!);
            var trusted = await store.TrustRejectedAsync(parseResult.GetValue(acceptFingerprint)!, ct);
            Console.WriteLine($"Now trusted: {trusted.Subject}  SHA-256 {Fingerprint.Format(trusted.Sha256Fingerprint)}");
            return 0;
        });

        var import = new Command("import", "Trust a certificate file (.der, .pem, .crt) received from the peer");
        var importFile = new Argument<FileInfo>("file") { Description = "Certificate file" };
        import.Arguments.Add(importFile);
        import.SetAction(async (parseResult, ct) =>
        {
            var store = OpenStore(parseResult.GetValue(pkiOption)!);
            var trusted = await store.ImportTrustedAsync(parseResult.GetValue(importFile)!.FullName, ct);
            Console.WriteLine($"Now trusted: {trusted.Subject}  SHA-256 {Fingerprint.Format(trusted.Sha256Fingerprint)}");
            return 0;
        });

        var remove = new Command("remove", "Stop trusting a certificate");
        var removeFingerprint = FingerprintArgument();
        remove.Arguments.Add(removeFingerprint);
        remove.SetAction(async (parseResult, ct) =>
        {
            var store = OpenStore(parseResult.GetValue(pkiOption)!);
            var removed = await store.RemoveTrustedAsync(parseResult.GetValue(removeFingerprint)!, ct);
            Console.WriteLine($"No longer trusted: {removed.Subject}  SHA-256 {Fingerprint.Format(removed.Sha256Fingerprint)}");
            return 0;
        });

        trust.Subcommands.Add(list);
        trust.Subcommands.Add(accept);
        trust.Subcommands.Add(import);
        trust.Subcommands.Add(remove);
        return trust;
    }

    public static Command CreateCert(Option<string> pkiOption)
    {
        var cert = new Command("cert", "Show this application's own certificate - give its fingerprint (or file) to the peer");
        cert.SetAction(async (parseResult, ct) =>
        {
            var store = OpenStore(parseResult.GetValue(pkiOption)!);
            var own = await store.ListOwnAsync(ct);
            if (own.Count == 0)
            {
                Console.WriteLine("No certificate yet. It is created the first time the application starts or connects.");
                return 0;
            }

            foreach (var c in own)
            {
                Console.WriteLine(c.Subject);
                Console.WriteLine($"  SHA-256   {Fingerprint.Format(c.Sha256Fingerprint)}");
                Console.WriteLine($"  valid     {c.NotBeforeUtc:yyyy-MM-dd} .. {c.NotAfterUtc:yyyy-MM-dd}");
                Console.WriteLine($"  app uri   {c.ApplicationUri}");
            }
            foreach (var file in store.OwnCertificateFiles())
            {
                Console.WriteLine($"  file      {file}");
            }
            return 0;
        });
        return cert;
    }

    private static Argument<string> FingerprintArgument() => new("fingerprint")
    {
        Description = "SHA-256 fingerprint or SHA-1 thumbprint, or at least its first 8 hex digits (colons optional)",
    };

    private static TrustStore OpenStore(string pkiRoot) => new(PkiLayout.In(pkiRoot), CliDefaults.CreateTelemetry());

    private static void Print(string title, IReadOnlyList<CertificateSummary> certificates)
    {
        Console.WriteLine($"{title}: {(certificates.Count == 0 ? "none" : certificates.Count)}");
        foreach (var c in certificates)
        {
            Console.WriteLine($"  {Fingerprint.Format(c.Sha256Fingerprint)}");
            Console.WriteLine($"    {c.Subject}  valid until {c.NotAfterUtc:yyyy-MM-dd}");
        }
    }
}
