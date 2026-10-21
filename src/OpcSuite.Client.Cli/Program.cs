using System.CommandLine;
using OpcSuite.Cli;
using OpcSuite.Client;
using OpcSuite.Client.Cli;
using OpcSuite.Crypto;

var options = new GlobalOptions();

var root = new RootCommand(
    "OpcSuite OPC UA client. Connects only over a signed and encrypted (SHA-256) channel " +
    "and only to servers whose certificate you trust.");
root.Options.Add(options.Endpoint);
root.Options.Add(options.Pki);
root.Options.Add(options.Security);
root.Options.Add(options.TrustServer);
root.Options.Add(options.SkipHostCheck);
root.Options.Add(options.LogLevel);

foreach (var command in ClientCommands.Create(new ConnectEachTime(options)))
{
    root.Subcommands.Add(command);
}
root.Subcommands.Add(HandshakeCommand.Create(options));
root.Subcommands.Add(ShellCommand.Create(options));
root.Subcommands.Add(EndpointsCommand(options));
root.Subcommands.Add(TrustCommands.CreateTrust(options.Pki));
root.Subcommands.Add(TrustCommands.CreateCert(options.Pki));

return await CliRunner.RunAsync(root, args);

static Command EndpointsCommand(GlobalOptions options)
{
    var endpoints = new Command("endpoints", "Show what the server advertises (unauthenticated - verify the SHA-256 out-of-band)");
    endpoints.SetAction(async (parseResult, ct) =>
    {
        var settings = options.Read(parseResult);
        var (crypto, telemetry) = Connector.CreateCrypto(settings);
        foreach (var endpoint in await OpcClient.GetEndpointsAsync(settings.Endpoint, crypto, telemetry, ct: ct))
        {
            var policy = endpoint.SecurityPolicyUri.Split('#').Last();
            Console.WriteLine($"{endpoint.EndpointUrl}  {policy} / {endpoint.SecurityMode}");
            if (endpoint.ServerCertificate is { Length: > 0 })
            {
                var cert = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(endpoint.ServerCertificate);
                Console.WriteLine($"  certificate {cert.Subject}");
                Console.WriteLine($"  SHA-256     {Fingerprint.Format(Fingerprint.Sha256(cert))}");
            }
        }
        return 0;
    });
    return endpoints;
}
