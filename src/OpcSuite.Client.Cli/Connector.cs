using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using OpcSuite.Cli;
using OpcSuite.Crypto;

namespace OpcSuite.Client.Cli;

internal static class Connector
{
    public static (OpcUaCryptoModule Crypto, ITelemetryContext Telemetry) CreateCrypto(ConnectionSettings settings)
    {
        var telemetry = CliDefaults.CreateTelemetry(settings.StackLevel);

        // Explicit pin > ask the user (interactive) > only already trusted servers (scripts, pipes)
        ITrustPolicy policy =
            settings.PinnedServers.Count > 0 ? TrustPolicies.Pinned(settings.PinnedServers)
            : Console.IsInputRedirected ? TrustPolicies.Strict
            : TrustPolicies.Ask(AskUser);

        return (new OpcUaCryptoModule(settings.PkiRoot, telemetry, settings.Profile, policy), telemetry);
    }

    public static async Task<OpcClient> ConnectAsync(ConnectionSettings settings, CancellationToken ct)
    {
        var (crypto, telemetry) = CreateCrypto(settings);
        return await ConnectAsync(settings, crypto, telemetry, ct);
    }

    public static async Task<OpcClient> ConnectAsync(
        ConnectionSettings settings, OpcUaCryptoModule crypto, ITelemetryContext telemetry, CancellationToken ct, bool printHint = true)
    {
        try
        {
            return await OpcClient.ConnectAsync(
                settings.Endpoint, crypto, telemetry, new ClientOptions { CheckServerHostName = settings.CheckServerHostName }, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (printHint)
            {
                await PrintHintAsync(crypto, ex);
            }
            throw;
        }
    }

    private static bool AskUser(X509Certificate2 certificate)
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine("The server presented a certificate that is not trusted yet:");
        Console.Error.WriteLine($"  subject  {certificate.Subject}");
        Console.Error.WriteLine($"  SHA-256  {Fingerprint.Format(Fingerprint.Sha256(certificate))}");
        Console.Error.WriteLine("Compare the SHA-256 with the one the server operator gave you (opcserver cert).");
        Console.Error.Write("Trust this server and remember it? [y/N] ");
        return Console.ReadLine()?.Trim().ToLowerInvariant() is "y" or "yes";
    }

    public static async Task PrintHintAsync(OpcUaCryptoModule crypto, Exception ex)
    {
        switch ((ex as ServiceResultException)?.StatusCode)
        {
            case StatusCodes.BadSecurityChecksFailed:
                // this is how a server says it does not trust our certificate
                if ((await crypto.Trust.ListOwnAsync()).FirstOrDefault() is { } own)
                {
                    Console.Error.WriteLine("The server may not trust this client yet. Ask its operator to run:");
                    Console.Error.WriteLine("  opcserver trust list");
                    Console.Error.WriteLine($"  opcserver trust accept {own.Sha256Fingerprint[..16]}");
                    Console.Error.WriteLine($"This client's SHA-256: {Fingerprint.Format(own.Sha256Fingerprint)}");
                }
                break;

            case StatusCodes.BadCertificateHostNameInvalid:
                Console.Error.WriteLine("The server's certificate does not list the host name used in --endpoint. Connect with a name it lists,");
                Console.Error.WriteLine("or add --skip-host-check if you identify the server by its pinned SHA-256 instead.");
                break;

            case StatusCodes.BadCertificateUntrusted:
                // the client refused the server's certificate
                Console.Error.WriteLine("This client does not trust the server's certificate. Get its SHA-256 from the server operator");
                Console.Error.WriteLine("(opcserver cert) and connect with --trust-server <SHA-256> - or answer 'y' when asked in a terminal.");
                break;
        }
    }
}
