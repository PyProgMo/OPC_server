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

    /// <summary>The login the options ask for: a user certificate, a user name (password asked for now), or none.</summary>
    public static UserLogin CreateLogin(ConnectionSettings settings, ICryptoModule crypto)
    {
        if (settings.UserCertificate is { } certificate)
        {
            return UserLogin.Certificate(UserCertificates.Load(UserCertificates.DirectoryOf(crypto.Pki), certificate));
        }
        if (settings.User is { } user)
        {
            return UserLogin.Password(user, Passwords.Read($"Password for {user}: "));
        }
        return UserLogin.Anonymous;
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
            var options = new ClientOptions { CheckServerHostName = settings.CheckServerHostName, Login = CreateLogin(settings, crypto) };
            return await OpcClient.ConnectAsync(settings.Endpoint, crypto, telemetry, options, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            if (printHint)
            {
                await PrintHintAsync(settings, crypto, ex);
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

    public static async Task PrintHintAsync(ConnectionSettings settings, OpcUaCryptoModule crypto, Exception ex)
    {
        if (ex is LoginNotAcceptedException notAccepted)
        {
            Console.Error.WriteLine(notAccepted.Requested == UserTokenType.Anonymous
                ? "The server wants a login: add --user <name> (password) or --user-cert <name> (user certificate)."
                : "Log in another way, or ask the server operator to allow this kind of login.");
            return;
        }

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

            case StatusCodes.BadUserAccessDenied:
                // the channel is fine, the login is not; the server does not say why, on purpose
                Console.Error.WriteLine($"The server refused the login as '{settings.User}'. Check the user name and password.");
                Console.Error.WriteLine("After several wrong attempts in a row a user is locked for a while (by default 5 attempts, 1 minute).");
                Console.Error.WriteLine("The operator can check the user with: opcserver user list");
                break;

            case StatusCodes.BadIdentityTokenRejected or StatusCodes.BadIdentityTokenInvalid:
                if (settings.UserCertificate is { } name)
                {
                    using var certificate = UserCertificates.Load(UserCertificates.DirectoryOf(crypto.Pki), name);
                    var fingerprint = Fingerprint.Sha256(certificate);
                    Console.Error.WriteLine("The server refused the user certificate. It may not be registered yet; ask the operator to run:");
                    Console.Error.WriteLine($"  opcserver user cert add <user> {fingerprint}");
                    Console.Error.WriteLine("It is also refused when expired or weak.");
                }
                else
                {
                    Console.Error.WriteLine("The server refused this kind of login.");
                }
                break;
        }
    }
}
