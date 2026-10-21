using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using OpcSuite.Client;
using OpcSuite.Core.Modules;
using OpcSuite.Crypto;
using OpcSuite.Modules.Demo;
using OpcSuite.Server;
using OpcSuite.Server.Security;
using Xunit;

namespace OpcSuite.Tests;

/// <summary>A real server on a free local port with a throw-away PKI and users, shared by the tests of one class.</summary>
public class ServerFixture : IAsyncLifetime
{
    /// <summary>The password of every test user.</summary>
    public const string Password = "correct horse battery";

    /// <summary>
    /// On top of the built-in default (everybody reads; operators, engineers and supervisors write):
    /// only engineers may change the message, only supervisors see the sensors, nobody sees the clock.
    /// </summary>
    public const string AccessRules = """
        {
          // comments are allowed
          "nodes": {
            "Demo/Message": { "AuthenticatedUser": "read", "Anonymous": "read", "Engineer": "write" },
            "Demo/Sensors": { "Supervisor": "read" },
            "Demo/Clock": { }
          }
        }
        """;

    private readonly string _root = Path.Combine(Path.GetTempPath(), "opcsuite-tests-" + Guid.NewGuid().ToString("N"));

    // set OPCSUITE_TEST_LOG=Information (or Debug, Trace) to see what the stack and the crypto module are doing
    public ITelemetryContext Telemetry { get; } = DefaultTelemetry.Create(b =>
    {
        var level = Enum.TryParse<LogLevel>(Environment.GetEnvironmentVariable("OPCSUITE_TEST_LOG"), out var l) ? l : LogLevel.Error;
        b.SetMinimumLevel(level).AddSimpleConsole(o => o.SingleLine = true);
    });
    public OpcUaCryptoModule ServerCrypto { get; private set; } = null!;
    public OpcServerApplication Server { get; private set; } = null!;
    public UserStore Users { get; private set; } = null!;
    public string EndpointUrl { get; private set; } = null!;

    protected virtual bool AllowAnonymous => false;

    public static UserLogin Login(string user) => UserLogin.Password(user, Password);

    public async Task InitializeAsync()
    {
        Users = new UserStore(Path.Combine(_root, "users.json"));
        Users.Add("operator", Password, [UserRole.Operator]);
        Users.Add("engineer", Password, [UserRole.Engineer]);
        Users.Add("supervisor", Password, [UserRole.Supervisor]);
        Users.Add("observer", Password, [UserRole.Observer]);

        EndpointUrl = $"opc.tcp://localhost:{FreePort()}/OpcSuite";
        ServerCrypto = new OpcUaCryptoModule(Path.Combine(_root, "server-pki"), Telemetry);
        Server = new OpcServerApplication(
            new ServerOptions
            {
                EndpointUrl = EndpointUrl,
                Users = Users,
                AllowAnonymous = AllowAnonymous,
                Access = AccessPolicy.Parse(AccessRules),
            },
            ServerCrypto,
            new ModuleCatalog().Add<DemoModule>(),
            Telemetry);
        await Server.StartAsync();
    }

    public async Task DisposeAsync()
    {
        await Server.DisposeAsync();
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch (IOException)
        {
            // best effort clean-up of the temp folder
        }
    }

    /// <summary>A client crypto module with its own new key pair that trusts exactly the fixture's server certificate.</summary>
    public OpcUaCryptoModule NewClientCrypto(string? pinnedServerSha256 = null, SecurityProfile? profile = null) =>
        new(
            Path.Combine(_root, "client-pki-" + Guid.NewGuid().ToString("N")),
            Telemetry,
            profile,
            TrustPolicies.Pinned([pinnedServerSha256 ?? Server.Certificate!.Sha256Fingerprint]));

    /// <summary>Connects; without <paramref name="options"/> it logs in as the user 'operator'.</summary>
    public Task<OpcClient> ConnectAsync(OpcUaCryptoModule clientCrypto, string? endpointUrl = null, ClientOptions? options = null) =>
        OpcClient.ConnectAsync(endpointUrl ?? EndpointUrl, clientCrypto, Telemetry, options ?? new ClientOptions { Login = Login("operator") });

    /// <summary>A client the server has been told to trust (provisioned out-of-band by importing its certificate file).</summary>
    public async Task<OpcUaCryptoModule> ProvisionTrustedClientAsync()
    {
        var crypto = NewClientCrypto();
        await Assert.ThrowsAnyAsync<Exception>(() => ConnectAsync(crypto)); // creates the client key pair; server turns it away
        await LetServerRescanTrustListAsync();
        var certificateFile = Directory.EnumerateFiles(crypto.Pki.Own, "*.der", SearchOption.AllDirectories).Single();
        await ServerCrypto.Trust.ImportTrustedAsync(certificateFile);
        return crypto;
    }

    /// <summary>A trusted client, logged in as 'operator' unless another <paramref name="login"/> is given.</summary>
    public async Task<OpcClient> ConnectTrustedClientAsync(UserLogin? login = null) =>
        await ConnectAsync(await ProvisionTrustedClientAsync(), options: new ClientOptions { Login = login ?? Login("operator") });

    /// <summary>
    /// The stack caches the trusted directory and treats the cache as fresh unless the directory's modification time
    /// (coarse, a few ms) is newer than the last scan. The server scans while it turns a client away, so a trust
    /// change made within milliseconds of that is missed. A human running `trust accept` is never that fast.
    /// </summary>
    public static Task LetServerRescanTrustListAsync() => Task.Delay(100);

    private static int FreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }
}

/// <summary>The same server, but it also accepts sessions without a login.</summary>
public sealed class AnonymousServerFixture : ServerFixture
{
    protected override bool AllowAnonymous => true;
}
