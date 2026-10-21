using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using OpcSuite.Client;
using OpcSuite.Core.Modules;
using OpcSuite.Crypto;
using OpcSuite.Modules.Demo;
using OpcSuite.Server;
using Xunit;

namespace OpcSuite.Tests;

/// <summary>A real server on a free local port with a throw-away PKI, shared by the tests of one class.</summary>
public sealed class ServerFixture : IAsyncLifetime
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), "opcsuite-tests-" + Guid.NewGuid().ToString("N"));

    // set OPCSUITE_TEST_LOG=Information (or Debug, Trace) to see what the stack and the crypto module are doing
    public ITelemetryContext Telemetry { get; } = DefaultTelemetry.Create(b =>
    {
        var level = Enum.TryParse<LogLevel>(Environment.GetEnvironmentVariable("OPCSUITE_TEST_LOG"), out var l) ? l : LogLevel.Error;
        b.SetMinimumLevel(level).AddSimpleConsole(o => o.SingleLine = true);
    });
    public OpcUaCryptoModule ServerCrypto { get; private set; } = null!;
    public OpcServerApplication Server { get; private set; } = null!;
    public string EndpointUrl { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        EndpointUrl = $"opc.tcp://localhost:{FreePort()}/OpcSuite";
        ServerCrypto = new OpcUaCryptoModule(Path.Combine(_root, "server-pki"), Telemetry);
        Server = new OpcServerApplication(
            new ServerOptions { EndpointUrl = EndpointUrl },
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

    public Task<OpcClient> ConnectAsync(OpcUaCryptoModule clientCrypto, string? endpointUrl = null, ClientOptions? options = null) =>
        OpcClient.ConnectAsync(endpointUrl ?? EndpointUrl, clientCrypto, Telemetry, options);

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

    public async Task<OpcClient> ConnectTrustedClientAsync() => await ConnectAsync(await ProvisionTrustedClientAsync());

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
