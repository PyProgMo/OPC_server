using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;
using Opc.Ua.Server;
using OpcSuite.Core.Modules;
using OpcSuite.Crypto;

namespace OpcSuite.Server;

/// <summary>
/// The OPC UA server: wires the crypto module, the hosted modules and the OPC UA stack together.
/// Only the endpoint required by <see cref="ICryptoModule.Profile"/> is offered - there is no unencrypted endpoint.
/// </summary>
public sealed class OpcServerApplication : IAsyncDisposable
{
    private readonly ServerOptions _options;
    private readonly ICryptoModule _crypto;
    private readonly ModuleCatalog _modules;
    private readonly ITelemetryContext _telemetry;
    private readonly ILogger _logger;

    private StandardServer? _server;
    private readonly List<IServerModule> _startedModules = [];

    public OpcServerApplication(ServerOptions options, ICryptoModule crypto, ModuleCatalog modules, ITelemetryContext telemetry)
    {
        _options = options;
        _crypto = crypto;
        _modules = modules;
        _telemetry = telemetry;
        _logger = telemetry.CreateLogger<OpcServerApplication>();
    }

    /// <summary>The endpoints clients can connect to; available after <see cref="StartAsync"/>.</summary>
    public IReadOnlyList<EndpointDescription> Endpoints { get; private set; } = [];

    public CertificateSummary? Certificate { get; private set; }

    public async Task StartAsync(CancellationToken ct = default)
    {
        var application = new ApplicationInstance(_telemetry)
        {
            ApplicationName = _options.ApplicationName,
            ApplicationType = ApplicationType.Server,
        };

        var applicationUri = _options.ApplicationUri ?? $"urn:{Utils.GetHostName()}:OpcSuite:Server";
        var profile = _crypto.Profile;

        await application
            .Build(applicationUri, "urn:opcsuite:server")
            .AsServer([_options.EndpointUrl])
            .AddPolicy(profile.Mode, profile.PolicyUri)
            .AddUserTokenPolicy(UserTokenType.Anonymous)
            .AddSecurityConfiguration(
                _crypto.CreateApplicationCertificates($"CN={_options.ApplicationName}, O=OpcSuite, DC=localhost"),
                _crypto.Pki.Root)
            .SetAutoAcceptUntrustedCertificates(false)
            .CreateAsync(ct)
            .ConfigureAwait(false);

        Certificate = await _crypto.ActivateAsync(application, ct).ConfigureAwait(false);

        var server = new HostedServer();
        server.AddNodeManager(new ModuleNodeManagerFactory(_modules.Modules));
        await application.StartAsync(server).ConfigureAwait(false);
        _server = server;

        Endpoints = server.GetEndpoints().ToList();
        foreach (var endpoint in Endpoints)
        {
            // defence in depth: refuse to run if anything but the required protection is offered
            _crypto.Require(endpoint);
        }

        foreach (var module in _modules.Modules)
        {
            await module.StartAsync(ct).ConfigureAwait(false);
            _startedModules.Add(module);
            _logger.LogInformation("Module '{Module}' started", module.Name);
        }
    }

    public async Task StopAsync(CancellationToken ct = default)
    {
        foreach (var module in Enumerable.Reverse(_startedModules))
        {
            try
            {
                await module.StopAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Module '{Module}' failed to stop cleanly", module.Name);
            }
        }
        _startedModules.Clear();

        if (_server is { } server)
        {
            _server = null;
            await server.StopAsync().ConfigureAwait(false);
            server.Dispose();
        }
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    private sealed class HostedServer : StandardServer
    {
        protected override ServerProperties LoadServerProperties() => new()
        {
            ManufacturerName = "OpcSuite",
            ProductName = "OpcSuite Server",
            ProductUri = "urn:opcsuite:server",
            SoftwareVersion = Utils.GetAssemblySoftwareVersion(),
            BuildNumber = Utils.GetAssemblyBuildNumber(),
            BuildDate = Utils.GetAssemblyTimestamp(),
        };
    }
}
