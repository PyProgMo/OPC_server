using System.CommandLine;
using Microsoft.Extensions.Logging;
using OpcSuite.Cli;
using OpcSuite.Core.Modules;
using OpcSuite.Crypto;
using OpcSuite.Modules.Demo;

namespace OpcSuite.Server.Cli;

internal static class RunCommand
{
    public static Command Create(Option<string> pkiOption)
    {
        var url = new Option<string>("--url", "-u")
        {
            Description = "Endpoint to listen on. 'localhost' listens on all interfaces; use your public DNS name for internet use.",
            DefaultValueFactory = _ => new ServerOptions().EndpointUrl,
        };
        var name = new Option<string>("--name")
        {
            Description = "Application name (becomes part of the server certificate)",
            DefaultValueFactory = _ => new ServerOptions().ApplicationName,
        };
        var security = new Option<string>("--security")
        {
            Description = $"Required protection, one of: {string.Join(", ", SecurityProfile.All.Select(p => p.Name))}",
            DefaultValueFactory = _ => SecurityProfile.Default.Name,
        };
        var plugins = new Option<DirectoryInfo?>("--plugins")
        {
            Description = "Folder with additional module assemblies (*.dll). Loading a module runs its code - use folders you control.",
        };
        var noDemo = new Option<bool>("--no-demo") { Description = "Do not host the built-in Demo module" };
        var acceptAll = new Option<bool>("--accept-all-clients")
        {
            Description = "INSECURE, testing only: accept every client certificate without trusting it first",
        };
        var logLevel = new Option<string>("--log-level")
        {
            Description = "Log level of the OPC UA stack (Trace, Debug, Information, Warning, Error)",
            DefaultValueFactory = _ => nameof(LogLevel.Warning),
        };

        var run = new Command("run", "Start the server");
        run.Options.Add(url);
        run.Options.Add(name);
        run.Options.Add(security);
        run.Options.Add(plugins);
        run.Options.Add(noDemo);
        run.Options.Add(acceptAll);
        run.Options.Add(logLevel);

        run.SetAction(async (parseResult, ct) =>
        {
            if (!SecurityProfile.TryParse(parseResult.GetValue(security), out var profile))
            {
                throw new ArgumentException($"Unknown security profile '{parseResult.GetValue(security)}'.");
            }
            if (!CliDefaults.TryParseLogLevel(parseResult.GetValue(logLevel), out var stackLevel))
            {
                throw new ArgumentException($"Unknown log level '{parseResult.GetValue(logLevel)}'.");
            }

            var telemetry = CliDefaults.CreateTelemetry(stackLevel);
            var logger = telemetry.LoggerFactory.CreateLogger("opcserver");

            var modules = new ModuleCatalog();
            if (!parseResult.GetValue(noDemo))
            {
                modules.Add<DemoModule>();
            }
            if (parseResult.GetValue(plugins) is { } pluginDirectory)
            {
                modules.AddFromDirectory(pluginDirectory.FullName, logger);
            }

            var insecure = parseResult.GetValue(acceptAll);
            if (insecure)
            {
                logger.LogWarning("--accept-all-clients is on: client certificates are NOT checked. Never use this on a reachable network.");
            }

            var pkiRoot = parseResult.GetValue(pkiOption)!;
            var crypto = new OpcUaCryptoModule(
                pkiRoot, telemetry, profile, insecure ? TrustPolicies.AcceptAllInsecure : TrustPolicies.Strict);

            await using var server = new OpcServerApplication(
                new ServerOptions
                {
                    ApplicationName = parseResult.GetValue(name)!,
                    EndpointUrl = parseResult.GetValue(url)!,
                },
                crypto, modules, telemetry);

            await server.StartAsync(ct);

            Console.WriteLine();
            foreach (var endpoint in server.Endpoints.Select(e => e.EndpointUrl).Distinct())
            {
                Console.WriteLine($"  endpoint     {endpoint}");
            }
            Console.WriteLine($"  protection   {profile} (no unencrypted endpoint is offered)");
            Console.WriteLine($"  certificate  {server.Certificate!.Subject}");
            Console.WriteLine($"  SHA-256      {Fingerprint.Format(server.Certificate.Sha256Fingerprint)}");
            Console.WriteLine($"  modules      {string.Join(", ", modules.Modules.Select(m => m.Name))}");
            Console.WriteLine($"  pki          {crypto.Pki.Root}");
            Console.WriteLine();
            Console.WriteLine("Give clients the SHA-256 above to verify this server. Unknown clients are turned away and listed by:");
            Console.WriteLine("  opcserver trust list      then      opcserver trust accept <fingerprint>");
            Console.WriteLine("Press Ctrl+C to stop.");

            try
            {
                await Task.Delay(Timeout.Infinite, ct);
            }
            catch (OperationCanceledException)
            {
                // Ctrl+C: leave the loop, the server is stopped by the 'await using'
            }
            Console.WriteLine("Stopping...");
            return 0;
        });

        return run;
    }
}
