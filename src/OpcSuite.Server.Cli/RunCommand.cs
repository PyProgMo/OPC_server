using System.CommandLine;
using Microsoft.Extensions.Logging;
using OpcSuite.Cli;
using OpcSuite.Core.Modules;
using OpcSuite.Crypto;
using OpcSuite.Modules.Demo;
using OpcSuite.Server.Security;

namespace OpcSuite.Server.Cli;

internal static class RunCommand
{
    public static Command Create(Option<string> pkiOption, Option<string> usersOption)
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
        var defaultAccess = CliDefaults.DefaultFile("server", "access.json");
        var access = new Option<FileInfo?>("--access")
        {
            Description = $"Per-node access rules (JSON). Default: {defaultAccess} if it exists, otherwise everybody reads and Operator/Engineer/Supervisor write",
        };
        var allowAnonymous = new Option<bool>("--allow-anonymous")
        {
            Description = "Also accept sessions without a user login (role Anonymous; read-only unless the access rules say otherwise)",
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
        run.Options.Add(access);
        run.Options.Add(allowAnonymous);
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

            // an explicitly named rules file must exist; the default one is optional
            var accessFile = parseResult.GetValue(access)?.FullName ?? (File.Exists(defaultAccess) ? defaultAccess : null);
            var rules = accessFile is null ? AccessPolicy.Default : AccessPolicy.Load(accessFile);
            var users = new UserStore(parseResult.GetValue(usersOption)!);
            var anonymous = parseResult.GetValue(allowAnonymous);

            var pkiRoot = parseResult.GetValue(pkiOption)!;
            var crypto = new OpcUaCryptoModule(
                pkiRoot, telemetry, profile, insecure ? TrustPolicies.AcceptAllInsecure : TrustPolicies.Strict);

            await using var server = new OpcServerApplication(
                new ServerOptions
                {
                    ApplicationName = parseResult.GetValue(name)!,
                    EndpointUrl = parseResult.GetValue(url)!,
                    Users = users,
                    AllowAnonymous = anonymous,
                    Access = rules,
                },
                crypto, modules, telemetry);

            await server.StartAsync(ct);

            var userCount = users.List().Count;
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
            Console.WriteLine($"  logins       {string.Join(", ", server.LoginTypes.Select(DescribeLogin))}{(anonymous ? "" : " (no anonymous sessions)")}");
            Console.WriteLine($"  users        {userCount} in {users.FilePath}");
            Console.WriteLine($"  access       {rules.Source ?? "built-in rules"}");
            Console.WriteLine($"    {"(default)",-24} {rules.DefaultRule}");
            foreach (var (path, rule) in rules.Nodes.OrderBy(n => n.Key, StringComparer.Ordinal))
            {
                Console.WriteLine($"    {path,-24} {rule}");
            }
            Console.WriteLine();
            Console.WriteLine("Give clients the SHA-256 above to verify this server. Unknown clients are turned away and listed by:");
            Console.WriteLine("  opcserver trust list      then      opcserver trust accept <fingerprint>");
            if (userCount == 0 && !anonymous)
            {
                Console.WriteLine("No users yet, so nobody can log in. Add one (works while the server runs):");
                Console.WriteLine("  opcserver user add <name> --role Operator");
            }
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

    private static string DescribeLogin(Opc.Ua.UserTokenType type) => type switch
    {
        Opc.Ua.UserTokenType.UserName => "user name and password",
        Opc.Ua.UserTokenType.Certificate => "user certificate",
        Opc.Ua.UserTokenType.Anonymous => "anonymous",
        _ => type.ToString(),
    };
}
