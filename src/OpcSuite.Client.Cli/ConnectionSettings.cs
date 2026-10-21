using System.CommandLine;
using Microsoft.Extensions.Logging;
using OpcSuite.Cli;
using OpcSuite.Crypto;

namespace OpcSuite.Client.Cli;

/// <summary>The options every command shares: where to connect, with which protection, whom to trust, who to log in as.</summary>
internal sealed class GlobalOptions
{
    public Option<string> Endpoint { get; } = new("--endpoint", "-e")
    {
        Description = "Server endpoint",
        DefaultValueFactory = _ => "opc.tcp://localhost:4840/OpcSuite",
        Recursive = true,
    };

    public Option<string> Pki { get; } = TrustCommands.CreatePkiOption("client");

    public Option<string> Security { get; } = new("--security")
    {
        Description = $"Required protection, one of: {string.Join(", ", SecurityProfile.All.Select(p => p.Name))}",
        DefaultValueFactory = _ => SecurityProfile.Default.Name,
        Recursive = true,
    };

    public Option<string[]> TrustServer { get; } = new("--trust-server")
    {
        Description = "SHA-256 fingerprint of the server certificate, obtained out-of-band. Trusted and remembered if it matches. Repeat for several servers.",
        Recursive = true,
    };

    public Option<bool> SkipHostCheck { get; } = new("--skip-host-check")
    {
        Description = "Do not require the server certificate to list the host name used in --endpoint (identity then rests on the trusted fingerprint alone)",
        Recursive = true,
    };

    public Option<string?> User { get; } = new("--user", "-u")
    {
        Description = $"Log in as this user. The password is asked for, or read from {Passwords.EnvironmentVariable}",
        Recursive = true,
    };

    public Option<string?> UserCertificate { get; } = new("--user-cert")
    {
        Description = "Log in with a user certificate: a name made with 'opcctl user-cert create', or a .pfx file",
        Recursive = true,
    };

    public Option<string> LogLevel { get; } = new("--log-level")
    {
        Description = "Log level of the OPC UA stack (Trace, Debug, Information, Warning, Error, Critical)",
        DefaultValueFactory = _ => nameof(Microsoft.Extensions.Logging.LogLevel.Critical),
        Recursive = true,
    };

    public void AddTo(Command command)
    {
        command.Options.Add(Endpoint);
        command.Options.Add(Pki);
        command.Options.Add(Security);
        command.Options.Add(TrustServer);
        command.Options.Add(SkipHostCheck);
        command.Options.Add(User);
        command.Options.Add(UserCertificate);
        command.Options.Add(LogLevel);
    }

    public ConnectionSettings Read(ParseResult parseResult)
    {
        if (!SecurityProfile.TryParse(parseResult.GetValue(Security), out var profile))
        {
            throw new ArgumentException($"Unknown security profile '{parseResult.GetValue(Security)}'.");
        }
        if (!CliDefaults.TryParseLogLevel(parseResult.GetValue(LogLevel), out var level))
        {
            throw new ArgumentException($"Unknown log level '{parseResult.GetValue(LogLevel)}'.");
        }
        var pins = parseResult.GetValue(TrustServer) ?? [];
        foreach (var pin in pins)
        {
            if (Fingerprint.Normalize(pin).Length != 64)
            {
                throw new ArgumentException($"--trust-server expects the full SHA-256 fingerprint (64 hex digits), got '{pin}'.");
            }
        }
        var user = parseResult.GetValue(User);
        var userCertificate = parseResult.GetValue(UserCertificate);
        if (user is not null && userCertificate is not null)
        {
            throw new ArgumentException("Log in either with --user (password) or with --user-cert, not both.");
        }
        return new ConnectionSettings(
            parseResult.GetValue(Endpoint)!,
            parseResult.GetValue(Pki)!,
            profile,
            pins,
            !parseResult.GetValue(SkipHostCheck),
            level,
            user,
            userCertificate);
    }
}

internal sealed record ConnectionSettings(
    string Endpoint,
    string PkiRoot,
    SecurityProfile Profile,
    IReadOnlyList<string> PinnedServers,
    bool CheckServerHostName,
    LogLevel StackLevel,
    string? User,
    string? UserCertificate);
