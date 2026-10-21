using Microsoft.Extensions.Logging;
using Opc.Ua;

namespace OpcSuite.Cli;

public static class CliDefaults
{
    /// <summary>Per-user certificate folder, e.g. <c>~/.local/share/OpcSuite/server/pki</c> on Linux.</summary>
    public static string DefaultPki(string role) => DefaultFile(role, "pki");

    /// <summary>A file next to the per-user certificate folder, e.g. <c>~/.local/share/OpcSuite/server/users.json</c>.</summary>
    public static string DefaultFile(string role, string name) =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpcSuite", role, name);

    /// <summary>
    /// Console telemetry for the OPC UA stack. The stack is very chatty at Information level, so it is held to
    /// <paramref name="stackLevel"/> while our own components log at Information.
    /// </summary>
    public static ITelemetryContext CreateTelemetry(LogLevel stackLevel = LogLevel.Warning) =>
        DefaultTelemetry.Create(builder => builder
            .SetMinimumLevel(LogLevel.Trace)
            .AddFilter((category, level) => level >= (IsStackCategory(category) ? stackLevel : LogLevel.Information))
            .AddSimpleConsole(o =>
            {
                o.SingleLine = true;
                o.TimestampFormat = "HH:mm:ss ";
            }));

    // Opc.Ua.* is the stack itself. The server class derived from the stack's StandardServer logs under its own
    // (nested) type name, but with the stack's start-up/session chatter.
    private static bool IsStackCategory(string? category) =>
        category is not null && (category.StartsWith("Opc.Ua", StringComparison.Ordinal) || category.EndsWith("+HostedServer", StringComparison.Ordinal));

    public static bool TryParseLogLevel(string? text, out LogLevel level) =>
        Enum.TryParse(text, ignoreCase: true, out level) && Enum.IsDefined(level);
}
