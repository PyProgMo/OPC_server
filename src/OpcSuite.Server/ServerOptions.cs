namespace OpcSuite.Server;

public sealed record ServerOptions
{
    public string ApplicationName { get; init; } = "OpcSuite Server";

    /// <summary>
    /// Where the server listens. A host name of <c>localhost</c> listens on all network interfaces and
    /// advertises the machine's host name to clients; use the public DNS name here when serving over the internet.
    /// </summary>
    public string EndpointUrl { get; init; } = "opc.tcp://localhost:4840/OpcSuite";

    /// <summary>Globally unique application identity, embedded in the server certificate. Defaults to a name derived from the host.</summary>
    public string? ApplicationUri { get; init; }
}
