namespace OpcSuite.Client;

public sealed record ClientOptions
{
    public string ApplicationName { get; init; } = "OpcSuite Client";

    /// <summary>Globally unique application identity, embedded in the client certificate. Defaults to a name derived from the host.</summary>
    public string? ApplicationUri { get; init; }

    /// <summary>
    /// Require the server certificate to list the host name the client connected to. Turn this off only when the
    /// server is identified by a pinned/trusted fingerprint and is reached by an address the certificate does not carry.
    /// </summary>
    public bool CheckServerHostName { get; init; } = true;

    public TimeSpan SessionTimeout { get; init; } = TimeSpan.FromMinutes(1);
}
