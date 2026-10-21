using OpcSuite.Server.Security;

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

    /// <summary>
    /// The users who may log in with a user name and password or a user certificate. Without it, those logins are not
    /// offered and only anonymous sessions are possible (if <see cref="AllowAnonymous"/>).
    /// </summary>
    public UserStore? Users { get; init; }

    /// <summary>Also accept sessions without a user login. They get the role Anonymous, which <see cref="Access"/> decides about.</summary>
    public bool AllowAnonymous { get; init; }

    /// <summary>Who may browse, read and write which nodes.</summary>
    public AccessPolicy Access { get; init; } = AccessPolicy.Default;

    /// <summary>Failed password logins in a row after which a user name is locked for <see cref="LoginLockout"/>; 0 disables the lockout.</summary>
    public int MaxFailedLogins { get; init; } = 5;

    public TimeSpan LoginLockout { get; init; } = TimeSpan.FromMinutes(1);
}
