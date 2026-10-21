using System.Security.Cryptography.X509Certificates;
using System.Text;
using Opc.Ua;
using OpcSuite.Crypto;

namespace OpcSuite.Client;

/// <summary>
/// Who the client logs in as once the encrypted channel is open. The channel authenticates the application by its
/// certificate; the login authenticates the person or service using it, and decides what it may browse, read and write.
/// </summary>
public sealed class UserLogin
{
    private readonly Func<IUserIdentity> _identity;

    private UserLogin(UserTokenType tokenType, string description, Func<IUserIdentity> identity)
    {
        TokenType = tokenType;
        Description = description;
        _identity = identity;
    }

    /// <summary>No login. Most servers refuse it; an OpcSuite server only accepts it when started with anonymous sessions allowed.</summary>
    public static UserLogin Anonymous { get; } = new(UserTokenType.Anonymous, "anonymous", () => new UserIdentity());

    /// <summary>A user name and password. The password is encrypted with the server's key, inside the encrypted channel.</summary>
    public static UserLogin Password(string userName, string password)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(userName);
        ArgumentNullException.ThrowIfNull(password);
        return new(UserTokenType.UserName, $"{userName} (password)", () => new UserIdentity(userName, Encoding.UTF8.GetBytes(password)));
    }

    /// <summary>A user certificate. The client proves it holds the private key by signing the server's nonce with it.</summary>
    public static UserLogin Certificate(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new ArgumentException("A user certificate needs its private key to log in.", nameof(certificate));
        }
        return new(UserTokenType.Certificate,
            $"user certificate {certificate.Subject} ({Fingerprint.Sha256(certificate)[..16]})",
            () => new UserIdentity(certificate));
    }

    public UserTokenType TokenType { get; }

    public string Description { get; }

    public override string ToString() => Description;

    internal IUserIdentity CreateIdentity() => _identity();

    /// <summary>The kinds of login an endpoint accepts, in words.</summary>
    public static IReadOnlyList<string> Accepted(EndpointDescription endpoint) =>
        endpoint.UserIdentityTokens.Select(t => Describe(t.TokenType)).Distinct().ToList();

    public static string Describe(UserTokenType type) => type switch
    {
        UserTokenType.Anonymous => "anonymous",
        UserTokenType.UserName => "user name and password",
        UserTokenType.Certificate => "user certificate",
        UserTokenType.IssuedToken => "issued token",
        _ => type.ToString(),
    };
}

/// <summary>The server does not offer the kind of login the client was told to use.</summary>
public sealed class LoginNotAcceptedException(UserTokenType requested, IReadOnlyList<string> accepted)
    : InvalidOperationException(
        $"The server does not accept {UserLogin.Describe(requested)} logins (it accepts: {(accepted.Count == 0 ? "none" : string.Join(", ", accepted))}).")
{
    public UserTokenType Requested { get; } = requested;

    public IReadOnlyList<string> Accepted { get; } = accepted;
}
