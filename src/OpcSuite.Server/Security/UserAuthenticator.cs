using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Server;
using OpcSuite.Crypto;

namespace OpcSuite.Server.Security;

/// <summary>
/// Decides who a session belongs to. When this runs, the stack has already decrypted the password (it travels encrypted
/// with the server's key inside the encrypted channel) and checked that the client holds the private key of a presented
/// user certificate. Here the credentials are checked against the <see cref="UserStore"/> and the user's roles are
/// attached to the session; the role permissions of every node are then checked against those roles.
/// </summary>
internal sealed class UserAuthenticator(UserStore? users, bool allowAnonymous, LoginThrottle throttle, TimeProvider time, ILogger logger)
{
    public void OnImpersonateUser(ISession session, ImpersonateEventArgs args)
    {
        var client = Describe(session.ClientCertificate);
        switch (args.NewIdentity)
        {
            case AnonymousIdentityToken token when allowAnonymous:
                args.Identity = new RoleBasedIdentity(new UserIdentity(token), [Role.Anonymous]);
                logger.LogInformation("Anonymous session for {Client}", client);
                break;
            case UserNameIdentityToken token when users is not null:
                LogInWithPassword(users, token, args, client);
                break;
            case X509IdentityToken token when users is not null:
                LogInWithCertificate(users, token, args, client);
                break;
            default:
                // the stack only lets through token types the endpoint offers; this is the second line of defence
                Refuse(args, StatusCodes.BadIdentityTokenRejected, "-", client, $"{args.NewIdentity?.GetType().Name ?? "no token"} logins are not enabled");
                break;
        }
    }

    private void LogInWithPassword(UserStore store, UserNameIdentityToken token, ImpersonateEventArgs args, string client)
    {
        var name = token.UserName ?? "";
        var password = token.DecryptedPassword ?? [];
        try
        {
            if (throttle.IsLockedOut(name, out var remaining))
            {
                Refuse(args, StatusCodes.BadUserAccessDenied, name, client,
                    $"locked for another {Math.Ceiling(remaining.TotalSeconds)} s after repeated failed logins");
                return;
            }

            UserAccount? account;
            try
            {
                account = store.CheckPassword(name, password);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                logger.LogError("Cannot read the users file, refusing logins: {Problem}", ex.Message);
                Refuse(args, StatusCodes.BadUserAccessDenied, name, client, "the users file cannot be read");
                return;
            }

            if (account is null)
            {
                throttle.RecordFailure(name);
                Refuse(args, StatusCodes.BadUserAccessDenied, name, client, "wrong user name or password");
                return;
            }
            throttle.RecordSuccess(name);
            Grant(args, new UserIdentity(token) { DisplayName = account.Name }, account, "password", client);
        }
        finally
        {
            // the plain text password is not needed any more
            CryptographicOperations.ZeroMemory(password);
        }
    }

    private void LogInWithCertificate(UserStore store, X509IdentityToken token, ImpersonateEventArgs args, string client)
    {
        var certificate = token.Certificate ??= X509CertificateLoader.LoadCertificate(token.CertificateData);
        var fingerprint = Fingerprint.Sha256(certificate);

        UserAccount? account;
        try
        {
            account = store.FindByCertificate(fingerprint);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            logger.LogError("Cannot read the users file, refusing logins: {Problem}", ex.Message);
            Refuse(args, StatusCodes.BadIdentityTokenRejected, certificate.Subject, client, "the users file cannot be read");
            return;
        }

        if (account is null)
        {
            Refuse(args, StatusCodes.BadIdentityTokenRejected, certificate.Subject, client,
                $"user certificate {Fingerprint.Format(fingerprint)} is not registered for any user");
            return;
        }
        if (Problem(certificate) is { } problem)
        {
            Refuse(args, StatusCodes.BadIdentityTokenRejected, account.Name, client, problem);
            return;
        }
        Grant(args, new UserIdentity(token) { DisplayName = account.Name }, account, $"certificate {fingerprint[..16]}", client);
    }

    /// <summary>Registering a fingerprint trusts the key, but not a certificate that is expired or weak.</summary>
    private string? Problem(X509Certificate2 certificate)
    {
        var now = time.GetUtcNow().UtcDateTime;
        if (now < certificate.NotBefore.ToUniversalTime() || now > certificate.NotAfter.ToUniversalTime())
        {
            return $"the user certificate is only valid {certificate.NotBefore.ToUniversalTime():yyyy-MM-dd} .. {certificate.NotAfter.ToUniversalTime():yyyy-MM-dd}";
        }
        // md5RSA, sha1RSA, sha1ECDSA
        if (certificate.SignatureAlgorithm.Value is "1.2.840.113549.1.1.4" or "1.2.840.113549.1.1.5" or "1.2.840.10045.4.1")
        {
            return $"the user certificate is signed with {certificate.SignatureAlgorithm.FriendlyName}";
        }
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is { KeySize: < 2048 })
        {
            return $"the user certificate has a {rsa.KeySize}-bit RSA key (at least 2048 needed)";
        }
        return null;
    }

    private void Grant(ImpersonateEventArgs args, UserIdentity identity, UserAccount account, string method, string client)
    {
        var roles = account.Roles.Prepend(UserRole.AuthenticatedUser).ToList();
        args.Identity = new RoleBasedIdentity(identity, roles.Select(r => r.ToStackRole()).ToList());
        logger.LogInformation("User {User} logged in ({Method}) from {Client}; roles {Roles}",
            account.Name, method, client, string.Join(", ", roles));
    }

    private void Refuse(ImpersonateEventArgs args, uint status, string user, string client, string reason)
    {
        args.IdentityValidationError = new ServiceResult(status);
        logger.LogWarning("Login refused for {User} from {Client}: {Reason}", Printable(user), client, reason);
    }

    private static string Describe(X509Certificate2? clientCertificate) =>
        clientCertificate is null ? "unknown client" : $"{Printable(clientCertificate.Subject)} ({Fingerprint.Sha256(clientCertificate)[..16]})";

    // user names come from the network: keep them from forging log lines
    private static string Printable(string text) =>
        new string(text.Take(64).Select(c => char.IsControl(c) ? '?' : c).ToArray()) + (text.Length > 64 ? "..." : "");
}
