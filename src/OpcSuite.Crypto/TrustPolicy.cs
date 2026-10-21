using System.Security.Cryptography.X509Certificates;

namespace OpcSuite.Crypto;

public enum TrustDecision
{
    /// <summary>Refuse. The certificate is kept in the rejected store so an administrator can trust it later.</summary>
    Reject,

    /// <summary>Accept this connection only; nothing is persisted.</summary>
    AcceptOnce,

    /// <summary>Accept and add the certificate to the trusted store (trust on first use).</summary>
    AcceptAndRemember,
}

/// <summary>
/// Decides about peer certificates that are not in the trusted store yet. It is only consulted for
/// certificates that are otherwise valid (signature, validity period, key size, hash algorithm);
/// expired, malformed or revoked certificates are always refused.
/// </summary>
public interface ITrustPolicy
{
    TrustDecision Evaluate(X509Certificate2 certificate);
}

public static class TrustPolicies
{
    /// <summary>Only certificates in the trusted store are accepted. This is the default.</summary>
    public static ITrustPolicy Strict { get; } = new Fixed(TrustDecision.Reject);

    /// <summary>Accepts every valid certificate. For local testing only - this disables peer authentication.</summary>
    public static ITrustPolicy AcceptAllInsecure { get; } = new Fixed(TrustDecision.AcceptOnce);

    /// <summary>
    /// Accepts exactly the certificates whose SHA-256 fingerprint is listed (obtained out-of-band) and remembers them,
    /// so later connections need no pin any more.
    /// </summary>
    public static ITrustPolicy Pinned(IEnumerable<string> sha256Fingerprints) => new PinnedPolicy(sha256Fingerprints);

    /// <summary>Asks a callback (e.g. the user) and remembers positive answers.</summary>
    public static ITrustPolicy Ask(Func<X509Certificate2, bool> ask) => new AskPolicy(ask);

    private sealed class Fixed(TrustDecision decision) : ITrustPolicy
    {
        public TrustDecision Evaluate(X509Certificate2 certificate) => decision;
    }

    private sealed class PinnedPolicy(IEnumerable<string> fingerprints) : ITrustPolicy
    {
        private readonly HashSet<string> _pins = fingerprints.Select(Fingerprint.Normalize).ToHashSet();

        public TrustDecision Evaluate(X509Certificate2 certificate) =>
            _pins.Contains(Fingerprint.Sha256(certificate)) ? TrustDecision.AcceptAndRemember : TrustDecision.Reject;
    }

    private sealed class AskPolicy(Func<X509Certificate2, bool> ask) : ITrustPolicy
    {
        public TrustDecision Evaluate(X509Certificate2 certificate) =>
            ask(certificate) ? TrustDecision.AcceptAndRemember : TrustDecision.Reject;
    }
}
