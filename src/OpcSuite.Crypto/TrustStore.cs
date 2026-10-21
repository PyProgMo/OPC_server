using System.Security.Cryptography.X509Certificates;
using Opc.Ua;

namespace OpcSuite.Crypto;

public enum TrustList
{
    Trusted,
    Rejected,
}

public sealed record CertificateSummary(
    string Thumbprint,
    string Sha256Fingerprint,
    string Subject,
    string? ApplicationUri,
    DateTime NotBeforeUtc,
    DateTime NotAfterUtc)
{
    public static CertificateSummary From(X509Certificate2 certificate) => new(
        certificate.Thumbprint,
        Fingerprint.Sha256(certificate),
        certificate.Subject,
        X509Utils.GetApplicationUrisFromCertificate(certificate).FirstOrDefault(),
        certificate.NotBefore.ToUniversalTime(),
        certificate.NotAfter.ToUniversalTime());
}

/// <summary>
/// Reads and edits the trusted / rejected certificate lists of a <see cref="PkiLayout"/>.
/// This is the operator workflow: a peer that connects for the first time ends up in the rejected list,
/// the operator compares its SHA-256 fingerprint out-of-band and then moves it to the trusted list.
/// </summary>
public sealed class TrustStore(PkiLayout pki, ITelemetryContext telemetry)
{
    public async Task<IReadOnlyList<CertificateSummary>> ListAsync(TrustList list, CancellationToken ct = default)
    {
        using var store = Open(list);
        var certificates = await store.EnumerateAsync(ct).ConfigureAwait(false);
        return certificates.Cast<X509Certificate2>().Select(CertificateSummary.From).ToList();
    }

    /// <summary>This application's own certificate(s), public part only - what a peer needs to be told to trust.</summary>
    public async Task<IReadOnlyList<CertificateSummary>> ListOwnAsync(CancellationToken ct = default)
    {
        using var own = new CertificateStoreIdentifier(pki.Own, noPrivateKeys: true).OpenStore(telemetry);
        var certificates = await own.EnumerateAsync(ct).ConfigureAwait(false);
        return certificates.Cast<X509Certificate2>().Select(CertificateSummary.From).ToList();
    }

    /// <summary>The DER files of this application's own certificate(s), ready to be copied to a peer and imported there.</summary>
    public IReadOnlyList<string> OwnCertificateFiles() =>
        Directory.Exists(Path.Combine(pki.Own, "certs"))
            ? Directory.EnumerateFiles(Path.Combine(pki.Own, "certs"), "*.der").Order(StringComparer.Ordinal).ToList()
            : [];

    /// <summary>Moves a rejected certificate to the trusted list. <paramref name="fingerprint"/> may be a unique prefix.</summary>
    public async Task<CertificateSummary> TrustRejectedAsync(string fingerprint, CancellationToken ct = default)
    {
        using var rejected = Open(TrustList.Rejected);
        var certificate = Resolve(await rejected.EnumerateAsync(ct).ConfigureAwait(false), fingerprint, "rejected");

        await AddTrustedAsync(certificate, ct).ConfigureAwait(false);
        await rejected.DeleteAsync(certificate.Thumbprint, ct).ConfigureAwait(false);
        return CertificateSummary.From(certificate);
    }

    /// <summary>Trusts a certificate file (DER or PEM) that was obtained out-of-band.</summary>
    public async Task<CertificateSummary> ImportTrustedAsync(string file, CancellationToken ct = default)
    {
        var certificate = X509CertificateLoader.LoadCertificateFromFile(file);
        await AddTrustedAsync(certificate, ct).ConfigureAwait(false);
        return CertificateSummary.From(certificate);
    }

    /// <summary>Adds a certificate to the trusted list; trusting an already trusted certificate is not an error.</summary>
    public async Task AddTrustedAsync(X509Certificate2 certificate, CancellationToken ct = default)
    {
        using var trusted = Open(TrustList.Trusted);
        if ((await trusted.FindByThumbprintAsync(certificate.Thumbprint, ct).ConfigureAwait(false)).Count == 0)
        {
            await trusted.AddAsync(certificate, ct: ct).ConfigureAwait(false);
        }
    }

    public async Task<CertificateSummary> RemoveTrustedAsync(string fingerprint, CancellationToken ct = default)
    {
        using var trusted = Open(TrustList.Trusted);
        var certificate = Resolve(await trusted.EnumerateAsync(ct).ConfigureAwait(false), fingerprint, "trusted");

        await trusted.DeleteAsync(certificate.Thumbprint, ct).ConfigureAwait(false);
        return CertificateSummary.From(certificate);
    }

    private ICertificateStore Open(TrustList list) =>
        new CertificateStoreIdentifier(list == TrustList.Trusted ? pki.Trusted : pki.Rejected, noPrivateKeys: true)
            .OpenStore(telemetry);

    private static X509Certificate2 Resolve(X509Certificate2Collection certificates, string query, string listName)
    {
        var wanted = Fingerprint.Normalize(query);
        if (wanted.Length < 8)
        {
            throw new ArgumentException("Give at least the first 8 hex digits of the SHA-256 fingerprint or SHA-1 thumbprint.");
        }

        var matches = certificates.Cast<X509Certificate2>()
            .Where(c => Fingerprint.Sha256(c).StartsWith(wanted, StringComparison.Ordinal)
                        || c.Thumbprint.StartsWith(wanted, StringComparison.OrdinalIgnoreCase))
            .ToList();

        return matches.Count switch
        {
            1 => matches[0],
            0 => throw new KeyNotFoundException($"No certificate matching '{query}' in the {listName} list."),
            _ => throw new ArgumentException($"'{query}' matches {matches.Count} certificates in the {listName} list; use a longer prefix."),
        };
    }
}
