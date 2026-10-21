using Opc.Ua;
using Opc.Ua.Configuration;

namespace OpcSuite.Crypto;

/// <summary>
/// The cryptography seam of the suite. Server and client ask this module which protection to use,
/// where the keys live and whom to trust; they never configure security themselves. A different
/// implementation (e.g. hardware-backed keys, a GDS-managed trust list) can be dropped in later.
/// </summary>
public interface ICryptoModule
{
    /// <summary>The only protection connections may use (sign + encrypt, SHA-256 based).</summary>
    SecurityProfile Profile { get; }

    PkiLayout Pki { get; }

    /// <summary>Operator access to the trusted / rejected certificate lists.</summary>
    TrustStore Trust { get; }

    ITrustPolicy TrustPolicy { get; }

    /// <summary>The application certificate slot(s) to hand to the OPC UA configuration builder (RSA, SHA-256 signed).</summary>
    CertificateIdentifierCollection CreateApplicationCertificates(string subjectName);

    /// <summary>
    /// Makes sure this application has a certificate (a new self-signed RSA/SHA-256 certificate is created on
    /// first start) and enforces <see cref="TrustPolicy"/> on every peer certificate.
    /// </summary>
    /// <returns>The application's own certificate.</returns>
    Task<CertificateSummary> ActivateAsync(ApplicationInstance application, CancellationToken ct = default);

    /// <summary>Throws if the endpoint does not offer exactly <see cref="Profile"/>.</summary>
    void Require(EndpointDescription endpoint);
}
