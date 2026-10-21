using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Configuration;

namespace OpcSuite.Crypto;

/// <summary>
/// <see cref="ICryptoModule"/> built on the OPC Foundation UA .NET Standard stack
/// (https://github.com/OPCFoundation/UA-.NETStandard): certificate creation, validation and the
/// secure channel (RSA key exchange, AES-256 encryption, HMAC-SHA-256) all come from that library.
/// </summary>
public sealed class OpcUaCryptoModule : ICryptoModule
{
    private readonly ILogger _logger;

    public OpcUaCryptoModule(
        string pkiRoot,
        ITelemetryContext telemetry,
        SecurityProfile? profile = null,
        ITrustPolicy? trustPolicy = null)
    {
        Pki = PkiLayout.In(pkiRoot);
        Profile = profile ?? SecurityProfile.Default;
        TrustPolicy = trustPolicy ?? TrustPolicies.Strict;
        Trust = new TrustStore(Pki, telemetry);
        _logger = telemetry.CreateLogger<OpcUaCryptoModule>();
    }

    public SecurityProfile Profile { get; }
    public PkiLayout Pki { get; }
    public TrustStore Trust { get; }
    public ITrustPolicy TrustPolicy { get; }

    public CertificateIdentifierCollection CreateApplicationCertificates(string subjectName) =>
    [
        new CertificateIdentifier
        {
            StoreType = CertificateStoreType.Directory,
            StorePath = Pki.Own,
            SubjectName = subjectName,
            CertificateType = ObjectTypeIds.RsaSha256ApplicationCertificateType,
        },
    ];

    public async Task<CertificateSummary> ActivateAsync(ApplicationInstance application, CancellationToken ct = default)
    {
        var configuration = application.ApplicationConfiguration;

        // The stack's own "accept everything" switch would bypass the trust policy.
        configuration.SecurityConfiguration.AutoAcceptUntrustedCertificates = false;

        if (!await application.CheckApplicationInstanceCertificatesAsync(silent: true, ct: ct).ConfigureAwait(false))
        {
            throw new InvalidOperationException("The application certificate could not be created or is invalid.");
        }

        configuration.CertificateValidator.CertificateValidation += OnCertificateValidation;

        var own = CertificateSummary.From(configuration.SecurityConfiguration.ApplicationCertificate.Certificate);
        _logger.LogDebug("Application certificate {Subject}, SHA-256 {Fingerprint}", own.Subject, own.Sha256Fingerprint);
        return own;
    }

    public void Require(EndpointDescription endpoint)
    {
        if (!Profile.IsSatisfiedBy(endpoint))
        {
            throw new InvalidOperationException(
                $"Endpoint {endpoint.EndpointUrl} offers {endpoint.SecurityPolicyUri.Split('#').Last()}/{endpoint.SecurityMode}, " +
                $"but only {Profile} is allowed.");
        }
    }

    private void OnCertificateValidation(CertificateValidator sender, CertificateValidationEventArgs e)
    {
        var fingerprint = Fingerprint.Sha256(e.Certificate);

        // Only "valid, but not in the trusted list" can be overruled. Expired, revoked, too weak
        // or otherwise invalid certificates are never accepted, whatever the policy says.
        if (e.Error.StatusCode != StatusCodes.BadCertificateUntrusted)
        {
            _logger.LogWarning("Certificate {Subject} ({Fingerprint}) refused: {Error}", e.Certificate.Subject, fingerprint, e.Error.StatusCode);
            return;
        }

        switch (TrustPolicy.Evaluate(e.Certificate))
        {
            case TrustDecision.AcceptAndRemember:
                Trust.AddTrustedAsync(e.Certificate).GetAwaiter().GetResult();
                e.Accept = true;
                _logger.LogInformation("Trusted new certificate {Subject} ({Fingerprint})", e.Certificate.Subject, fingerprint);
                break;
            case TrustDecision.AcceptOnce:
                e.Accept = true;
                _logger.LogWarning("Accepted certificate {Subject} ({Fingerprint}) without it being in the trusted list", e.Certificate.Subject, fingerprint);
                break;
            default:
                _logger.LogWarning(
                    "Refused untrusted certificate {Subject} ({Fingerprint}). Trust it explicitly if it is the expected peer.",
                    e.Certificate.Subject, fingerprint);
                break;
        }
    }
}
