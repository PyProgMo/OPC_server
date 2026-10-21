using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpcSuite.Crypto;

public static class Fingerprint
{
    /// <summary>SHA-256 fingerprint of the DER encoded certificate, upper case hex without separators.</summary>
    public static string Sha256(X509Certificate2 certificate) =>
        Convert.ToHexString(certificate.GetCertHash(HashAlgorithmName.SHA256));

    /// <summary>Strips separators and normalises the case, so users can paste fingerprints as printed by other tools.</summary>
    public static string Normalize(string value) =>
        new string(value.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant();

    /// <summary>Groups a hex fingerprint in pairs separated by colons for display: AB:CD:...</summary>
    public static string Format(string hex) =>
        string.Join(':', Enumerable.Range(0, hex.Length / 2).Select(i => hex.Substring(i * 2, 2)));
}
