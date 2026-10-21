using Opc.Ua;

namespace OpcSuite.Crypto;

/// <summary>
/// The transport protection every connection must use. Only profiles that both sign and encrypt
/// and use SHA-256 are offered; there is deliberately no "None" profile.
/// </summary>
/// <remarks>
/// Basic256Sha256 = RSA key exchange (certificates with SHA-256 signatures), AES-256-CBC encryption
/// and HMAC-SHA-256 message signatures, applied to every message of the secure channel.
/// </remarks>
public sealed record SecurityProfile(string Name, string PolicyUri, MessageSecurityMode Mode)
{
    public static readonly SecurityProfile Basic256Sha256 =
        new("Basic256Sha256", SecurityPolicies.Basic256Sha256, MessageSecurityMode.SignAndEncrypt);

    public static readonly SecurityProfile Aes256Sha256RsaPss =
        new("Aes256_Sha256_RsaPss", SecurityPolicies.Aes256_Sha256_RsaPss, MessageSecurityMode.SignAndEncrypt);

    public static readonly SecurityProfile Aes128Sha256RsaOaep =
        new("Aes128_Sha256_RsaOaep", SecurityPolicies.Aes128_Sha256_RsaOaep, MessageSecurityMode.SignAndEncrypt);

    public static SecurityProfile Default => Basic256Sha256;

    public static IReadOnlyList<SecurityProfile> All { get; } = [Basic256Sha256, Aes256Sha256RsaPss, Aes128Sha256RsaOaep];

    public static bool TryParse(string? name, out SecurityProfile profile)
    {
        profile = All.FirstOrDefault(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase))!;
        return profile is not null;
    }

    public bool IsSatisfiedBy(EndpointDescription endpoint) =>
        endpoint.SecurityMode == Mode && endpoint.SecurityPolicyUri == PolicyUri;

    public override string ToString() => $"{Name}/{Mode}";
}
