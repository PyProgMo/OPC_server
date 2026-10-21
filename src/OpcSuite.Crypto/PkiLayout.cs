namespace OpcSuite.Crypto;

/// <summary>
/// The on-disk certificate store layout (the standard OPC UA directory layout):
/// <c>own</c> holds this application's certificate and private key, <c>trusted</c> the certificates of peers
/// we accept, <c>issuer</c> trusted CAs and <c>rejected</c> the certificates of peers that were turned away.
/// </summary>
public sealed record PkiLayout(string Root)
{
    public string Own => Path.Combine(Root, "own");
    public string Trusted => Path.Combine(Root, "trusted");
    public string Issuer => Path.Combine(Root, "issuer");
    public string Rejected => Path.Combine(Root, "rejected");

    public static PkiLayout In(string root) => new(Path.GetFullPath(root));
}
