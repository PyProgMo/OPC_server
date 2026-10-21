namespace OpcSuite.Client;

/// <summary>What the client negotiated with the server.</summary>
public sealed record ConnectionInfo(
    string EndpointUrl,
    string SecurityPolicy,
    string SecurityMode,
    string ServerCertificateSubject,
    string ServerCertificateSha256);

public sealed record BrowseEntry(string NodeId, string DisplayName, string NodeClass);

public sealed record NodeValue(
    string NodeId,
    object? Value,
    string DataType,
    string Status,
    DateTime? SourceTimestampUtc);
