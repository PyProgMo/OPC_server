using System.Globalization;
using System.Security.Cryptography.X509Certificates;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcSuite.Crypto;

namespace OpcSuite.Client;

/// <summary>
/// A connected, encrypted OPC UA session. The connection only succeeds if the server offers exactly the
/// <see cref="ICryptoModule.Profile"/> and its certificate is accepted by the crypto module's trust policy.
/// </summary>
public sealed class OpcClient : IAsyncDisposable
{
    private readonly ISession _session;

    private OpcClient(ISession session, ConnectionInfo connection)
    {
        _session = session;
        Connection = connection;
    }

    public ConnectionInfo Connection { get; }

    public static async Task<OpcClient> ConnectAsync(
        string endpointUrl,
        ICryptoModule crypto,
        ITelemetryContext telemetry,
        ClientOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ClientOptions();

        var application = new ApplicationInstance(telemetry)
        {
            ApplicationName = options.ApplicationName,
            ApplicationType = ApplicationType.Client,
        };

        var configuration = await application
            .Build(options.ApplicationUri ?? $"urn:{Utils.GetHostName()}:OpcSuite:Client", "urn:opcsuite:client")
            .AsClient()
            .AddSecurityConfiguration(
                crypto.CreateApplicationCertificates($"CN={options.ApplicationName}, O=OpcSuite, DC=localhost"),
                crypto.Pki.Root)
            .SetAutoAcceptUntrustedCertificates(false)
            .CreateAsync(ct)
            .ConfigureAwait(false);

        await crypto.ActivateAsync(application, ct).ConfigureAwait(false);

        var endpoint = await SelectEndpointAsync(configuration, endpointUrl, crypto, ct).ConfigureAwait(false);

        var configured = new ConfiguredEndpoint(null, endpoint, EndpointConfiguration.Create(configuration));
        var session = await new DefaultSessionFactory(telemetry)
            .CreateAsync(
                configuration,
                configured,
                updateBeforeConnect: false,
                checkDomain: options.CheckServerHostName,
                options.ApplicationName,
                (uint)options.SessionTimeout.TotalMilliseconds,
                new UserIdentity(),
                preferredLocales: null,
                ct)
            .ConfigureAwait(false);

        var serverCertificate = X509CertificateLoader.LoadCertificate(endpoint.ServerCertificate);
        return new OpcClient(session, new ConnectionInfo(
            endpoint.EndpointUrl,
            crypto.Profile.Name,
            endpoint.SecurityMode.ToString(),
            serverCertificate.Subject,
            Fingerprint.Sha256(serverCertificate)));
    }

    /// <summary>Lists the endpoints the server advertises, without connecting a session.</summary>
    public static async Task<IReadOnlyList<EndpointDescription>> GetEndpointsAsync(
        string endpointUrl,
        ICryptoModule crypto,
        ITelemetryContext telemetry,
        ClientOptions? options = null,
        CancellationToken ct = default)
    {
        options ??= new ClientOptions();
        var application = new ApplicationInstance(telemetry)
        {
            ApplicationName = options.ApplicationName,
            ApplicationType = ApplicationType.Client,
        };
        var configuration = await application
            .Build(options.ApplicationUri ?? $"urn:{Utils.GetHostName()}:OpcSuite:Client", "urn:opcsuite:client")
            .AsClient()
            .AddSecurityConfiguration(
                crypto.CreateApplicationCertificates($"CN={options.ApplicationName}, O=OpcSuite, DC=localhost"),
                crypto.Pki.Root)
            .CreateAsync(ct)
            .ConfigureAwait(false);
        return await DiscoverAsync(configuration, endpointUrl, ct).ConfigureAwait(false);
    }

    public async Task<IReadOnlyList<BrowseEntry>> BrowseAsync(string? nodeId = null, CancellationToken ct = default)
    {
        var start = nodeId is null ? ObjectIds.ObjectsFolder : ParseNodeId(nodeId);
        var description = new BrowseDescription
        {
            NodeId = start,
            BrowseDirection = BrowseDirection.Forward,
            ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences,
            IncludeSubtypes = true,
            NodeClassMask = 0,
            ResultMask = (uint)BrowseResultMask.All,
        };

        var response = await _session.BrowseAsync(null, null, 0, [description], ct).ConfigureAwait(false);
        var result = response.Results[0];
        ThrowIfBad(result.StatusCode, $"Browse of {start}");

        var references = new List<ReferenceDescription>(result.References);
        var continuation = result.ContinuationPoint;
        while (continuation is { Length: > 0 })
        {
            var next = await _session.BrowseNextAsync(null, false, [continuation], ct).ConfigureAwait(false);
            references.AddRange(next.Results[0].References);
            continuation = next.Results[0].ContinuationPoint;
        }

        return references
            .Select(r => new BrowseEntry(
                ExpandedNodeId.ToNodeId(r.NodeId, _session.NamespaceUris).ToString(),
                r.DisplayName.Text,
                r.NodeClass.ToString()))
            .ToList();
    }

    public async Task<NodeValue> ReadAsync(string nodeId, CancellationToken ct = default)
    {
        var id = ParseNodeId(nodeId);
        var value = await _session.ReadValueAsync(id, ct).ConfigureAwait(false);
        return ToNodeValue(id, value);
    }

    /// <summary>Writes <paramref name="text"/>, converted to the data type the node declares.</summary>
    public async Task WriteAsync(string nodeId, string text, CancellationToken ct = default)
    {
        var id = ParseNodeId(nodeId);
        var builtIn = await ReadBuiltInTypeAsync(id, ct).ConfigureAwait(false);

        object value;
        try
        {
            value = ParseValue(text, builtIn);
        }
        catch (Exception ex) when (ex is FormatException or OverflowException)
        {
            throw new ArgumentException($"'{text}' is not a valid {builtIn} value.", ex);
        }

        var request = new WriteValueCollection
        {
            new WriteValue
            {
                NodeId = id,
                AttributeId = Attributes.Value,
                Value = new DataValue(new Variant(value)),
            },
        };
        var response = await _session.WriteAsync(null, request, ct).ConfigureAwait(false);
        ThrowIfBad(response.Results[0], $"Write to {id}");
    }

    /// <summary>
    /// Subscribes to value changes. The callback runs on a stack thread and is also called once with the initial value.
    /// Dispose the returned handle to unsubscribe.
    /// </summary>
    public async Task<IAsyncDisposable> SubscribeAsync(
        IEnumerable<string> nodeIds,
        Action<NodeValue> onChange,
        TimeSpan? interval = null,
        CancellationToken ct = default)
    {
        var milliseconds = (int)(interval ?? TimeSpan.FromSeconds(1)).TotalMilliseconds;
        var subscription = new Subscription(_session.DefaultSubscription)
        {
            DisplayName = "OpcSuite subscription",
            PublishingEnabled = true,
            PublishingInterval = milliseconds,
        };
        _session.AddSubscription(subscription);
        await subscription.CreateAsync(ct).ConfigureAwait(false);

        foreach (var text in nodeIds)
        {
            var id = ParseNodeId(text);
            var item = new MonitoredItem(subscription.DefaultItem)
            {
                StartNodeId = id,
                AttributeId = Attributes.Value,
                SamplingInterval = milliseconds,
                QueueSize = 10,
                DiscardOldest = true,
            };
            item.Notification += (_, args) =>
            {
                if (args.NotificationValue is MonitoredItemNotification notification)
                {
                    onChange(ToNodeValue(id, notification.Value));
                }
            };
            subscription.AddItem(item);
        }
        await subscription.ApplyChangesAsync(ct).ConfigureAwait(false);

        return new SubscriptionHandle(_session, subscription);
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _session.CloseAsync(CancellationToken.None).ConfigureAwait(false);
        }
        finally
        {
            _session.Dispose();
        }
    }

    private static async Task<EndpointDescription> SelectEndpointAsync(
        ApplicationConfiguration configuration, string endpointUrl, ICryptoModule crypto, CancellationToken ct)
    {
        var endpoints = await DiscoverAsync(configuration, endpointUrl, ct).ConfigureAwait(false);
        var wanted = endpoints.FirstOrDefault(crypto.Profile.IsSatisfiedBy);
        if (wanted is null)
        {
            var offered = string.Join(", ", endpoints.Select(e => $"{e.SecurityPolicyUri.Split('#').Last()}/{e.SecurityMode}"));
            throw new InvalidOperationException(
                $"The server does not offer the required protection {crypto.Profile} (it offers: {(offered.Length == 0 ? "nothing" : offered)}).");
        }
        crypto.Require(wanted);
        return wanted;
    }

    private static async Task<IReadOnlyList<EndpointDescription>> DiscoverAsync(
        ApplicationConfiguration configuration, string endpointUrl, CancellationToken ct)
    {
        var uri = new Uri(endpointUrl);
        var endpointConfiguration = EndpointConfiguration.Create(configuration);
        endpointConfiguration.OperationTimeout = 15_000;

        using var discovery = await DiscoveryClient.CreateAsync(configuration, uri, endpointConfiguration, ct: ct).ConfigureAwait(false);
        var endpoints = await discovery.GetEndpointsAsync(null, ct).ConfigureAwait(false);

        // The server advertises its own host name, which may not be reachable the way the user connected
        // (NAT, DNS name, port forwarding). Keep the address the user asked for.
        foreach (var endpoint in endpoints)
        {
            if (Utils.ParseUri(endpoint.EndpointUrl) is { } advertised && advertised.Scheme == uri.Scheme)
            {
                endpoint.EndpointUrl = new UriBuilder(advertised) { Host = uri.IdnHost, Port = uri.Port }.ToString();
            }
        }
        return endpoints.ToList();
    }

    private NodeId ParseNodeId(string text) =>
        text.StartsWith("nsu=", StringComparison.OrdinalIgnoreCase)
            ? ExpandedNodeId.ToNodeId(ExpandedNodeId.Parse(text), _session.NamespaceUris)
            : NodeId.Parse(text);

    private async Task<BuiltInType> ReadBuiltInTypeAsync(NodeId id, CancellationToken ct)
    {
        var request = new ReadValueIdCollection { new ReadValueId { NodeId = id, AttributeId = Attributes.DataType } };
        var response = await _session.ReadAsync(null, 0, TimestampsToReturn.Neither, request, ct).ConfigureAwait(false);
        ThrowIfBad(response.Results[0].StatusCode, $"Reading the data type of {id}");

        var dataTypeId = (NodeId)response.Results[0].Value;
        return TypeInfo.GetBuiltInType(dataTypeId, _session.TypeTree);
    }

    private static object ParseValue(string text, BuiltInType type) => type switch
    {
        BuiltInType.Boolean => bool.Parse(text),
        BuiltInType.SByte => sbyte.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Byte => byte.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Int16 => short.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.UInt16 => ushort.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Int32 => int.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.UInt32 => uint.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Int64 => long.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.UInt64 => ulong.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Float => float.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.Double => double.Parse(text, CultureInfo.InvariantCulture),
        BuiltInType.String => text,
        BuiltInType.DateTime => DateTime.Parse(text, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal),
        _ => throw new NotSupportedException($"Writing values of type {type} is not supported."),
    };

    private NodeValue ToNodeValue(NodeId id, DataValue value) => new(
        id.ToString(),
        value.Value,
        value.WrappedValue.TypeInfo?.BuiltInType.ToString() ?? "Unknown",
        value.StatusCode.ToString(),
        value.SourceTimestamp == DateTime.MinValue ? null : value.SourceTimestamp);

    private static void ThrowIfBad(StatusCode status, string what)
    {
        if (StatusCode.IsBad(status))
        {
            throw new ServiceResultException(status, $"{what} failed: {StatusCodes.GetBrowseName(status.Code)}");
        }
    }

    private sealed class SubscriptionHandle(ISession session, Subscription subscription) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await session.RemoveSubscriptionAsync(subscription).ConfigureAwait(false);
            subscription.Dispose();
        }
    }
}
