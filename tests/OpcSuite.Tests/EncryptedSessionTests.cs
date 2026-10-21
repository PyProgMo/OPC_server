using Opc.Ua;
using Opc.Ua.Client;
using OpcSuite.Client;
using OpcSuite.Crypto;
using Xunit;

namespace OpcSuite.Tests;

public sealed class EncryptedSessionTests(ServerFixture fixture) : IClassFixture<ServerFixture>
{
    [Fact]
    public void Server_offers_only_the_encrypted_sha256_profile()
    {
        Assert.NotEmpty(fixture.Server.Endpoints);
        Assert.All(fixture.Server.Endpoints, e =>
        {
            Assert.Equal(SecurityPolicies.Basic256Sha256, e.SecurityPolicyUri);
            Assert.Equal(MessageSecurityMode.SignAndEncrypt, e.SecurityMode);
        });
    }

    [Fact]
    public async Task Unknown_client_is_rejected_until_the_operator_trusts_it()
    {
        var crypto = fixture.NewClientCrypto();
        var before = await fixture.ServerCrypto.Trust.ListAsync(TrustList.Rejected);

        await Assert.ThrowsAnyAsync<ServiceResultException>(() => fixture.ConnectAsync(crypto));

        await ServerFixture.LetServerRescanTrustListAsync();

        // the refused client certificate is parked in the rejected list for the operator to review
        var rejected = (await fixture.ServerCrypto.Trust.ListAsync(TrustList.Rejected))
            .Single(c => before.All(b => b.Sha256Fingerprint != c.Sha256Fingerprint));
        Assert.Equal(64, rejected.Sha256Fingerprint.Length);

        await fixture.ServerCrypto.Trust.TrustRejectedAsync(rejected.Sha256Fingerprint[..16]);

        await using var client = await fixture.ConnectAsync(crypto);
        Assert.Equal("SignAndEncrypt", client.Connection.SecurityMode);
        Assert.Equal("Basic256Sha256", client.Connection.SecurityPolicy);
        Assert.Equal(fixture.Server.Certificate!.Sha256Fingerprint, client.Connection.ServerCertificateSha256);
    }

    [Fact]
    public async Task Client_refuses_a_server_that_does_not_match_the_pinned_fingerprint()
    {
        var crypto = fixture.NewClientCrypto(pinnedServerSha256: new string('A', 64));

        await Assert.ThrowsAnyAsync<ServiceResultException>(() => fixture.ConnectAsync(crypto));
    }

    [Fact]
    public async Task A_pinned_server_is_remembered_for_later_connections()
    {
        var crypto = await fixture.ProvisionTrustedClientAsync();
        await using (await fixture.ConnectAsync(crypto))
        {
            // first contact: accepted because of the pin
        }

        // same key store, but no pin any more: the server must now be in the client's trusted list
        var later = new OpcUaCryptoModule(crypto.Pki.Root, fixture.Telemetry);
        Assert.Contains(await later.Trust.ListAsync(TrustList.Trusted), c => c.Sha256Fingerprint == fixture.Server.Certificate!.Sha256Fingerprint);
        await using var client = await fixture.ConnectAsync(later);
        Assert.Equal("SignAndEncrypt", client.Connection.SecurityMode);
    }

    [Fact]
    public async Task Client_demanding_a_different_protection_is_refused_before_connecting()
    {
        var crypto = fixture.NewClientCrypto(profile: SecurityProfile.Aes256Sha256RsaPss);

        var refused = await Assert.ThrowsAsync<InvalidOperationException>(() => fixture.ConnectAsync(crypto));

        Assert.Contains("does not offer the required protection", refused.Message);
    }

    [Fact]
    public async Task Server_certificate_must_list_the_host_name_unless_the_check_is_switched_off()
    {
        // 127.0.0.2 reaches the same server on Linux/Windows but is not in the server certificate;
        // other platforms do not route it, so there is nothing to test there.
        var other = fixture.EndpointUrl.Replace("localhost", "127.0.0.2");
        if (!await Reachable(other))
        {
            return;
        }

        var crypto = await fixture.ProvisionTrustedClientAsync();

        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => fixture.ConnectAsync(crypto, other));
        Assert.Equal(StatusCodes.BadCertificateHostNameInvalid, refused.StatusCode);

        await using var client = await fixture.ConnectAsync(crypto, other, new ClientOptions { CheckServerHostName = false, Login = ServerFixture.Login("operator") });
        Assert.Equal("SignAndEncrypt", client.Connection.SecurityMode);

        static async Task<bool> Reachable(string url)
        {
            var uri = new Uri(url);
            try
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                await tcp.ConnectAsync(uri.Host, uri.Port).WaitAsync(TimeSpan.FromSeconds(2));
                return true;
            }
            catch (Exception ex) when (ex is System.Net.Sockets.SocketException or TimeoutException)
            {
                return false;
            }
        }
    }

    [Fact]
    public async Task Unencrypted_session_is_refused()
    {
        var crypto = fixture.NewClientCrypto();
        var application = new Opc.Ua.Configuration.ApplicationInstance(fixture.Telemetry)
        {
            ApplicationName = "PlainClient",
            ApplicationType = ApplicationType.Client,
        };
        var configuration = await application
            .Build("urn:test:plain", "urn:test:plain")
            .AsClient()
            .AddSecurityConfiguration(crypto.CreateApplicationCertificates("CN=PlainClient, O=OpcSuite, DC=localhost"), crypto.Pki.Root)
            .CreateAsync();

        var plain = new EndpointDescription(fixture.EndpointUrl)
        {
            SecurityMode = MessageSecurityMode.None,
            SecurityPolicyUri = SecurityPolicies.None,
            TransportProfileUri = Profiles.UaTcpTransport,
        };
        plain.UserIdentityTokens.Add(new UserTokenPolicy(UserTokenType.Anonymous));

        await Assert.ThrowsAnyAsync<ServiceResultException>(async () =>
        {
            using var session = await new DefaultSessionFactory(fixture.Telemetry).CreateAsync(
                configuration,
                new ConfiguredEndpoint(null, plain, EndpointConfiguration.Create(configuration)),
                false, "plain", 10_000, new UserIdentity(), null);
        });
    }

    [Fact]
    public async Task Browse_lists_the_demo_module()
    {
        // the supervisor may see everything but the clock (see ServerFixture.AccessRules)
        await using var client = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("supervisor"));

        var objects = await client.BrowseAsync();
        var demo = Assert.Single(objects, e => e.DisplayName == "Demo");

        var children = (await client.BrowseAsync(demo.NodeId)).Select(e => e.DisplayName).ToList();
        Assert.Contains("Counter", children);
        Assert.Contains("Setpoint", children);
        Assert.Contains("Sensors", children);
    }

    [Fact]
    public async Task Write_changes_a_writable_node_and_is_refused_on_a_read_only_node()
    {
        await using var client = await fixture.ConnectTrustedClientAsync();
        const string setpoint = "nsu=urn:opcsuite:modules;s=Demo/Setpoint";
        const string counter = "nsu=urn:opcsuite:modules;s=Demo/Counter";

        await client.WriteAsync(setpoint, "42.5");
        Assert.Equal(42.5, (double)(await client.ReadAsync(setpoint)).Value!);

        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => client.WriteAsync(counter, "7"));
        Assert.Equal(StatusCodes.BadNotWritable, refused.StatusCode);
    }

    [Fact]
    public async Task Subscription_delivers_value_changes()
    {
        await using var client = await fixture.ConnectTrustedClientAsync();
        var values = new List<int>();
        var enough = new TaskCompletionSource();

        await using var subscription = await client.SubscribeAsync(
            ["nsu=urn:opcsuite:modules;s=Demo/Counter"],
            update =>
            {
                lock (values)
                {
                    values.Add((int)update.Value!);
                    if (values.Count >= 3)
                    {
                        enough.TrySetResult();
                    }
                }
            },
            TimeSpan.FromMilliseconds(250));

        await enough.Task.WaitAsync(TimeSpan.FromSeconds(15));
        lock (values)
        {
            Assert.True(values[^1] > values[0], $"counter should increase: {string.Join(',', values)}");
        }
    }
}
