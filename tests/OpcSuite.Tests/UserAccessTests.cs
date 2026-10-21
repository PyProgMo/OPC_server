using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcSuite.Client;
using OpcSuite.Crypto;
using OpcSuite.Server.Security;
using Xunit;

namespace OpcSuite.Tests;

/// <summary>Logins and per-node permissions, against a server with the users and rules of <see cref="ServerFixture"/>.</summary>
public sealed class UserAccessTests(ServerFixture fixture) : IClassFixture<ServerFixture>
{
    private const string Demo = "nsu=urn:opcsuite:modules;s=Demo";
    private const string Setpoint = "nsu=urn:opcsuite:modules;s=Demo/Setpoint";
    private const string Message = "nsu=urn:opcsuite:modules;s=Demo/Message";
    private const string Counter = "nsu=urn:opcsuite:modules;s=Demo/Counter";
    private const string Clock = "nsu=urn:opcsuite:modules;s=Demo/Clock";
    private const string Temperature = "nsu=urn:opcsuite:modules;s=Demo/Sensors/Temperature";

    private static ClientOptions As(UserLogin login) => new() { Login = login };

    [Fact]
    public void Server_offers_password_and_certificate_logins_but_no_anonymous_ones()
    {
        Assert.All(fixture.Server.Endpoints, e =>
        {
            var types = e.UserIdentityTokens.Select(t => t.TokenType).ToList();
            Assert.Contains(UserTokenType.UserName, types);
            Assert.Contains(UserTokenType.Certificate, types);
            Assert.DoesNotContain(UserTokenType.Anonymous, types);
        });
    }

    [Fact]
    public async Task Client_without_a_login_is_told_which_logins_the_server_accepts()
    {
        var crypto = await fixture.ProvisionTrustedClientAsync();

        var refused = await Assert.ThrowsAsync<LoginNotAcceptedException>(() => fixture.ConnectAsync(crypto, options: As(UserLogin.Anonymous)));

        Assert.Equal(new[] { "user name and password", "user certificate" }, refused.Accepted);
    }

    [Fact]
    public async Task Server_itself_refuses_an_anonymous_session()
    {
        // a client that skips its own check and pretends the endpoint offers anonymous logins
        var crypto = await fixture.ProvisionTrustedClientAsync();
        var application = new ApplicationInstance(fixture.Telemetry) { ApplicationName = "OpcSuite Client", ApplicationType = ApplicationType.Client };
        var configuration = await application
            .Build($"urn:{Utils.GetHostName()}:OpcSuite:Client", "urn:opcsuite:client")
            .AsClient()
            .AddSecurityConfiguration(crypto.CreateApplicationCertificates("CN=OpcSuite Client, O=OpcSuite, DC=localhost"), crypto.Pki.Root)
            .CreateAsync();
        await crypto.ActivateAsync(application);

        var endpoint = (await OpcClient.GetEndpointsAsync(fixture.EndpointUrl, crypto, fixture.Telemetry)).Single(crypto.Profile.IsSatisfiedBy);
        endpoint.UserIdentityTokens.Add(new UserTokenPolicy(UserTokenType.Anonymous) { PolicyId = "anonymous" });

        var refused = await Assert.ThrowsAsync<ServiceResultException>(async () =>
        {
            using var session = await new DefaultSessionFactory(fixture.Telemetry).CreateAsync(
                configuration,
                new ConfiguredEndpoint(null, endpoint, EndpointConfiguration.Create(configuration)),
                updateBeforeConnect: false, checkDomain: false, "anonymous", 10_000, new UserIdentity(), preferredLocales: null);
        });
        Assert.Equal(StatusCodes.BadIdentityTokenRejected, refused.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_and_unknown_user_are_refused_alike()
    {
        var crypto = await fixture.ProvisionTrustedClientAsync();

        var wrongPassword = await Assert.ThrowsAsync<ServiceResultException>(
            () => fixture.ConnectAsync(crypto, options: As(UserLogin.Password("observer", "not the password"))));
        var unknownUser = await Assert.ThrowsAsync<ServiceResultException>(
            () => fixture.ConnectAsync(crypto, options: As(UserLogin.Password("nobody", ServerFixture.Password))));

        // the same answer, so a client cannot find out which users exist
        Assert.Equal(StatusCodes.BadUserAccessDenied, wrongPassword.StatusCode);
        Assert.Equal(StatusCodes.BadUserAccessDenied, unknownUser.StatusCode);
    }

    [Fact]
    public async Task Observer_reads_but_cannot_write()
    {
        await using var client = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("observer"));
        Assert.Equal("observer (password)", client.Connection.User);

        await client.ReadAsync(Setpoint);
        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => client.WriteAsync(Setpoint, "21"));
        Assert.Equal(StatusCodes.BadUserAccessDenied, refused.StatusCode);

        var access = Assert.Single(await client.GetUserAccessAsync([Setpoint]));
        Assert.True(access.CanRead);
        Assert.False(access.CanWrite);
    }

    [Fact]
    public async Task Operator_writes_the_setpoint_but_only_engineers_change_the_message()
    {
        await using var op = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("operator"));
        await op.WriteAsync(Setpoint, "22.5");
        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => op.WriteAsync(Message, "from the operator"));
        Assert.Equal(StatusCodes.BadUserAccessDenied, refused.StatusCode);

        // what the operator sees about itself: the counter is read-only for everybody, the message just for it
        var access = (await op.GetUserAccessAsync([Setpoint, Message, Counter])).ToDictionary(a => a.NodeId);
        Assert.True(access[Setpoint].CanWrite);
        Assert.False(access[Message].CanWrite);
        Assert.False(access[Counter].CanWrite);
        Assert.True(access[Counter].CanRead);

        await using var engineer = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("engineer"));
        await engineer.WriteAsync(Message, "from the engineer");
        Assert.Equal("from the engineer", (await engineer.ReadAsync(Message)).Value);
    }

    [Fact]
    public async Task Nodes_a_user_may_not_read_are_hidden_and_refused()
    {
        await using var op = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("operator"));
        var visible = (await op.BrowseAsync(Demo)).Select(e => e.DisplayName).ToList();
        Assert.Contains("Counter", visible);
        Assert.DoesNotContain("Sensors", visible);
        Assert.DoesNotContain("Clock", visible);

        var read = await Assert.ThrowsAsync<ServiceResultException>(() => op.ReadAsync(Temperature));
        Assert.Equal(StatusCodes.BadUserAccessDenied, read.StatusCode);
        var subscribe = await Assert.ThrowsAsync<ServiceResultException>(() => op.SubscribeAsync([Temperature], _ => { }));
        Assert.Equal(StatusCodes.BadUserAccessDenied, subscribe.StatusCode);

        await using var supervisor = await fixture.ConnectTrustedClientAsync(ServerFixture.Login("supervisor"));
        Assert.Contains("Sensors", (await supervisor.BrowseAsync(Demo)).Select(e => e.DisplayName));
        Assert.IsType<double>((await supervisor.ReadAsync(Temperature)).Value);

        // a rule that grants nothing hides the node from everybody (and does not, as no rule would, open it to all)
        var clock = await Assert.ThrowsAsync<ServiceResultException>(() => supervisor.ReadAsync(Clock));
        Assert.Equal(StatusCodes.BadUserAccessDenied, clock.StatusCode);
    }

    [Fact]
    public async Task User_certificate_logs_in_once_it_is_registered_for_a_user()
    {
        var crypto = await fixture.ProvisionTrustedClientAsync();
        using var certificate = UserCertificates.Create(UserCertificates.DirectoryOf(crypto.Pki), "alice", TimeSpan.FromDays(1));
        var login = As(UserLogin.Certificate(certificate));

        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => fixture.ConnectAsync(crypto, options: login));
        Assert.Equal(StatusCodes.BadIdentityTokenRejected, refused.StatusCode);

        fixture.Users.Add("alice", password: null, [UserRole.Engineer]);
        fixture.Users.AddCertificate("alice", Fingerprint.Sha256(certificate));

        await using var client = await fixture.ConnectAsync(crypto, options: login);
        await client.WriteAsync(Message, "from alice");
        Assert.StartsWith("user certificate CN=alice", client.Connection.User);
    }

    [Fact]
    public async Task Users_added_by_another_process_can_log_in_without_a_restart()
    {
        var crypto = await fixture.ProvisionTrustedClientAsync();
        var login = As(UserLogin.Password("latecomer", ServerFixture.Password));
        await Assert.ThrowsAsync<ServiceResultException>(() => fixture.ConnectAsync(crypto, options: login));

        // what `opcserver user add` does: its own store on the same file
        new UserStore(fixture.Users.FilePath).Add("latecomer", ServerFixture.Password, [UserRole.Operator]);

        await using var client = await fixture.ConnectAsync(crypto, options: login);
        await client.WriteAsync(Setpoint, "23");
    }

    [Fact]
    public async Task Repeated_wrong_passwords_lock_the_user_out()
    {
        fixture.Users.Add("guessed", ServerFixture.Password, [UserRole.Operator]);
        var crypto = await fixture.ProvisionTrustedClientAsync();
        for (var attempt = 0; attempt < 5; attempt++)
        {
            await Assert.ThrowsAsync<ServiceResultException>(
                () => fixture.ConnectAsync(crypto, options: As(UserLogin.Password("guessed", $"guess {attempt}"))));
        }

        // now even the right password is refused for a while
        var locked = await Assert.ThrowsAsync<ServiceResultException>(
            () => fixture.ConnectAsync(crypto, options: As(ServerFixture.Login("guessed"))));
        Assert.Equal(StatusCodes.BadUserAccessDenied, locked.StatusCode);
    }
}

/// <summary>A server started with anonymous sessions allowed.</summary>
public sealed class AnonymousAccessTests(AnonymousServerFixture fixture) : IClassFixture<AnonymousServerFixture>
{
    [Fact]
    public async Task Anonymous_session_may_read_but_not_write()
    {
        await using var client = await fixture.ConnectTrustedClientAsync(UserLogin.Anonymous);
        Assert.Equal("anonymous", client.Connection.User);

        await client.ReadAsync("nsu=urn:opcsuite:modules;s=Demo/Setpoint");
        var refused = await Assert.ThrowsAsync<ServiceResultException>(() => client.WriteAsync("nsu=urn:opcsuite:modules;s=Demo/Setpoint", "30"));
        Assert.Equal(StatusCodes.BadUserAccessDenied, refused.StatusCode);
        await Assert.ThrowsAsync<ServiceResultException>(() => client.ReadAsync("nsu=urn:opcsuite:modules;s=Demo/Sensors/Temperature"));
    }
}
