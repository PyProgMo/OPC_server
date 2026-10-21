using System.CommandLine;
using System.Diagnostics;
using Opc.Ua;
using OpcSuite.Crypto;

namespace OpcSuite.Client.Cli;

/// <summary>
/// The first connection, narrated: what the server offers, who is trusted, what protection was negotiated.
/// Meant for setting up a new client/server pair and for finding out why a connection is refused.
/// </summary>
internal static class HandshakeCommand
{
    public static Command Create(GlobalOptions options)
    {
        var handshake = new Command("handshake", "Connect step by step and show what is offered, negotiated and trusted");
        handshake.SetAction(async (parseResult, ct) =>
        {
            var settings = options.Read(parseResult);
            var (crypto, telemetry) = Connector.CreateCrypto(settings);

            Console.WriteLine($"Handshake with {settings.Endpoint}");
            Console.WriteLine($"Required protection: {settings.Profile}");

            // 1. discovery - unauthenticated, only public information
            Console.WriteLine();
            Console.WriteLine("[1/3] Discovery (what the server advertises; not yet authenticated)");
            EndpointDescription? offer;
            try
            {
                var endpoints = await OpcClient.GetEndpointsAsync(settings.Endpoint, crypto, telemetry, ct: ct);
                offer = endpoints.FirstOrDefault(settings.Profile.IsSatisfiedBy);
                foreach (var endpoint in endpoints)
                {
                    var match = settings.Profile.IsSatisfiedBy(endpoint) ? "ok    " : "NOT OK";
                    Console.WriteLine($"      {match} offers {endpoint.SecurityPolicyUri.Split('#').Last()}/{endpoint.SecurityMode}");
                }
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                return Fail($"cannot reach the server: {CliRunnerMessage(ex)}",
                    "Is the server running? Start it with scripts/start-server.sh, and check --endpoint and the firewall.");
            }

            if (offer is null)
            {
                return Fail($"the server does not offer the required protection {settings.Profile}.",
                    "Start the server with the same --security, or pass --security to match the server.");
            }

            var serverCertificate = System.Security.Cryptography.X509Certificates.X509CertificateLoader.LoadCertificate(offer.ServerCertificate);
            var serverFingerprint = Fingerprint.Sha256(serverCertificate);
            var alreadyTrusted = (await crypto.Trust.ListAsync(TrustList.Trusted, ct))
                .Any(c => c.Sha256Fingerprint == serverFingerprint);
            Console.WriteLine($"      server certificate  {serverCertificate.Subject}");
            Console.WriteLine($"      SHA-256             {Fingerprint.Format(serverFingerprint)}");
            Console.WriteLine($"      {(alreadyTrusted ? "already trusted by this client" : "not trusted yet by this client - compare the SHA-256 with `opcserver cert` on the server")}");

            // 2. secure channel: both certificates are checked here
            Console.WriteLine();
            Console.WriteLine("[2/3] Encrypted channel and session (both sides check each other's certificate)");
            OpcClient client;
            try
            {
                client = await Connector.ConnectAsync(settings, crypto, telemetry, ct, printHint: false);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Console.Error.WriteLine($"      FAILED {CliRunnerMessage(ex)}");
                Console.Error.WriteLine();
                await Connector.PrintHintAsync(crypto, ex);
                return Summary();
            }

            await using (client)
            {
                var own = (await crypto.Trust.ListOwnAsync(ct)).FirstOrDefault();
                Console.WriteLine($"      ok     channel open, {client.Connection.SecurityPolicy}/{client.Connection.SecurityMode}");
                if (!alreadyTrusted)
                {
                    Console.WriteLine("      server certificate trusted just now and remembered for next time");
                }
                if (own is not null)
                {
                    Console.WriteLine($"      client certificate  {own.Subject}");
                    Console.WriteLine($"      SHA-256             {Fingerprint.Format(own.Sha256Fingerprint)}  (accepted by the server)");
                }

                // 3. proof that application data flows over the channel
                Console.WriteLine();
                Console.WriteLine("[3/3] Server status (first encrypted request)");
                var stopwatch = Stopwatch.StartNew();
                var state = await client.ReadAsync(VariableIds.Server_ServerStatus_State.ToString(), ct);
                var product = await client.ReadAsync(VariableIds.Server_ServerStatus_BuildInfo_ProductName.ToString(), ct);
                var time = await client.ReadAsync(VariableIds.Server_ServerStatus_CurrentTime.ToString(), ct);
                stopwatch.Stop();
                Console.WriteLine($"      server    {product.Value}");
                Console.WriteLine($"      state     {(ServerState)(int)state.Value!}");
                Console.WriteLine($"      time      {time.Value:O}");
                Console.WriteLine($"      3 reads in {stopwatch.ElapsedMilliseconds} ms");
            }

            Console.WriteLine();
            Console.WriteLine($"Handshake complete: both sides trust each other, all traffic is {settings.Profile}.");
            return 0;
        });
        return handshake;
    }

    private static int Fail(string problem, string? hint)
    {
        Console.Error.WriteLine($"      FAILED {problem}");
        if (hint is not null)
        {
            Console.Error.WriteLine($"      {hint}");
        }
        return Summary();
    }

    private static int Summary()
    {
        Console.Error.WriteLine();
        Console.Error.WriteLine("Handshake failed.");
        return 1;
    }

    private static string CliRunnerMessage(Exception ex) => OpcSuite.Cli.CliRunner.Describe(ex);
}
