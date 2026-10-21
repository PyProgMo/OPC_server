using System.CommandLine;
using OpcSuite.Client;

namespace OpcSuite.Client.Cli;

/// <summary>A connection handed to a command. Disposing it closes the connection only if the command owns it.</summary>
internal sealed class ClientLease(OpcClient client, bool ownsConnection) : IAsyncDisposable
{
    public OpcClient Client => client;

    public ValueTask DisposeAsync() => ownsConnection ? client.DisposeAsync() : ValueTask.CompletedTask;
}

/// <summary>Where the commands get their connection from: a new one per invocation, or the shell's shared one.</summary>
internal interface IClientSource
{
    Task<ClientLease> AcquireAsync(ParseResult parseResult, CancellationToken ct);
}

internal sealed class ConnectEachTime(GlobalOptions options) : IClientSource
{
    public async Task<ClientLease> AcquireAsync(ParseResult parseResult, CancellationToken ct) =>
        new(await Connector.ConnectAsync(options.Read(parseResult), ct), ownsConnection: true);
}

internal sealed class SharedConnection(OpcClient client) : IClientSource
{
    public Task<ClientLease> AcquireAsync(ParseResult parseResult, CancellationToken ct) =>
        Task.FromResult(new ClientLease(client, ownsConnection: false));
}
