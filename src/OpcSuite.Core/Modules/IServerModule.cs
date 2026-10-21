namespace OpcSuite.Core.Modules;

/// <summary>
/// A self-contained unit of server functionality. Implement this interface in any assembly,
/// register it (see <see cref="ModuleCatalog"/>) and the server hosts it.
/// Implementations need a public parameterless constructor to be discoverable as plugins.
/// </summary>
public interface IServerModule
{
    /// <summary>Unique, human readable module name; also the name of the module's root folder.</summary>
    string Name { get; }

    /// <summary>Called once at server start-up. Create the module's nodes below <see cref="IModuleContext.Root"/>.</summary>
    void CreateNodes(IModuleContext context);

    /// <summary>Called after the server is up. Start background work here.</summary>
    Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    /// <summary>Called when the server shuts down.</summary>
    Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
