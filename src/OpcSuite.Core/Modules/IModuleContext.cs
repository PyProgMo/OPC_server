using Microsoft.Extensions.Logging;
using OpcSuite.Core.AddressSpace;

namespace OpcSuite.Core.Modules;

/// <summary>What the host hands to a module while it is being set up.</summary>
public interface IModuleContext
{
    /// <summary>The module's own folder in the address space (named after <see cref="IServerModule.Name"/>).</summary>
    INodeFolder Root { get; }

    ILogger Logger { get; }
}
