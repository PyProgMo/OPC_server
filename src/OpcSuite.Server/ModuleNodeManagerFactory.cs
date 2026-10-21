using Opc.Ua;
using Opc.Ua.Server;
using OpcSuite.Core.Modules;

namespace OpcSuite.Server;

internal sealed class ModuleNodeManagerFactory(IReadOnlyList<IServerModule> modules) : INodeManagerFactory
{
    public StringCollection NamespacesUris => [Namespaces.Modules];

    public INodeManager Create(IServerInternal server, ApplicationConfiguration configuration) =>
        new ModuleNodeManager(server, configuration, modules);
}
