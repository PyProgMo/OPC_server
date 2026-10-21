using Opc.Ua;
using Opc.Ua.Server;
using OpcSuite.Core.Modules;
using OpcSuite.Server.Security;

namespace OpcSuite.Server;

internal sealed class ModuleNodeManagerFactory(IReadOnlyList<IServerModule> modules, AccessPolicy access) : INodeManagerFactory
{
    public StringCollection NamespacesUris => [Namespaces.Modules];

    public INodeManager Create(IServerInternal server, ApplicationConfiguration configuration) =>
        new ModuleNodeManager(server, configuration, modules, access);
}
