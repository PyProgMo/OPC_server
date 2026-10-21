using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Server;
using OpcSuite.Core.AddressSpace;
using OpcSuite.Core.Modules;

namespace OpcSuite.Server;

/// <summary>
/// Hosts the nodes of all <see cref="IServerModule"/>s in one OPC UA namespace. Every module gets its own folder
/// below the standard <c>Objects</c> folder; the module only sees the protocol-neutral <see cref="INodeFolder"/> API.
/// </summary>
internal sealed class ModuleNodeManager : CustomNodeManager2
{
    private static readonly Dictionary<Type, NodeId> DataTypes = new()
    {
        [typeof(bool)] = DataTypeIds.Boolean,
        [typeof(sbyte)] = DataTypeIds.SByte,
        [typeof(byte)] = DataTypeIds.Byte,
        [typeof(short)] = DataTypeIds.Int16,
        [typeof(ushort)] = DataTypeIds.UInt16,
        [typeof(int)] = DataTypeIds.Int32,
        [typeof(uint)] = DataTypeIds.UInt32,
        [typeof(long)] = DataTypeIds.Int64,
        [typeof(ulong)] = DataTypeIds.UInt64,
        [typeof(float)] = DataTypeIds.Float,
        [typeof(double)] = DataTypeIds.Double,
        [typeof(string)] = DataTypeIds.String,
        [typeof(DateTime)] = DataTypeIds.DateTime,
    };

    private readonly IReadOnlyList<IServerModule> _modules;
    private readonly ILoggerFactory _loggerFactory;
    private bool _sealed;

    public ModuleNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration,
        IReadOnlyList<IServerModule> modules)
        : base(server, configuration, server.Telemetry.CreateLogger<ModuleNodeManager>(), Namespaces.Modules)
    {
        _modules = modules;
        _loggerFactory = server.Telemetry.LoggerFactory;
    }

    public override void CreateAddressSpace(IDictionary<NodeId, IList<IReference>> externalReferences)
    {
        lock (Lock)
        {
            if (!externalReferences.TryGetValue(ObjectIds.ObjectsFolder, out var objectsReferences))
            {
                externalReferences[ObjectIds.ObjectsFolder] = objectsReferences = [];
            }

            foreach (var module in _modules)
            {
                var root = CreateFolder(null, module.Name, module.Name, module.Name);
                root.AddReference(ReferenceTypes.Organizes, true, ObjectIds.ObjectsFolder);
                objectsReferences.Add(new NodeStateReference(ReferenceTypes.Organizes, false, root.NodeId));

                module.CreateNodes(new ModuleContext(
                    new FolderBuilder(this, root, module.Name),
                    _loggerFactory.CreateLogger($"Module.{module.Name}")));

                AddPredefinedNode(SystemContext, root);
            }

            _sealed = true;
        }
    }

    private FolderState CreateFolder(NodeState? parent, string path, string name, string? description)
    {
        var folder = new FolderState(parent)
        {
            SymbolicName = name,
            ReferenceTypeId = ReferenceTypes.Organizes,
            TypeDefinitionId = ObjectTypeIds.FolderType,
            NodeId = new NodeId(path, NamespaceIndex),
            BrowseName = new QualifiedName(name, NamespaceIndex),
            DisplayName = new LocalizedText("en", name),
            Description = description is null ? null : new LocalizedText("en", description),
            EventNotifier = EventNotifiers.None,
        };
        parent?.AddChild(folder);
        return folder;
    }

    private void EnsureBuilding()
    {
        if (_sealed)
        {
            throw new InvalidOperationException("Nodes can only be added while IServerModule.CreateNodes runs.");
        }
    }

    private sealed class FolderBuilder(ModuleNodeManager owner, FolderState state, string path) : INodeFolder
    {
        public INodeFolder AddFolder(string name, string? description = null)
        {
            owner.EnsureBuilding();
            var childPath = $"{path}/{name}";
            return new FolderBuilder(owner, owner.CreateFolder(state, childPath, name, description), childPath);
        }

        public IVariableNode<T> AddVariable<T>(string name, T initialValue, NodeAccess access = NodeAccess.ReadOnly, string? description = null)
        {
            owner.EnsureBuilding();
            if (!DataTypes.TryGetValue(typeof(T), out var dataType))
            {
                throw new NotSupportedException($"Variables of type {typeof(T).Name} are not supported.");
            }
            ArgumentNullException.ThrowIfNull(initialValue);

            var accessLevel = access == NodeAccess.ReadWrite ? AccessLevels.CurrentReadOrWrite : AccessLevels.CurrentRead;
            var variable = new BaseDataVariableState(state)
            {
                SymbolicName = name,
                ReferenceTypeId = ReferenceTypes.Organizes,
                TypeDefinitionId = VariableTypeIds.BaseDataVariableType,
                NodeId = new NodeId($"{path}/{name}", owner.NamespaceIndex),
                BrowseName = new QualifiedName(name, owner.NamespaceIndex),
                DisplayName = new LocalizedText("en", name),
                Description = description is null ? null : new LocalizedText("en", description),
                DataType = dataType,
                ValueRank = ValueRanks.Scalar,
                AccessLevel = accessLevel,
                UserAccessLevel = accessLevel,
                Historizing = false,
                Value = initialValue,
                StatusCode = StatusCodes.Good,
                Timestamp = DateTime.UtcNow,
            };
            state.AddChild(variable);

            var node = new VariableNode<T>(owner, variable);
            if (access == NodeAccess.ReadWrite)
            {
                variable.OnSimpleWriteValue = node.OnClientWrite;
            }
            return node;
        }
    }

    private sealed class VariableNode<T>(ModuleNodeManager owner, BaseDataVariableState state) : IVariableNode<T>
    {
        public string Name => state.SymbolicName;

        public event Action<T>? WrittenByClient;

        public T Value
        {
            get { lock (owner.Lock) { return (T)state.Value; } }
            set
            {
                lock (owner.Lock)
                {
                    state.Value = value;
                    state.Timestamp = DateTime.UtcNow;
                    state.StatusCode = StatusCodes.Good;
                    // wakes up the monitored items of subscribed clients
                    state.ClearChangeMasks(owner.SystemContext, false);
                }
            }
        }

        // Runs inside the node manager lock, before the stack stores the new value.
        public ServiceResult OnClientWrite(ISystemContext context, NodeState node, ref object value)
        {
            if (value is not T typed)
            {
                return StatusCodes.BadTypeMismatch;
            }
            WrittenByClient?.Invoke(typed);
            return ServiceResult.Good;
        }
    }

    private sealed class ModuleContext(INodeFolder root, ILogger logger) : IModuleContext
    {
        public INodeFolder Root => root;
        public ILogger Logger => logger;
    }
}
