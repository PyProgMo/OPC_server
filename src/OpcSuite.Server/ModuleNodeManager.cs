using Microsoft.Extensions.Logging;
using Opc.Ua;
using Opc.Ua.Server;
using OpcSuite.Core.AddressSpace;
using OpcSuite.Core.Modules;
using OpcSuite.Server.Security;

namespace OpcSuite.Server;

/// <summary>
/// Hosts the nodes of all <see cref="IServerModule"/>s in one OPC UA namespace. Every module gets its own folder
/// below the standard <c>Objects</c> folder; the module only sees the protocol-neutral <see cref="INodeFolder"/> API.
/// Every node carries the OPC UA role permissions its <see cref="AccessPolicy"/> rule grants; the stack checks them on
/// browse, read, write and subscription sampling, so a user never sees or touches more than its roles allow.
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

    // read = see the node, its value and who may access it; write adds changing the value
    private const PermissionType ReadPermissions = PermissionType.Browse | PermissionType.ReadRolePermissions | PermissionType.Read;
    private const PermissionType WritePermissions = ReadPermissions | PermissionType.Write;

    private readonly IReadOnlyList<IServerModule> _modules;
    private readonly AccessPolicy _access;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;
    private readonly HashSet<string> _paths = new(StringComparer.Ordinal);
    private bool _sealed;

    public ModuleNodeManager(
        IServerInternal server,
        ApplicationConfiguration configuration,
        IReadOnlyList<IServerModule> modules,
        AccessPolicy access)
        : base(server, configuration, server.Telemetry.CreateLogger<ModuleNodeManager>(), Namespaces.Modules)
    {
        _modules = modules;
        _access = access;
        _loggerFactory = server.Telemetry.LoggerFactory;
        _logger = _loggerFactory.CreateLogger<ModuleNodeManager>();
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

        // a rule that matches nothing is almost always a typo, and then it protects nothing
        foreach (var path in _access.Nodes.Keys.Where(p => !_paths.Contains(p)))
        {
            _logger.LogWarning("The access rule for '{Path}' matches no node", path);
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
            RolePermissions = RolePermissionsFor(path),
        };
        parent?.AddChild(folder);
        return folder;
    }

    /// <summary>
    /// The role permissions for the node at <paramref name="path"/>. Never empty: the stack treats a node without
    /// role permissions as open to everybody, so a rule that grants nothing becomes one role with no permission.
    /// </summary>
    private RolePermissionTypeCollection RolePermissionsFor(string path)
    {
        _paths.Add(path);
        var permissions = new RolePermissionTypeCollection();
        foreach (var (role, permission) in _access.RuleFor(path).Grants)
        {
            permissions.Add(new RolePermissionType
            {
                RoleId = role.ToStackRole().RoleId,
                Permissions = (uint)(permission == NodePermission.Write ? WritePermissions : ReadPermissions),
            });
        }
        if (permissions.Count == 0)
        {
            permissions.Add(new RolePermissionType { RoleId = Role.Anonymous.RoleId, Permissions = (uint)PermissionType.None });
        }
        return permissions;
    }

    /// <summary>What the user of the current request may do according to a node's role permissions.</summary>
    private static PermissionType Granted(ISystemContext context, RolePermissionTypeCollection permissions)
    {
        var roles = (context as ISessionSystemContext)?.UserIdentity?.GrantedRoleIds;
        var granted = PermissionType.None;
        if (roles is not null)
        {
            foreach (var permission in permissions.Where(p => roles.Contains(p.RoleId)))
            {
                granted |= (PermissionType)permission.Permissions;
            }
        }
        return granted;
    }

    private static string? UserOf(ISystemContext context) => (context as ISessionSystemContext)?.UserIdentity?.DisplayName;

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
            var variablePath = $"{path}/{name}";
            var permissions = owner.RolePermissionsFor(variablePath);
            var variable = new BaseDataVariableState(state)
            {
                SymbolicName = name,
                ReferenceTypeId = ReferenceTypes.Organizes,
                TypeDefinitionId = VariableTypeIds.BaseDataVariableType,
                NodeId = new NodeId(variablePath, owner.NamespaceIndex),
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
                RolePermissions = permissions,
            };
            // UserAccessLevel tells each client what it may do itself, so tools can show what the user cannot change
            variable.OnReadUserAccessLevel = (ISystemContext context, NodeState _, ref byte value) =>
            {
                var granted = Granted(context, permissions);
                if (!granted.HasFlag(PermissionType.Read))
                {
                    value &= unchecked((byte)~AccessLevels.CurrentRead);
                }
                if (!granted.HasFlag(PermissionType.Write))
                {
                    value &= unchecked((byte)~AccessLevels.CurrentWrite);
                }
                return ServiceResult.Good;
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

        // Runs inside the node manager lock, after the stack checked the role permissions and before it stores the value.
        public ServiceResult OnClientWrite(ISystemContext context, NodeState node, ref object value)
        {
            if (value is not T typed)
            {
                return StatusCodes.BadTypeMismatch;
            }
            owner._logger.LogInformation("{User} wrote {Node} = {Value}", UserOf(context) ?? "unknown user", state.NodeId.Identifier, typed);
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
