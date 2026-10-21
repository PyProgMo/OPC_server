using System.Text.Json;

namespace OpcSuite.Server.Security;

/// <summary>What a role may do with a node.</summary>
public enum NodePermission
{
    /// <summary>Nothing; the node does not even show up when browsing.</summary>
    None,

    /// <summary>Browse, read and subscribe.</summary>
    Read,

    /// <summary>Everything <see cref="Read"/> allows, plus writing the value of writable variables.</summary>
    Write,
}

/// <summary>The permissions one rule grants. Roles it does not list get <see cref="NodePermission.None"/>.</summary>
public sealed class AccessRule
{
    public AccessRule(IReadOnlyDictionary<UserRole, NodePermission> grants) =>
        Grants = grants.Where(g => g.Value != NodePermission.None).ToDictionary();

    public IReadOnlyDictionary<UserRole, NodePermission> Grants { get; }

    public NodePermission For(UserRole role) => Grants.GetValueOrDefault(role);

    public override string ToString() =>
        Grants.Count == 0
            ? "nobody"
            : string.Join(", ", Grants.OrderBy(g => g.Key).Select(g => $"{g.Key} {g.Value.ToString().ToLowerInvariant()}"));
}

/// <summary>
/// Per-node authorisation. Rules are keyed by node path - the module name, then folders and variables, e.g.
/// <c>Demo/Sensors/Temperature</c> - and cover that node and everything below it. The rule with the longest
/// matching path decides alone, so every rule says completely who may do what; nodes no rule covers use
/// <see cref="DefaultRule"/>. A user may do what the best of its roles may do. Every logged-in user has the role
/// AuthenticatedUser, a session without a login has the role Anonymous.
/// </summary>
/// <remarks>The file format (comments allowed):
/// <code>
/// {
///   "default": { "AuthenticatedUser": "read", "Operator": "write" },
///   "nodes": {
///     "Demo/Setpoint": { "AuthenticatedUser": "read", "Engineer": "write" },
///     "Demo/Sensors":  { "Supervisor": "read" }
///   }
/// }
/// </code></remarks>
public sealed class AccessPolicy
{
    /// <summary>Everybody may read, operators, engineers and supervisors may also write.</summary>
    public static AccessRule BuiltInDefault { get; } = new(new Dictionary<UserRole, NodePermission>
    {
        [UserRole.Anonymous] = NodePermission.Read,
        [UserRole.AuthenticatedUser] = NodePermission.Read,
        [UserRole.Operator] = NodePermission.Write,
        [UserRole.Engineer] = NodePermission.Write,
        [UserRole.Supervisor] = NodePermission.Write,
    });

    public static AccessPolicy Default { get; } = new(BuiltInDefault, new Dictionary<string, AccessRule>());

    public AccessPolicy(AccessRule defaultRule, IReadOnlyDictionary<string, AccessRule> nodes, string? source = null)
    {
        DefaultRule = defaultRule;
        Nodes = nodes.ToDictionary(n => NormalizePath(n.Key), n => n.Value, StringComparer.Ordinal);
        Source = source;
    }

    public AccessRule DefaultRule { get; }

    /// <summary>The rules by node path.</summary>
    public IReadOnlyDictionary<string, AccessRule> Nodes { get; }

    /// <summary>The file the rules were read from; <c>null</c> for rules built in code.</summary>
    public string? Source { get; }

    /// <summary>The rule for the node at <paramref name="path"/>: the one with the longest matching path, or the default.</summary>
    public AccessRule RuleFor(string path)
    {
        for (var candidate = NormalizePath(path); candidate.Length > 0; candidate = Parent(candidate))
        {
            if (Nodes.TryGetValue(candidate, out var rule))
            {
                return rule;
            }
        }
        return DefaultRule;

        static string Parent(string p) => p.LastIndexOf('/') is var slash and >= 0 ? p[..slash] : "";
    }

    public static AccessPolicy Load(string file) => Parse(File.ReadAllText(file), Path.GetFullPath(file));

    public static AccessPolicy Parse(string json, string? source = null)
    {
        var where = source ?? "access rules";
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json, new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"{where}: not valid JSON: {ex.Message}");
        }

        using (document)
        {
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                throw new InvalidDataException($"{where}: expected an object with \"default\" and \"nodes\".");
            }

            var defaultRule = BuiltInDefault;
            var nodes = new Dictionary<string, AccessRule>(StringComparer.Ordinal);
            foreach (var setting in root.EnumerateObject())
            {
                switch (setting.Name)
                {
                    case "default":
                        defaultRule = ParseRule(setting.Value, where, "default");
                        break;
                    case "nodes":
                        if (setting.Value.ValueKind != JsonValueKind.Object)
                        {
                            throw new InvalidDataException($"{where}: \"nodes\" must map node paths to rules.");
                        }
                        foreach (var node in setting.Value.EnumerateObject())
                        {
                            var path = NormalizePath(node.Name);
                            if (path.Length == 0)
                            {
                                throw new InvalidDataException($"{where}: empty node path; use \"default\" for the rule of all nodes.");
                            }
                            if (!nodes.TryAdd(path, ParseRule(node.Value, where, path)))
                            {
                                throw new InvalidDataException($"{where}: node path '{path}' is listed twice.");
                            }
                        }
                        break;
                    default:
                        throw new InvalidDataException($"{where}: unknown setting \"{setting.Name}\" (expected \"default\" and \"nodes\").");
                }
            }
            return new AccessPolicy(defaultRule, nodes, source);
        }
    }

    private static AccessRule ParseRule(JsonElement element, string where, string rule)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidDataException($"{where}: rule '{rule}' must map roles to \"none\", \"read\" or \"write\".");
        }
        var grants = new Dictionary<UserRole, NodePermission>();
        foreach (var grant in element.EnumerateObject())
        {
            if (!UserRoles.TryParse(grant.Name, out var role))
            {
                throw new InvalidDataException(
                    $"{where}: rule '{rule}': unknown role '{grant.Name}'. Roles: {string.Join(", ", Enum.GetNames<UserRole>())}.");
            }
            NodePermission permission = default;
            if (grant.Value.ValueKind != JsonValueKind.String
                || Enum.GetNames<NodePermission>().FirstOrDefault(n => n.Equals(grant.Value.GetString(), StringComparison.OrdinalIgnoreCase)) is not { } name
                || !Enum.TryParse(name, out permission))
            {
                throw new InvalidDataException($"{where}: rule '{rule}': {role} must be \"none\", \"read\" or \"write\", not {grant.Value.GetRawText()}.");
            }
            if (!grants.TryAdd(role, permission))
            {
                throw new InvalidDataException($"{where}: rule '{rule}': {role} is listed twice.");
            }
        }
        return new AccessRule(grants);
    }

    private static string NormalizePath(string path) => path.Trim().Trim('/');
}
