using Opc.Ua.Server;

namespace OpcSuite.Server.Security;

/// <summary>
/// The OPC UA well-known roles (OPC 10000-18). Users are given roles; access rules grant permissions to roles.
/// <see cref="Anonymous"/> and <see cref="AuthenticatedUser"/> are never given out: every session without a login
/// has the first, every logged-in user the second.
/// </summary>
public enum UserRole
{
    Anonymous,
    AuthenticatedUser,
    Observer,
    Operator,
    Engineer,
    Supervisor,
    ConfigureAdmin,
    SecurityAdmin,
}

public static class UserRoles
{
    /// <summary>The roles a user can be given.</summary>
    public static IReadOnlyList<UserRole> Assignable { get; } =
        [UserRole.Observer, UserRole.Operator, UserRole.Engineer, UserRole.Supervisor, UserRole.ConfigureAdmin, UserRole.SecurityAdmin];

    public static bool IsAssignable(this UserRole role) => role is not (UserRole.Anonymous or UserRole.AuthenticatedUser);

    /// <summary>Parses a role name, ignoring case. Unlike <see cref="Enum.TryParse{TEnum}(string, bool, out TEnum)"/> it accepts no numbers or lists.</summary>
    public static bool TryParse(string? text, out UserRole role)
    {
        var name = Enum.GetNames<UserRole>().FirstOrDefault(n => string.Equals(n, text?.Trim(), StringComparison.OrdinalIgnoreCase));
        role = name is null ? default : Enum.Parse<UserRole>(name);
        return name is not null;
    }

    public static UserRole Parse(string text) =>
        TryParse(text, out var role)
            ? role
            : throw new ArgumentException($"Unknown role '{text}'. Roles: {string.Join(", ", Enum.GetNames<UserRole>())}.");

    internal static Role ToStackRole(this UserRole role) => role switch
    {
        UserRole.Anonymous => Role.Anonymous,
        UserRole.AuthenticatedUser => Role.AuthenticatedUser,
        UserRole.Observer => Role.Observer,
        UserRole.Operator => Role.Operator,
        UserRole.Engineer => Role.Engineer,
        UserRole.Supervisor => Role.Supervisor,
        UserRole.ConfigureAdmin => Role.ConfigureAdmin,
        UserRole.SecurityAdmin => Role.SecurityAdmin,
        _ => throw new ArgumentOutOfRangeException(nameof(role), role, null),
    };
}
