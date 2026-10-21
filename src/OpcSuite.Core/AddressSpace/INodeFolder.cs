namespace OpcSuite.Core.AddressSpace;

/// <summary>
/// A folder in the server's address space. Modules build their part of the address space
/// through this protocol-neutral interface and never touch the OPC UA stack directly.
/// </summary>
public interface INodeFolder
{
    /// <summary>Creates a sub folder below this folder.</summary>
    INodeFolder AddFolder(string name, string? description = null);

    /// <summary>
    /// Creates a scalar variable below this folder.
    /// Supported types: bool, byte, sbyte, short, ushort, int, uint, long, ulong, float, double, string, DateTime.
    /// </summary>
    IVariableNode<T> AddVariable<T>(
        string name,
        T initialValue,
        NodeAccess access = NodeAccess.ReadOnly,
        string? description = null);
}
