namespace OpcSuite.Core.AddressSpace;

public enum NodeAccess
{
    /// <summary>Clients can read and subscribe, only the module can change the value.</summary>
    ReadOnly,

    /// <summary>Clients can also write the value.</summary>
    ReadWrite,
}

/// <summary>A scalar variable node owned by a module.</summary>
public interface IVariableNode<T>
{
    string Name { get; }

    /// <summary>
    /// Current value. Setting it from the module publishes the change to subscribed clients.
    /// </summary>
    T Value { get; set; }

    /// <summary>Raised after a client successfully wrote a new value (<see cref="NodeAccess.ReadWrite"/> only).</summary>
    event Action<T>? WrittenByClient;
}
