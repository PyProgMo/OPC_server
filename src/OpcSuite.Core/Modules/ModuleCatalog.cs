using System.Reflection;
using Microsoft.Extensions.Logging;

namespace OpcSuite.Core.Modules;

/// <summary>The set of modules a server instance will host.</summary>
public sealed class ModuleCatalog
{
    private readonly List<IServerModule> _modules = [];

    public IReadOnlyList<IServerModule> Modules => _modules;

    public ModuleCatalog Add(IServerModule module)
    {
        ArgumentNullException.ThrowIfNull(module);
        if (_modules.Any(m => string.Equals(m.Name, module.Name, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException($"A module named '{module.Name}' is already registered.");
        }
        _modules.Add(module);
        return this;
    }

    public ModuleCatalog Add<T>() where T : IServerModule, new() => Add(new T());

    /// <summary>
    /// Loads every <see cref="IServerModule"/> implementation found in the assemblies (*.dll) of a directory.
    /// This executes code from that directory: only point it at folders you control.
    /// </summary>
    public ModuleCatalog AddFromDirectory(string directory, ILogger? logger = null)
    {
        if (!Directory.Exists(directory))
        {
            throw new DirectoryNotFoundException($"Plugin directory not found: {directory}");
        }

        foreach (var file in Directory.EnumerateFiles(directory, "*.dll").Order(StringComparer.Ordinal))
        {
            foreach (var type in FindModuleTypes(file, logger))
            {
                var module = (IServerModule)Activator.CreateInstance(type)!;
                Add(module);
                logger?.LogInformation("Loaded module '{Module}' from {File}", module.Name, Path.GetFileName(file));
            }
        }
        return this;
    }

    private static IEnumerable<Type> FindModuleTypes(string file, ILogger? logger)
    {
        Type[] types;
        try
        {
            types = Assembly.LoadFrom(file).GetTypes();
        }
        catch (Exception ex) when (ex is BadImageFormatException or FileLoadException or ReflectionTypeLoadException)
        {
            // native libraries and dependency assemblies that cannot be inspected are not plugins
            logger?.LogDebug("Skipping {File}: {Reason}", Path.GetFileName(file), ex.GetType().Name);
            yield break;
        }

        foreach (var type in types)
        {
            if (typeof(IServerModule).IsAssignableFrom(type)
                && type is { IsAbstract: false, IsInterface: false }
                && type.GetConstructor(Type.EmptyTypes) is not null)
            {
                yield return type;
            }
        }
    }
}
