using System.CommandLine;
using System.Globalization;
using OpcSuite.Client;

namespace OpcSuite.Client.Cli;

/// <summary>Commands that operate on an open session. Built per source so the shell can reuse them.</summary>
internal static class ClientCommands
{
    public static IReadOnlyList<Command> Create(IClientSource source) => [Info(source), Browse(source), Read(source), Write(source), Subscribe(source)];

    private static Command Info(IClientSource source)
    {
        var info = new Command("info", "Connect and show the negotiated protection and the server's certificate");
        info.SetAction(async (parseResult, ct) =>
        {
            await using var lease = await source.AcquireAsync(parseResult, ct);
            var c = lease.Client.Connection;
            Console.WriteLine($"connected    {c.EndpointUrl}");
            Console.WriteLine($"protection   {c.SecurityPolicy} / {c.SecurityMode}");
            Console.WriteLine($"server cert  {c.ServerCertificateSubject}");
            Console.WriteLine($"SHA-256      {OpcSuite.Crypto.Fingerprint.Format(c.ServerCertificateSha256)}");
            Console.WriteLine($"logged in    {c.User}");
            return 0;
        });
        return info;
    }

    private static Command Browse(IClientSource source)
    {
        var node = new Argument<string?>("node")
        {
            Description = "Node to start at, e.g. 'ns=2;s=Demo' (default: the Objects folder)",
            Arity = ArgumentArity.ZeroOrOne,
        };
        var depth = new Option<int>("--depth", "-d") { Description = "How many levels to descend", DefaultValueFactory = _ => 1 };
        var browse = new Command("browse", "List the nodes below a node, and what you may do with each variable");
        browse.Arguments.Add(node);
        browse.Options.Add(depth);
        browse.SetAction(async (parseResult, ct) =>
        {
            await using var lease = await source.AcquireAsync(parseResult, ct);
            await PrintTreeAsync(lease.Client, parseResult.GetValue(node), parseResult.GetValue(depth), indent: 0, ct);
            return 0;
        });
        return browse;
    }

    private static async Task PrintTreeAsync(OpcClient client, string? node, int depth, int indent, CancellationToken ct)
    {
        var entries = await client.BrowseAsync(node, ct);
        // one request for all variables of this level: what the logged-in user may do with them
        var variables = entries.Where(e => e.NodeClass is "Variable").Select(e => e.NodeId).Distinct().ToList();
        var access = (await client.GetUserAccessAsync(variables, ct)).ToDictionary(a => a.NodeId);
        foreach (var entry in entries)
        {
            var kind = access.TryGetValue(entry.NodeId, out var a)
                ? $"{entry.NodeClass}, {(a.CanWrite ? "read/write" : a.CanRead ? "read-only" : "no access")}"
                : entry.NodeClass;
            Console.WriteLine($"{new string(' ', indent * 2)}{entry.DisplayName}  [{kind}]  {entry.NodeId}");
            if (depth > 1 && entry.NodeClass is "Object")
            {
                await PrintTreeAsync(client, entry.NodeId, depth - 1, indent + 1, ct);
            }
        }
    }

    private static Command Read(IClientSource source)
    {
        var nodes = NodesArgument();
        var read = new Command("read", "Read the current value of one or more nodes");
        read.Arguments.Add(nodes);
        read.SetAction(async (parseResult, ct) =>
        {
            await using var lease = await source.AcquireAsync(parseResult, ct);
            foreach (var id in parseResult.GetValue(nodes)!)
            {
                Console.WriteLine(Format(await lease.Client.ReadAsync(id, ct)));
            }
            return 0;
        });
        return read;
    }

    private static Command Write(IClientSource source)
    {
        var node = new Argument<string>("node") { Description = "Node to write" };
        var value = new Argument<string>("value") { Description = "New value, converted to the node's data type" };
        var write = new Command("write", "Write a value to a node");
        write.Arguments.Add(node);
        write.Arguments.Add(value);
        write.SetAction(async (parseResult, ct) =>
        {
            await using var lease = await source.AcquireAsync(parseResult, ct);
            await lease.Client.WriteAsync(parseResult.GetValue(node)!, parseResult.GetValue(value)!, ct);
            Console.WriteLine("ok");
            return 0;
        });
        return write;
    }

    private static Command Subscribe(IClientSource source)
    {
        var nodes = NodesArgument();
        var interval = new Option<int>("--interval", "-i") { Description = "Sampling/publishing interval in ms", DefaultValueFactory = _ => 1000 };
        var count = new Option<int>("--count", "-n") { Description = "Stop after this many updates (0 = until Ctrl+C)", DefaultValueFactory = _ => 0 };
        var subscribe = new Command("subscribe", "Print value changes until Ctrl+C");
        subscribe.Arguments.Add(nodes);
        subscribe.Options.Add(interval);
        subscribe.Options.Add(count);
        subscribe.SetAction(async (parseResult, ct) =>
        {
            await using var lease = await source.AcquireAsync(parseResult, ct);
            var limit = parseResult.GetValue(count);
            var received = 0;
            using var done = CancellationTokenSource.CreateLinkedTokenSource(ct);

            await using var subscription = await lease.Client.SubscribeAsync(
                parseResult.GetValue(nodes)!,
                update =>
                {
                    Console.WriteLine(Format(update));
                    if (limit > 0 && Interlocked.Increment(ref received) >= limit)
                    {
                        done.Cancel();
                    }
                },
                TimeSpan.FromMilliseconds(parseResult.GetValue(interval)),
                ct);

            try
            {
                await Task.Delay(Timeout.Infinite, done.Token);
            }
            catch (OperationCanceledException)
            {
                // Ctrl+C or --count reached
            }
            return 0;
        });
        return subscribe;
    }

    private static Argument<string[]> NodesArgument() => new("nodes")
    {
        Description = "Node ids, 'ns=2;s=Demo/Counter' or namespace-independent 'nsu=urn:opcsuite:modules;s=Demo/Counter'",
        Arity = ArgumentArity.OneOrMore,
    };

    private static string Format(NodeValue v)
    {
        var timestamp = v.SourceTimestampUtc is { } t ? $"  @ {t:HH:mm:ss.fff}Z" : "";
        return $"{v.NodeId} = {FormatValue(v.Value)}  ({v.DataType}, {v.Status}){timestamp}";
    }

    private static string FormatValue(object? value) => value switch
    {
        null => "null",
        DateTime d => d.ToString("O", CultureInfo.InvariantCulture),
        string s => $"\"{s}\"",
        Array a => "[" + string.Join(", ", a.Cast<object?>().Select(FormatValue)) + "]",
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };
}
