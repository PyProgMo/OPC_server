using System.CommandLine;
using System.CommandLine.Parsing;
using OpcSuite.Cli;

namespace OpcSuite.Client.Cli;

internal static class ShellCommand
{
    public static Command Create(GlobalOptions options)
    {
        var shell = new Command("shell", "Connect once and run several commands interactively");
        shell.SetAction(async (parseResult, ct) =>
        {
            await using var client = await Connector.ConnectAsync(options.Read(parseResult), ct);
            var c = client.Connection;
            Console.WriteLine($"Connected to {c.EndpointUrl} using {c.SecurityPolicy}/{c.SecurityMode}.");
            Console.WriteLine("Type 'help' for commands, 'exit' to leave.");

            // the same commands as on the command line, bound to the open connection
            var inner = new RootCommand("Commands");
            foreach (var command in ClientCommands.Create(new SharedConnection(client)))
            {
                inner.Subcommands.Add(command);
            }

            while (!ct.IsCancellationRequested)
            {
                Console.Write("opc> ");
                var line = Console.ReadLine()?.Trim();
                if (line is null or "exit" or "quit")
                {
                    break;
                }
                if (line.Length == 0)
                {
                    continue;
                }

                var tokens = line is "help" or "?" ? ["--help"] : CommandLineParser.SplitCommandLine(line).ToArray();
                await CliRunner.RunAsync(inner, tokens);
            }
            return 0;
        });
        return shell;
    }
}
