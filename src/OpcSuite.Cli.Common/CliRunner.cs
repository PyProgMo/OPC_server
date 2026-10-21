using System.CommandLine;
using Opc.Ua;

namespace OpcSuite.Cli;

public static class CliRunner
{
    /// <summary>Runs the command line; failures become a one-line <c>error:</c> message and exit code 1.</summary>
    public static async Task<int> RunAsync(RootCommand root, string[] args)
    {
        try
        {
            return await root.Parse(args)
                .InvokeAsync(new InvocationConfiguration
                {
                    EnableDefaultExceptionHandler = false,
                    // Ctrl+C cancels the action's token; give it time to shut down cleanly
                    ProcessTerminationTimeout = TimeSpan.FromSeconds(15),
                })
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return 130;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {Describe(ex)}");
            return 1;
        }
    }

    public static string Describe(Exception ex)
    {
        var message = ex is ServiceResultException sre ? sre.Message : ex.Message;
        return message.ReplaceLineEndings(" ").Trim();
    }
}
