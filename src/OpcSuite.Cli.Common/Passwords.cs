using System.Text;

namespace OpcSuite.Cli;

/// <summary>
/// Reads passwords without putting them on the command line, where they would end up in the shell history and the
/// process list: from <see cref="EnvironmentVariable"/> (for scripts) or typed in without echo.
/// </summary>
public static class Passwords
{
    public const string EnvironmentVariable = "OPCSUITE_PASSWORD";

    public static string Read(string prompt, bool confirm = false)
    {
        if (Environment.GetEnvironmentVariable(EnvironmentVariable) is { Length: > 0 } fromEnvironment)
        {
            return fromEnvironment;
        }
        if (Console.IsInputRedirected)
        {
            throw new InvalidOperationException($"A password is needed: set {EnvironmentVariable} or run this in a terminal.");
        }

        var password = ReadHidden(prompt);
        if (confirm && ReadHidden("Repeat it: ") != password)
        {
            throw new InvalidOperationException("The passwords do not match.");
        }
        return password;
    }

    private static string ReadHidden(string prompt)
    {
        Console.Error.Write(prompt);
        var text = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                break;
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (text.Length > 0)
                {
                    text.Length--;
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                text.Append(key.KeyChar);
            }
        }
        Console.Error.WriteLine();
        return text.ToString();
    }
}
