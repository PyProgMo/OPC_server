using System.CommandLine;
using OpcSuite.Cli;
using OpcSuite.Server.Cli;

var pki = TrustCommands.CreatePkiOption("server");

var root = new RootCommand(
    "OpcSuite OPC UA server. Every connection is signed and encrypted (SHA-256 based); " +
    "clients must present a certificate you have trusted.");
root.Options.Add(pki);
root.Subcommands.Add(RunCommand.Create(pki));
root.Subcommands.Add(TrustCommands.CreateTrust(pki));
root.Subcommands.Add(TrustCommands.CreateCert(pki));

return await CliRunner.RunAsync(root, args);
