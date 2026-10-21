using System.CommandLine;
using OpcSuite.Cli;
using OpcSuite.Server.Cli;

var pki = TrustCommands.CreatePkiOption("server");
var users = UserCommands.CreateUsersOption();

var root = new RootCommand(
    "OpcSuite OPC UA server. Every connection is signed and encrypted (SHA-256 based); " +
    "clients must present a certificate you have trusted and log in as a user you have added.");
root.Options.Add(pki);
root.Options.Add(users);
root.Subcommands.Add(RunCommand.Create(pki, users));
root.Subcommands.Add(TrustCommands.CreateTrust(pki));
root.Subcommands.Add(TrustCommands.CreateCert(pki));
root.Subcommands.Add(UserCommands.Create(users));

return await CliRunner.RunAsync(root, args);
