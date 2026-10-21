# OpcSuite

An **OPC UA server** and a **command-line client** in C# (.NET 10). Everything is built from small
modules so it can grow, every byte of traffic is signed and encrypted, and every session belongs to a
user whose roles decide which nodes it may see, read and write.

```
opcserver run                 start the server (hosts the modules)
opcserver user add            let someone log in
opcctl browse / read / write / subscribe / shell     talk to it
```

## What "encrypted with SHA-256" means here

SHA-256 is a hash, not a cipher, so it can't encrypt anything by itself. The OPC UA security profile
that matches the request is **`Basic256Sha256`** (the default here):

| Purpose                     | Algorithm                                   |
| --------------------------- | ------------------------------------------- |
| Message encryption          | AES-256-CBC                                 |
| Message integrity           | HMAC-SHA-256                                |
| Key exchange / handshake    | RSA with SHA-256 signed certificates        |

It always runs as `SignAndEncrypt`. There is **no unencrypted endpoint**: the server only offers the
configured profile, the client refuses anything else, and the server aborts at start-up if an endpoint
ever deviates. Two newer SHA-256 profiles can be selected with `--security`
(`Aes256_Sha256_RsaPss`, `Aes128_Sha256_RsaOaep`).

The cryptography comes from the **OPC Foundation's reference stack**
([UA-.NETStandard](https://github.com/OPCFoundation/UA-.NETStandard), MIT licence) rather than
home-grown code. It is pinned to `1.5.378.182`; a 2.0 line exists but is only weeks old, so moving to
it is a deliberate later step (versions are centralised in `Directory.Packages.props`).

## Quick start

Needs the .NET 10 SDK (if `dotnet` is not found, an SDK may be in `~/.dotnet`).

```bash
# terminal 1 - build and start the server (creates its certificate on first start, prints its SHA-256)
scripts/start-server.sh

# terminal 2 - add a user (works while the server runs; asks for a password),
#              then build the client and run the first-connection handshake as that user
src/OpcSuite.Server.Cli/bin/Release/net10.0/opcserver user add alice --role Operator
scripts/run-client.sh -u alice
```

The scripts build first (`--no-build` skips that, `--debug` switches configuration) and find the SDK even
when `dotnet` isn't on `PATH`. Anything else is passed through to the program, so
`scripts/start-server.sh --url opc.tcp://localhost:4850/OpcSuite` and
`scripts/run-client.sh -e opc.tcp://localhost:4850/OpcSuite handshake` work as you'd expect; with only
options and no command, the client script runs `handshake`. `dotnet test` runs the test suite.

The first handshake is refused because the server doesn't know the client yet; that is the trust
step described below. Without `-u` (or `--user-cert`) the handshake stops at step 1 and says the server
wants a login.

### The first connection: `opcctl handshake`

`handshake` connects in three narrated steps and tells you what to do when one fails:

```
[1/3] Discovery            what the server offers, its certificate SHA-256, whether you trust it yet,
                           which logins it accepts
[2/3] Encrypted channel    both certificates are checked, then the server checks the user;
      and login            shows the client certificate the server accepted and who is logged in
[3/3] Server status        first encrypted request: server name, state, round-trip time
```

Typical failures and their messages: server not running (start it with the script), the server doesn't
offer the required protection (`--security` mismatch), the server doesn't trust this client yet (prints the
`opcserver trust accept <fingerprint>` command to run), this client doesn't trust the server (prints how
to pin its SHA-256), no login given, wrong user name or password, or a user certificate that is not
registered yet (prints the `opcserver user cert add` command).
`dotnet publish src/OpcSuite.Server.Cli -c Release -o out/server` produces the `opcserver` executable
(add `--self-contained` for one that needs no installed runtime); the client project produces `opcctl`.

### Trust: both sides must know each other

OPC UA authenticates with certificates, so trust is explicit in **both** directions:

1. **Client trusts the server.** In a terminal the client shows the server's SHA-256 and asks
   (like SSH). In scripts, pass it up front: `opcctl --trust-server <SHA-256> ...`. A matching
   fingerprint is remembered, so later runs need nothing. Compare it with `opcserver cert`.
2. **Server trusts the client.** An unknown client is turned away and parked in the rejected list.
   The operator reviews and accepts it:
   ```bash
   opcserver trust list
   opcserver trust accept <first 8+ hex digits of the fingerprint>
   ```
   or imports the client's certificate file (`opcctl cert` prints its path):
   `opcserver trust import client.der`.

`opcserver trust remove <fp>` revokes a client. `--accept-all-clients` exists for throw-away testing
only and disables client authentication; it prints a warning.

### Users and permissions

The certificate says *which application* connects; the login says *who* uses it. Every session logs in,
and the user's roles decide, node by node, what it may see, read and write.

**Users** live in `~/.local/share/OpcSuite/server/users.json` (`--users` to change). Changes apply
to a running server immediately.

```bash
opcserver user add alice --role Operator     # asks for the password twice (or reads OPCSUITE_PASSWORD)
opcserver user add plc7 --role Observer --no-password   # certificate login only, see below
opcserver user list
opcserver user roles alice Operator Engineer # replace the roles
opcserver user passwd alice
opcserver user remove alice
```

Passwords are stored as salted PBKDF2-SHA-256 hashes (600 000 iterations), at least 8 characters.
On the wire the password is encrypted with the server's key on top of the encrypted channel. After 5
wrong passwords in a row a user name is locked for a minute (then one try per minute until a success).
Wrong user names and wrong passwords get the same answer and take the same time.

**User certificates** replace the password with a key pair that never leaves the client:

```bash
opcctl user-cert create plc7                 # on the client: prints the SHA-256
opcserver user cert add plc7 <SHA-256>       # on the server, after comparing the SHA-256 with the user
opcctl --user-cert plc7 read ...
```

The server also refuses user certificates that are expired, SHA-1 signed or have RSA keys under 2048 bits.

**Roles** are the OPC UA well-known roles: `Observer`, `Operator`, `Engineer`, `Supervisor`,
`ConfigureAdmin`, `SecurityAdmin`. Every logged-in user also has `AuthenticatedUser`. Anonymous
sessions are off; `opcserver run --allow-anonymous` turns them on, with the role `Anonymous`.

**Per-node permissions** come from `access.json` in the same folder (`--access` to change). Without
the file, everybody may read and `Operator`, `Engineer` and `Supervisor` may also write
(writable variables only):

```jsonc
{
  // optional; this is the built-in default
  "default": { "AuthenticatedUser": "read", "Anonymous": "read",
               "Operator": "write", "Engineer": "write", "Supervisor": "write" },
  "nodes": {
    "Demo/Setpoint": { "AuthenticatedUser": "read", "Engineer": "write" },
    "Demo/Sensors":  { "Supervisor": "read" },   // folder: covers everything below it
    "Demo/Clock":    { }                         // nobody
  }
}
```

A rule is keyed by node path (module, folders, variable) and covers that node and everything below it.
The rule with the longest matching path decides **alone**: it does not inherit from the rules above it,
so each rule states fully who may do what. A user gets the best permission any of its roles has: `none`,
`read` (browse, read, subscribe) or `write` (also write). The server checks the rules on startup, prints
them, and warns about a rule that matches no node, which is usually a typo. A
restart applies changes.

Rules become standard OPC UA `RolePermissions` on every node, and the stack checks them on browse,
read, write and subscriptions. Nodes a user may not read are left out of its browse results.
Each variable's `UserAccessLevel` reports what the logged-in user may do, which `opcctl browse` shows as
`read/write` or `read-only`. The server logs every login, refusal and write with the user's name.

### Using the client

```bash
opcctl -e opc.tcp://myserver:4840/OpcSuite -u alice browse -d 2
opcctl -u alice read  "nsu=urn:opcsuite:modules;s=Demo/Counter" "nsu=urn:opcsuite:modules;s=Demo/Setpoint"
opcctl -u alice write "nsu=urn:opcsuite:modules;s=Demo/Setpoint" 42.5
opcctl --user-cert plc7 subscribe "nsu=urn:opcsuite:modules;s=Demo/Counter" -i 500
opcctl -u alice shell             # connect and log in once, run many commands
opcctl -u alice handshake         # the first connection, step by step
opcctl endpoints                  # what the server advertises (unauthenticated)
```

`-u` asks for the password in a terminal. Scripts set `OPCSUITE_PASSWORD` instead; there is deliberately
no password option, because it would end up in the shell history and the process list.
Node ids can be written `ns=2;s=...` or namespace-independent `nsu=<uri>;s=...`.
Global options (`-e`, `--pki`, `--security`, `--trust-server`, `--skip-host-check`, `-u`/`--user`,
`--user-cert`, `--log-level`) work before or after the command. Certificates live in
`~/.local/share/OpcSuite/{server,client}/pki` (`--pki` to change), user certificates in the client's
`pki/user`. **These folders contain private keys.**

## Architecture

```
                    OpcSuite.Core            module contract, no OPC UA dependency
                    (IServerModule, INodeFolder, ModuleCatalog)
                         ▲                ▲
        OpcSuite.Modules.Demo             │
        (your modules)                    │
                                  OpcSuite.Server ──► OpcSuite.Crypto ◄── OpcSuite.Client
                                  (OPC UA host)       (profile, PKI,      (session, browse,
                                        ▲              trust policy)       read/write/subscribe)
                                        │                    ▲                    ▲
                              OpcSuite.Server.Cli     OpcSuite.Cli.Common   OpcSuite.Client.Cli
                              → `opcserver`           (trust/cert commands) → `opcctl`
```

| Project | Role |
| --- | --- |
| `OpcSuite.Core` | What a module is. Modules build nodes through a protocol-neutral API (`AddFolder`, `AddVariable<T>`), never the OPC UA stack. |
| `OpcSuite.Crypto` | **The cryption module.** `ICryptoModule` decides the allowed protection, where keys live and whom to trust; `OpcUaCryptoModule` implements it on the OPC Foundation stack. Server and client never configure security themselves. |
| `OpcSuite.Server` | Hosts modules in one OPC UA namespace (`urn:opcsuite:modules`) and enforces the crypto profile. `Security/` holds the users, the login checks and the per-node access rules. |
| `OpcSuite.Client` | Library behind `opcctl`; usable from your own code. |
| `OpcSuite.*.Cli`, `Cli.Common` | The two executables and the shared `trust` / `cert` commands. |
| `OpcSuite.Modules.Demo` | Counter, clock, writable setpoint/message, temperature that follows the setpoint. A template. |

### Writing a module

```csharp
public sealed class PumpModule : IServerModule
{
    public string Name => "Pump";                       // folder name under Objects

    public void CreateNodes(IModuleContext context)     // build the address space once
    {
        var speed = context.Root.AddVariable("Speed", 0.0, NodeAccess.ReadWrite);
        speed.WrittenByClient += rpm => context.Logger.LogInformation("Speed set to {Rpm}", rpm);
    }

    public Task StartAsync(CancellationToken ct) => Task.CompletedTask;   // optional background work
    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
```

Supported variable types: `bool, byte, sbyte, short, ushort, int, uint, long, ulong, float, double, string, DateTime`.
Assigning `speed.Value = ...` from your code publishes the change to subscribed clients.

Register it in code (`new ModuleCatalog().Add<PumpModule>()`) **or** build it as a separate class library that
references only `OpcSuite.Core`, drop the DLL into a folder and start the server with `--plugins <folder>`.
Plugins execute code with the server's privileges: only load folders you control.

## Security notes

Covered:
* All sessions are `SignAndEncrypt`; no `None` endpoint. (A raw `None` channel is only accepted for endpoint
  discovery, which exposes nothing but the public endpoint list and certificate.) A packet capture of a
  write through a recording proxy contained the profile name in the handshake header and **none** of the
  written value, node ids or names.
* Both sides authenticate by certificate; untrusted peers are refused and recorded. Expired, weak
  (< 2048-bit RSA), SHA-1-signed or otherwise invalid certificates can't be overridden by any trust policy.
* The client checks that the server certificate lists the host name it connected to
  (`--skip-host-check` relaxes this for fingerprint-pinned servers reached by IP).
* Every session logs in as a user: a password (PBKDF2 hashed, lockout after repeated failures) or a user
  certificate (the client proves it holds the private key). There are no anonymous sessions unless
  `--allow-anonymous` is given.
* Per-node authorisation: role permissions from `access.json` on every node, checked by the stack on
  browse, read, write and subscriptions. Logins, refusals and writes are logged with the user's name.

Not covered yet (relevant before exposing this to the internet):
* Self-signed certificates only; no CA / GDS integration and no automatic renewal (certificates last one year).
* No rate limiting or connection quotas beyond the stack's defaults. The login lockout is per user name.
  The stack checks logins one at a time and each password costs a PBKDF2 run, so a trusted but hostile
  client could slow logins down for others.
* Rules apply to the module nodes. The standard `Server` object (status, capabilities) stays readable by
  every logged-in session, as the stack ships it.
* Removing a user or changing its roles only affects new logins: sessions already open keep their user and
  roles until they end.
* To serve over the internet: start with `--url opc.tcp://your.public.name:4840/OpcSuite`, open the port, and
  give clients the fingerprint through a channel you trust. The host name is written into the server
  certificate when it is created. If you change it later the server refuses to start (and says why) until you
  delete `<pki>/own`; the regenerated certificate has a new fingerprint that clients must trust again.
  A VPN or SSH tunnel in front is still a sensible extra layer.

Operational detail: the stack caches the trusted-certificate folder and decides it is stale by directory
modification time. A trust change made within a few milliseconds of a connection attempt can be missed once;
a human using `trust accept` is never that fast, but test code that automates it should wait ~100 ms
(see `ServerFixture.LetServerRescanTrustListAsync`).

## Tests

`dotnet test` runs unit tests plus integration tests against a real server on a free local port with a
throw-away PKI and users: encrypted-only endpoints, rejected-then-trusted clients, pinned and wrong-pin
servers, refused plaintext sessions, protection mismatch, host-name check, browse / read / write /
subscribe. Login tests cover password, user certificate, refused anonymous (also when the client skips its
own check), wrong and unknown users, lockout and users added while the server runs. Permission tests
cover read-only and write roles, per-node rules, hidden folders and a rule that grants nobody. Unit tests
cover password hashing, rule parsing and matching, the lockout timing and the users file.
Set `OPCSUITE_TEST_LOG=Information` to see what the stack is doing.
