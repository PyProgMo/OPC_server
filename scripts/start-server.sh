#!/usr/bin/env bash
# Builds the OpcSuite server and starts it. Stop it with Ctrl+C.
set -euo pipefail
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
    cat <<USAGE
Usage: scripts/start-server.sh [--debug] [--no-build] [opcserver run options]

  --debug      build and run the Debug configuration (default: Release)
  --no-build   skip the build and start what was built last

Everything else is passed to 'opcserver run', for example:
  scripts/start-server.sh --url opc.tcp://localhost:4850/OpcSuite
  scripts/start-server.sh --pki ./pki --no-demo
  scripts/start-server.sh -- --help        (options of the server itself)

Other server commands (user add/list/cert, trust list/accept/import, cert) are run through the built binary:
  src/OpcSuite.Server.Cli/bin/Release/net10.0/opcserver user add alice --role Operator
  src/OpcSuite.Server.Cli/bin/Release/net10.0/opcserver trust list
USAGE
}

parse_launcher_flags "$@"
build_and_locate src/OpcSuite.Server.Cli opcserver
echo "Starting server..." >&2
exec "$EXE" run ${ARGS[@]+"${ARGS[@]}"}
