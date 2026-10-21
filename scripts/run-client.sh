#!/usr/bin/env bash
# Builds the OpcSuite client and runs it. Without arguments it performs the first-connection handshake.
set -euo pipefail
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
    cat <<USAGE
Usage: scripts/run-client.sh [--debug] [--no-build] [opcctl arguments]

  --debug      build and run the Debug configuration (default: Release)
  --no-build   skip the build and run what was built last

Everything is passed to opcctl. If no command is given (no arguments, or only options like -e), it runs 'opcctl handshake':
  scripts/run-client.sh
  scripts/run-client.sh -e opc.tcp://myserver:4840/OpcSuite handshake
  scripts/run-client.sh read "nsu=urn:opcsuite:modules;s=Demo/Counter"
  scripts/run-client.sh shell
  scripts/run-client.sh -- --help          (all opcctl commands)
USAGE
}

parse_launcher_flags "$@"
build_and_locate src/OpcSuite.Client.Cli opcctl

# Options only (e.g. just '-e <url>')? Then the user wants the default command.
has_command=0
for arg in ${ARGS[@]+"${ARGS[@]}"}; do
    case " info browse read write subscribe handshake shell endpoints trust cert -h --help -? --version " in
        *" $arg "*) has_command=1 ;;
    esac
done
[[ $has_command -eq 1 ]] || ARGS+=(handshake)

exec "$EXE" ${ARGS[@]+"${ARGS[@]}"}
