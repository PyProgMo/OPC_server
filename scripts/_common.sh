# Shared helpers for the launcher scripts. Sourced by them, not meant to be run directly.

ROOT="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/.." && pwd)"
CONFIG=Release
BUILD=1
ARGS=()

die() { echo "error: $*" >&2; exit 1; }

# Finds the .NET SDK: PATH first, then DOTNET_ROOT, then the per-user install in ~/.dotnet.
find_dotnet() {
    if command -v dotnet >/dev/null 2>&1; then
        DOTNET="$(command -v dotnet)"
    elif [[ -n "${DOTNET_ROOT:-}" && -x "$DOTNET_ROOT/dotnet" ]]; then
        DOTNET="$DOTNET_ROOT/dotnet"
    elif [[ -x "$HOME/.dotnet/dotnet" ]]; then
        DOTNET="$HOME/.dotnet/dotnet"
    else
        die "no .NET SDK found. Install the .NET 10 SDK (https://dot.net) or set DOTNET_ROOT."
    fi
    # the built executables locate their runtime through DOTNET_ROOT
    DOTNET_ROOT="$(dirname "$(readlink -f "$DOTNET")")"
    export DOTNET_ROOT
}

# Consumes the leading launcher flags; everything from the first other argument on goes to the program.
parse_launcher_flags() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --debug)    CONFIG=Debug ;;
            --no-build) BUILD=0 ;;
            -h|--help)  usage; exit 0 ;;
            --)         shift; break ;;
            *)          break ;;
        esac
        shift
    done
    ARGS=("$@")
}

# build_and_locate <project folder relative to the repo> <executable name>  -> sets EXE
build_and_locate() {
    local project="$ROOT/$1" name="$2"
    find_dotnet
    if [[ $BUILD -eq 1 ]]; then
        echo "Building $1 ($CONFIG)..." >&2
        # warnings are errors in this repo, so a successful build has nothing worth showing
        local log
        log="$("$DOTNET" build "$project" -c "$CONFIG" --nologo -v quiet 2>&1)" || { echo "$log" >&2; die "build failed"; }
    fi
    EXE="$(ls -d "$project"/bin/"$CONFIG"/*/"$name" 2>/dev/null | head -1 || true)"
    [[ -n "$EXE" && -x "$EXE" ]] || die "$name not found under $1/bin/$CONFIG - run without --no-build"
}
