# Shared by the demo scripts: run from the repository root, print step headers, and
# provide `demo "<ticket>"`, which sends one ticket unguarded and then guarded.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PYTHONPATH=.

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
demo() { python3 demos/demo.py "$1"; }
