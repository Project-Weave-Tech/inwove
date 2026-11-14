#!/usr/bin/env bash
# Install didwebvh-py from its pinned sha into a venv and export WPI_PYTHON. Prints the FULL sha. Usage: install-py.sh <workdir>
set -euo pipefail
work="${1:?workdir}"
pin="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$(dirname "$0")/../pins.json','utf8'))['didwebvh-py'].head)")"
mkdir -p "$work"
git clone --quiet https://github.com/decentralized-identity/didwebvh-py "$work/src"
git -C "$work/src" checkout --quiet --detach "$pin"
full="$(git -C "$work/src" rev-parse HEAD)"
case "$full" in "$pin"*) ;; *) echo "didwebvh-py checkout is $full, pin is $pin" >&2; exit 1;; esac
python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --quiet --disable-pip-version-check "$work/src"
echo "didwebvh-py pinned at $full"
moved_from="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$(dirname "$0")/../pins.json','utf8'))['didwebvh-py'].movedOnPurpose?.from ?? '')")"
if [ -n "$moved_from" ]; then echo "didwebvh-py pin moved on purpose from $moved_from; the commits in between:"; git -C "$work/src" log --format='  %h %s' "$moved_from..$full"; fi
"$work/venv/bin/python" -I -c "import did_webvh.resolver"
if [ -n "${GITHUB_ENV:-}" ]; then echo "WPI_PYTHON=$work/venv/bin/python" >> "$GITHUB_ENV"; fi
