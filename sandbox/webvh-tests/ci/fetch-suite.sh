#!/usr/bin/env bash
# Clone the test suite and check out the pinned sha. Prints and records the FULL sha. Usage: fetch-suite.sh <dest>
set -euo pipefail
dest="${1:?dest}"
pin="$(node -e "console.log(JSON.parse(require('fs').readFileSync('$(dirname "$0")/../pins.json','utf8'))['didwebvh-test-suite'].head)")"
git clone --quiet https://github.com/decentralized-identity/didwebvh-test-suite "$dest"
git -C "$dest" checkout --quiet --detach "$pin"
full="$(git -C "$dest" rev-parse HEAD)"
case "$full" in "$pin"*) ;; *) echo "test-suite checkout is $full, pin is $pin" >&2; exit 1;; esac
echo "didwebvh-test-suite pinned at $full"
