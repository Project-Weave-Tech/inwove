#!/usr/bin/env bash
# ref/09 §1 "How a pin is checked" (Security, bus 12036): fetch EXACTLY a pinned commit by its full sha, with no
# token, and prove upstream has it. On GitHub a bare sha fetched from owner/repo is also served when it lives only in
# a fork in the same network (an "imposter commit"), so the fetched sha alone doesn't prove the upstream ever had it:
# the pin's `ref` (its release tag, else the default branch) is fetched blobless and the sha must be its ancestor.
# Fails closed: any fetch error, a sha that isn't 40 hex, a HEAD that isn't the sha, or a sha off the ref all exit 1.
# Never calls api.github.com and never falls back to it.
#
# Usage: fetch-pinned.sh <repo url> <full sha> <ref> <dir> [--checkout]
# Prints one JSON line: {"repo","sha","ref","ref_tip","ancestor"}. With --checkout, leaves <dir> at the sha.
set -euo pipefail
repo="$1"; sha="$2"; ref="$3"; dir="$4"; mode="${5:-}"
[[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "pin is not a full 40-char sha: $sha" >&2; exit 1; }
[ -n "$ref" ] || { echo "pin has no ref to check ancestry against" >&2; exit 1; }
git init -q "$dir"
git -C "$dir" -c protocol.version=2 fetch -q --depth 1 "$repo" "$sha"
got="$(git -C "$dir" rev-parse FETCH_HEAD)"
[ "$got" = "$sha" ] || { echo "fetched $got, pinned $sha" >&2; exit 1; }
git -C "$dir" update-ref refs/wpi/pinned "$sha"
# The ref, blobless (history only). A shallow pinned fetch would cut the ancestry walk, so unshallow just this ref.
git -C "$dir" -c protocol.version=2 fetch -q --filter=blob:none --unshallow "$repo" "$ref" 2>/dev/null \
  || git -C "$dir" -c protocol.version=2 fetch -q --filter=blob:none "$repo" "$ref"
tip="$(git -C "$dir" rev-parse FETCH_HEAD^{commit})"
if git -C "$dir" merge-base --is-ancestor "$sha" "$tip"; then anc=true; else anc=false; fi
if [ "$mode" = "--checkout" ]; then git -C "$dir" checkout -q "$sha"; test "$(git -C "$dir" rev-parse HEAD)" = "$sha"; fi
printf '{"repo":"%s","sha":"%s","ref":"%s","ref_tip":"%s","ancestor":%s}\n' "$repo" "$sha" "$ref" "$tip" "$anc"
[ "$anc" = true ] || { echo "$sha is not an ancestor of $ref ($tip): not upstream's" >&2; exit 1; }
