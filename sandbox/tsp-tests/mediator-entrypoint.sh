#!/usr/bin/env bash
# Condition 16.4 (Security 11984 §2-3, 12079.2): the mediator's entrypoint. It refuses to start, loudly and by name
# (never a value), when the host carries something the mediator must not see; otherwise it writes the backend
# passphrase to a tmpfs file and `exec env -i` the mediator with ONLY the allow list, so nothing is inherited.
#
# Usage: mediator-entrypoint.sh --bin <mediator> --volume <dir holding secrets.json> --tmpfs <dir> --workdir <dir>
#                               --deny-file <names, one per line> [--with-path-home] -- <mediator args>
# Host inputs (read here, never passed on): DATABASE_URL, and the passphrase's one host secret, named in
# PASSPHRASE_SOURCE below (its name goes in register L8; its value only ever in the host secret and the tmpfs file).
#
# Refuses (exit 78, "refused: <case>") when:
#   - `mediator-setup` is on PATH or beside the binary (1b: it writes the admin credential; setup job only)
#   - the plain MEDIATOR_FILE_BACKEND_PASSPHRASE is present (2i: it would sit in /proc/<pid>/environ)
#   - any MEDIATOR_TAG_* is present (12079.2: those values land in log lines; refused, never scrubbed in silence)
#   - the deny file is missing a floor deny name, or its sha256 isn't the one baked beside this script
#     (`mediator-deny.sha256`, the deny side of the 16.2(b) record at 44c7d92; Security 12144.3a: an empty or cut
#     file must never pass every deny check)
#   - any name on the deny file is present (3: the 16.2(b) record's deny side, the 4 flips among them)
#   - any other host name in the MEDIATOR_, VAULT_ or AWS_ families that isn't on the allow list (12144.2: the
#     families the mediator and its clients read; a new one stops the start loudly instead of being dropped unheard)
#   - DATABASE_URL or the passphrase source is missing or empty (a missing required value fails loudly)
#   - the tmpfs dir isn't tmpfs, is a symlink, sits on the volume's filesystem, or isn't owned by this user with
#     mode 0700 or narrower (12144.3b: no co-tenant gap between the rm and the write); the passphrase file already
#     exists as a symlink, or ends up wider than 0400 or not owned by this user (2ii)
#   - the working directory isn't an empty directory (Q1: no decoy file for a working-dir fallback)
# Host names on no list (the platform's own, e.g. its PORT) are not refused: `env -i` drops them, and one start line
# on stderr says which, by NAME only and never a value (12144.3c, charter §9: drift shows in the log, not nowhere).
set -uo pipefail
PASSPHRASE_SOURCE=ENKARA_MEDIATOR_BACKEND_PASSPHRASE
PINNED_RUST_LOG='info,affinidi_messaging_mediator::common::config=warn'   # condition 15's pinned filter (line D)
ALLOW=(DATABASE_URL MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE RUST_LOG)          # the record's allow side (L8)
# The record's floor deny names (bus 12048/12079.1), held here too so a deny file that lost one refuses by name.
FLOOR_DENY=(MEDIATOR_ACL_MODE BLOCK_REMOTE_ADMIN_MSGS ENABLE_INTER_MEDIATOR_RELAY PROCESSOR_FORWARDING_EXTERNAL
            GLOBAL_DEFAULT_ACL ADMIN_DID MEDIATOR_SECRETS_BACKEND MEDIATOR_FILE_BACKEND_PASSPHRASE)
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"

refuse() { echo "refused: $1" >&2; exit 78; }
bin= volume= tmpfs= workdir= denyfile= pathhome=0
while [ $# -gt 0 ]; do
  case "$1" in
    --bin) bin="$2"; shift 2 ;; --volume) volume="$2"; shift 2 ;; --tmpfs) tmpfs="$2"; shift 2 ;;
    --workdir) workdir="$2"; shift 2 ;; --deny-file) denyfile="$2"; shift 2 ;; --with-path-home) pathhome=1; shift ;;
    --) shift; break ;; *) refuse "unknown argument $1" ;;
  esac
done
for a in bin volume tmpfs workdir denyfile; do [ -n "${!a}" ] || refuse "missing --$a"; done
[ -x "$bin" ] || refuse "no mediator binary at --bin"
[ -r "$denyfile" ] || refuse "no deny file"
# 12144.3a: the deny file is whole, and it is the record's
for n in "${FLOOR_DENY[@]}"; do grep -qx -- "$n" "$denyfile" || refuse "the deny file is missing the floor name $n"; done
[ -r "$HERE/mediator-deny.sha256" ] || refuse "no baked deny sha256 beside the entrypoint"
want="$(tr -d ' \n' < "$HERE/mediator-deny.sha256")"; got="$(sha256sum < "$denyfile" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$got" = "$want" ] || refuse "the deny file's sha256 is not the record's"

# 1(b)
if command -v mediator-setup > /dev/null 2>&1 || [ -e "$(dirname "$bin")/mediator-setup" ]; then refuse "mediator-setup is in the image"; fi
# 2(i)
[ -z "${MEDIATOR_FILE_BACKEND_PASSPHRASE+x}" ] || refuse "MEDIATOR_FILE_BACKEND_PASSPHRASE is set on the host (use the _FILE road only)"
# 12079.2
tags="$(compgen -e | grep '^MEDIATOR_TAG_' || true)"
[ -z "$tags" ] || refuse "MEDIATOR_TAG_* present on the host: $(echo $tags)"
# 3: the deny side of the record
while IFS= read -r n; do
  [ -n "$n" ] || continue
  [ -z "${!n+x}" ] || refuse "$n is set on the host (deny list)"
done < "$denyfile"
# 12144.2: the families the mediator and its clients read, beyond the allow list
fam="$(compgen -e | grep -E '^(MEDIATOR_|VAULT_|AWS_)' | grep -vxF -f <(printf '%s\n' "${ALLOW[@]}") || true)"
[ -z "$fam" ] || refuse "host names in the MEDIATOR_/VAULT_/AWS_ families not on the allow list: $(echo $fam)"
# required values
[ -n "${DATABASE_URL:-}" ] || refuse "DATABASE_URL is missing"
[ -n "${!PASSPHRASE_SOURCE:-}" ] || refuse "$PASSPHRASE_SOURCE is missing"
# 2(ii): where the passphrase file goes
[ -L "$tmpfs" ] && refuse "the tmpfs dir is a symlink"
[ -d "$tmpfs" ] || refuse "the tmpfs dir does not exist"
[ "$(stat -f -c %T "$tmpfs")" = tmpfs ] || refuse "the passphrase dir is not tmpfs"
[ -d "$volume" ] || refuse "the volume does not exist"
[ "$(stat -c %d "$tmpfs")" != "$(stat -c %d "$volume")" ] || refuse "the passphrase dir is on the volume's filesystem"
[ "$(stat -c %u "$tmpfs")" = "$(id -u)" ] || refuse "the tmpfs dir is not owned by the service user"
dmode="$(stat -c %a "$tmpfs")"; (( (8#$dmode & 8#077) == 0 )) || refuse "the tmpfs dir's mode is $dmode, wider than 0700"
pf="$tmpfs/backend-passphrase"
[ -L "$pf" ] && refuse "the passphrase file is a symlink"
rm -f -- "$pf"
( umask 0377; set -o noclobber; printf '%s' "${!PASSPHRASE_SOURCE}" > "$pf" ) || refuse "could not write the passphrase file"
[ -L "$pf" ] && refuse "the passphrase file is a symlink"
mode="$(stat -c %a "$pf")"; owner="$(stat -c %u "$pf")"
case "$mode" in 400|0) ;; *) refuse "the passphrase file's mode is $mode, wider than 0400" ;; esac
[ "$owner" = "$(id -u)" ] || refuse "the passphrase file is not owned by the service user"
# Q1: fixed, empty working directory
[ -d "$workdir" ] && [ ! -L "$workdir" ] || refuse "the working directory is not a directory"
[ -z "$(ls -A "$workdir")" ] || refuse "the working directory is not empty"

cd "$workdir" || refuse "cannot enter the working directory"
keep=(DATABASE_URL="$DATABASE_URL" MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE="$pf" RUST_LOG="$PINNED_RUST_LOG")
[ "$pathhome" = 1 ] && keep+=(PATH=/usr/local/bin:/usr/bin:/bin HOME="$workdir")
# 12144.3c: what `env -i` drops, names only (the shell's own PWD/OLDPWD/SHLVL/_ aside; DATABASE_URL is passed on)
dropped="$(compgen -e | grep -vxE '(DATABASE_URL|PWD|OLDPWD|SHLVL|_)' | LC_ALL=C sort || true)"
echo "entrypoint: env -i dropped $(printf '%s' "$dropped" | grep -c . || true) host names: $(echo $dropped)" >&2
exec env -i "${keep[@]}" "$bin" "$@"
