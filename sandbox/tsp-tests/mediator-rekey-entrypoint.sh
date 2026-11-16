#!/bin/bash -p
# The one-off rekey image's entrypoint (Security 12024.1, shape B: the image swap in place). It is the image's
# exec-form ENTRYPOINT, `/bin/bash -p /opt/rekey/rekey-entrypoint.sh`, and it does one thing: write the old and the new
# backend passphrase to a fresh private tmpfs dir, then `exec env -i` the shipped store tool's `rekey` with ONLY
#   REKEY_STORE, REKEY_OLD_PASSPHRASE_FILE, REKEY_NEW_PASSPHRASE_FILE, PATH=/usr/local/bin:/usr/bin:/bin, HOME
# (HOME = the image's empty read-only /opt/rekey/home). In shape B the run sees the mediator service's whole variable
# set (DATABASE_URL, the Redis password, …); none of it reaches the tool, which checks its own /proc/self/environ and
# refuses on any other name. Accepted limit (Security 12024.1): this script's own pid sees the service's variables for
# its first lines; it is ours, and the base diff pins it.
#
# The shell guards are the service entrypoint's (12180, 12346): -p, PATH first, `set -f`, host names read from
# /proc/$$/environ, the shell/loader names refused by name, a non-plain name refused by count, every host name
# un-exported before any tool runs. Names only on stderr, never a value.
#
# Usage: rekey-entrypoint.sh --volume <dir holding secrets.json> --tmpfs <tmpfs root, e.g. /dev/shm>
# Host inputs (read here, never passed on): ENKARA_MEDIATOR_BACKEND_PASSPHRASE (today's, the one that opens the store)
# and ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW (the sitting's new one; after the read-back it replaces the first and is
# removed, sheet E step 6).
# Refuses (exit 78, "refused: <case>") when: an unknown or missing argument; a shell/loader name or a non-plain name on
# the host; either passphrase missing or empty, or the two equal; the tmpfs root not tmpfs, a symlink, or on the
# volume's filesystem; the private dir or a passphrase file not ours, wider than 0700/0400, or a symlink; the store
# missing, a symlink or not a regular file; HOME not an empty directory; the tool or node not where the image puts them.
# Then the tool's own exit is the run's: 0 = re-sealed and read back (old no longer opens, new does), 1 = refused or
# failed with nothing written, 6 = its environment is not exactly the allow list.
PATH=/usr/bin:/bin; export PATH
set -f
set -uo pipefail
refuse() { echo "refused: $1" >&2; exit 78; }
HOST_NAMES=()
mapfile -d '' -t _host_env < "/proc/$$/environ" || refuse "cannot read the host environment"
for _kv in "${_host_env[@]}"; do HOST_NAMES+=("${_kv%%=*}"); done
unset _host_env _kv
PLAIN_NAME='^[A-Za-z_][A-Za-z0-9_]*$'
host_matching() { local n; MATCH=(); for n in "${HOST_NAMES[@]}"; do [[ "$n" =~ $1 ]] && MATCH+=("$n"); done; return 0; }
say_names() {
  local n out=() withheld=0
  for n in "$@"; do
    if [[ "$n" =~ $PLAIN_NAME || "$n" =~ ^BASH_FUNC_[A-Za-z0-9_]+%%$ ]]; then out+=("$n"); else withheld=$((withheld + 1)); fi
  done
  [ "${#out[@]}" -gt 0 ] && printf '%s' "${out[0]}" && [ "${#out[@]}" -gt 1 ] && printf ' %s' "${out[@]:1}"
  [ "$withheld" -gt 0 ] && printf '%s%d not plain names (withheld)' "$([ "${#out[@]}" -gt 0 ] && printf ' + ')" "$withheld"
  return 0
}
host_matching '^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS)$|^BASH_FUNC_|^LD_'
[ "${#MATCH[@]}" -eq 0 ] || refuse "host names that change the shell or the loader: $(say_names "${MATCH[@]}")"
_odd=0; for _n in "${HOST_NAMES[@]}"; do [[ "$_n" =~ $PLAIN_NAME ]] || _odd=$((_odd + 1)); done
[ "$_odd" -eq 0 ] || refuse "$_odd host names that aren't plain names"
unset _odd
for _n in "${HOST_NAMES[@]}"; do [ "$_n" != PATH ] && export -n "$_n"; done
unset _n
export LC_ALL=C
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
OLD_SOURCE=ENKARA_MEDIATOR_BACKEND_PASSPHRASE
NEW_SOURCE=ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW
NODE=/usr/local/bin/node
TOOL="$HERE/mediator-store.mjs"
RHOME="$HERE/home"

volume= tmproot=
while [ $# -gt 0 ]; do
  case "$1" in
    --volume) volume="${2:-}"; shift 2 || refuse "missing --volume value" ;;
    --tmpfs) tmproot="${2:-}"; shift 2 || refuse "missing --tmpfs value" ;;
    *) refuse "unknown argument (rekey takes only --volume and --tmpfs)" ;;
  esac
done
[ -n "$volume" ] || refuse "missing --volume"
[ -n "$tmproot" ] || refuse "missing --tmpfs"
[ -x "$NODE" ] && [ -f "$TOOL" ] && [ ! -L "$TOOL" ] || refuse "the tool or node is not where the image puts them"
[ -d "$RHOME" ] && [ ! -L "$RHOME" ] && [ -z "$(ls -A "$RHOME")" ] || refuse "HOME ($RHOME) is not an empty directory"
# required values (a missing one fails loudly, never a silent no-op)
[ -n "${!OLD_SOURCE:-}" ] || refuse "$OLD_SOURCE is missing"
[ -n "${!NEW_SOURCE:-}" ] || refuse "$NEW_SOURCE is missing"
[ "${!OLD_SOURCE}" != "${!NEW_SOURCE}" ] || refuse "$NEW_SOURCE equals $OLD_SOURCE"
# the store: ours, a regular file (the tool reads it; the encrypted backend would make an empty one if it were gone)
store="$volume/secrets.json"
[ -d "$volume" ] && [ ! -L "$volume" ] || refuse "the volume is not a directory"
[ -L "$store" ] && refuse "the secret store is a symlink"
[ -f "$store" ] || refuse "no secret store on the volume"
# where the passphrases go: a fresh private dir on tmpfs, never on the volume
[ -L "$tmproot" ] && refuse "the tmpfs root is a symlink"
[ -d "$tmproot" ] || refuse "the tmpfs root does not exist"
[ "$(stat -f -c %T "$tmproot")" = tmpfs ] || refuse "the passphrase root is not tmpfs"
[ "$(stat -c %d "$tmproot")" != "$(stat -c %d "$volume")" ] || refuse "the passphrase root is on the volume's filesystem"
pp="$(umask 0077; mktemp -d "$tmproot/rekey.XXXXXXXX")" || refuse "could not make the private passphrase dir"
[ ! -L "$pp" ] && [ "$(stat -c %u "$pp")" = "$(id -u)" ] || refuse "the private passphrase dir is not ours"
dmode="$(stat -c %a "$pp")"; (( (8#$dmode & 8#077) == 0 )) || refuse "the private passphrase dir's mode is $dmode, wider than 0700"
for side in old new; do
  src=$OLD_SOURCE; [ "$side" = new ] && src=$NEW_SOURCE
  f="$pp/$side"
  ( umask 0377; set -o noclobber; printf '%s' "${!src}" > "$f" ) || refuse "could not write the $side passphrase file"
  [ ! -L "$f" ] && [ "$(stat -c %u "$f")" = "$(id -u)" ] || refuse "the $side passphrase file is not ours"
  case "$(stat -c %a "$f")" in 400) ;; *) refuse "the $side passphrase file is wider than 0400" ;; esac
done
unset side src f
cd "$RHOME" || refuse "cannot enter HOME"
# What `env -i` drops, names only (12144.3c's shape): every name the host passed, for sheet E.
dropped=()
[ "${#HOST_NAMES[@]}" -gt 0 ] && mapfile -t dropped < <(printf '%s\n' "${HOST_NAMES[@]}" | sort -u || true)
printf 'rekey-entrypoint: env -i dropped %d host names: %s\n' "${#dropped[@]}" "$(say_names "${dropped[@]}")" >&2
exec /usr/bin/env -i REKEY_STORE="$store" REKEY_OLD_PASSPHRASE_FILE="$pp/old" REKEY_NEW_PASSPHRASE_FILE="$pp/new" \
  PATH=/usr/local/bin:/usr/bin:/bin HOME="$RHOME" "$NODE" "$TOOL" rekey "$store" "$pp/old" "$pp/new"
