#!/bin/bash -p
# 12180 (Security): this script never trusts the shell the host hands it. It runs as `/bin/bash -p <script>` (the
# image's exec-form ENTRYPOINT, and this shebang): no BASH_ENV/ENV, no imported functions, SHELLOPTS/BASHOPTS/CDPATH/
# GLOBIGNORE ignored. Its first statement sets PATH, every tool it calls resolves under /usr/bin:/bin, the host's own
# exported names are un-exported before any tool runs, and the mediator is started with /usr/bin/env -i by path, so a
# host PATH is only ever a name on the dropped line. Host names are read from /proc/$$/environ (the kernel's copy of
# what the host passed), never from `compgen -e`, which under -p doesn't list a BASH_FUNC_x%% name.
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
#   - 16.3(b): the backend's own storage (`<volume>/secrets.json`) names `mediator_admin_credential` at all, public or
#     private. Entry names are plaintext in both file shapes, so this needs no passphrase. Fail closed: the bare name
#     anywhere in the file refuses (values are base64url, so it can only appear as an entry name), AND any `\u` escape
#     anywhere in the file refuses (Security 12247.1: a key spelled `"\u006dediator_admin_credential"` is missed by a
#     plain grep, yet JSON.parse and serde_json both decode it to the real name; serde writes no `\u` for these
#     names, and values and salts are base64url, so a `\u` in our store only ever means someone wrote it by hand).
#     JSON's other escapes (\" \\ \/ \b \f \n \r \t) can't produce a letter or `_`, so they can't spell the name.
#   - the mediator's own conf (its `-c`/`--config` argument) is missing, a symlink, or has any `backend = "file://…"`
#     line other than exactly `file://<volume>/secrets.json?encrypt=1`, or not exactly one (Security 12247.4: the
#     check above must read the same file the mediator opens)
#   - the conf's `[security]` doesn't hold `trust_task_verification = "enforce"` as a typed literal, exactly once
#     (Security 12672.2; under `warn` an unsigned or replayed admin write is let through), or holds a TOML
#     multi-line string anywhere (Security 12795.2: one can hide a line that reads as the key), or a brace on any
#     non-comment line (Security 12892.3: a TOML 1.1 multi-line inline table can hide it too)
#   - the store file is missing, a symlink or not a regular file: the encrypted backend CREATES an empty store when
#     its file is absent (file_encrypted.rs open → init_new), so a lost volume must stop the start, never be replaced
# Host names on no list (the platform's own, e.g. its PORT) are not refused: `env -i` drops them, and one start line
# on stderr says which, by NAME only and never a value (12144.3c, charter §9: drift shows in the log, not nowhere).
# Security 12346: a host name is never a glob and never printed unless it is a plain name. `set -f` right after PATH,
# every name list is printed from an array, quoted, and a host name that isn't `^[A-Za-z_][A-Za-z0-9_]*$` refuses the
# start by COUNT only (a `/dev/shm/*` name would list tmpfs file names; a newline name would forge a line).
PATH=/usr/bin:/bin; export PATH
set -f
set -uo pipefail
refuse() { echo "refused: $1" >&2; exit 78; }
# 12180 (iv): every name the host passed, from the kernel's copy, builtins only (no tool has run yet).
HOST_NAMES=()
mapfile -d '' -t _host_env < "/proc/$$/environ" || refuse "cannot read the host environment"
for _kv in "${_host_env[@]}"; do HOST_NAMES+=("${_kv%%=*}"); done
unset _host_env _kv
host_has() { local n; for n in "${HOST_NAMES[@]}"; do [ "$n" = "$1" ] && return 0; done; return 1; }
PLAIN_NAME='^[A-Za-z_][A-Za-z0-9_]*$'
# host_matching <regex>: the host names matching it, into the array MATCH (never through a word-split string).
host_matching() { local n; MATCH=(); for n in "${HOST_NAMES[@]}"; do [[ "$n" =~ $1 ]] && MATCH+=("$n"); done; return 0; }
# say_names <names…>: one line, the names quoted from the array; any name not safe to print is counted, never shown.
# Safe = a plain name, or BASH_FUNC_<plain>%% (the shape bash itself exports, so 12180's refusal can still name it).
say_names() {
  local n out=() withheld=0
  for n in "$@"; do
    if [[ "$n" =~ $PLAIN_NAME || "$n" =~ ^BASH_FUNC_[A-Za-z0-9_]+%%$ ]]; then out+=("$n"); else withheld=$((withheld + 1)); fi
  done
  [ "${#out[@]}" -gt 0 ] && printf '%s' "${out[0]}" && [ "${#out[@]}" -gt 1 ] && printf ' %s' "${out[@]:1}"
  [ "$withheld" -gt 0 ] && printf '%s%d not plain names (withheld)' "$([ "${#out[@]}" -gt 0 ] && printf ' + ')" "$withheld"
  return 0
}
# 12180 (iii): the names that change what a shell or the loader does, refused by name before any tool runs. Under
# -p bash ignores the shell ones already; the loader reads LD_* before this line, so the refusal is the tripwire
# and a read-only image is the guard. A platform that sets one on its own is a finding about the image (Security
# 12204.2c), never a reason to shorten this list.
host_matching '^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS)$|^BASH_FUNC_|^LD_'
[ "${#MATCH[@]}" -eq 0 ] || refuse "host names that change the shell or the loader: $(say_names "${MATCH[@]}")"
# 12346.2: every other host name must be a plain name; the rest refuse by count, never printed. These are also the
# names `export -n` below can't take, so without this they would still reach grep/sha256sum/stat. A platform that
# sets one is an image/platform finding (12204.2c), never a loosening.
_odd=0; for _n in "${HOST_NAMES[@]}"; do [[ "$_n" =~ $PLAIN_NAME ]] || _odd=$((_odd + 1)); done
[ "$_odd" -eq 0 ] || refuse "$_odd host names that aren't plain names"
unset _odd
# The host's exported names stay shell variables here but are no longer handed to the tools this script runs.
for _n in "${HOST_NAMES[@]}"; do [ "$_n" != PATH ] && export -n "$_n"; done
unset _n
export LC_ALL=C
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
# Security 12940 / 12519 (e): the kernel-keyring probe, the first line of every start that gets past the shell
# guards above (builtins only, so they stay first). What it measures is the HOST's syscall filter, which can change
# under us, so every real start re-proves it and the dry first start reads it; there is no separate one-off. It runs
# before anything reads the passphrase or a secret, under `env -i` (it is handed no host name at all) with a short
# timeout, and it NEVER gates the start: it writes one JSON line to stderr and the script carries on.
#   verdict refused      both add_key calls refused (the guard holds)             l8 PASS
#   verdict landed       an add landed and was removed (the host lets it through)  l8 AMBER → SECURITY
#   verdict probe_failed it ran but timed out, failed, or printed the wrong shape  l8 FINDING
#   verdict absent       no probe beside the entrypoint                            l8 FINDING
# The probe's own line is embedded only when it is exactly the shape keyring-probe.c prints (no value, id or
# description is ever in it), so nothing it prints can forge a second line.
kr_rc=0; kr_out=; kr_verdict=absent
if [ -x "$HERE/keyring-probe" ] && [ ! -L "$HERE/keyring-probe" ]; then
  kr_out="$(/usr/bin/env -i /usr/bin/timeout -k 1 5 "$HERE/keyring-probe" 2> /dev/null)" || kr_rc=$?
  if [ "$kr_rc" -ne 0 ] || ! [[ "$kr_out" =~ ^\{\"uid\":[0-9]+(,\"[a-z_]+\":(\"[A-Za-z_]+\"|true|false))+\}$ ]]; then
    kr_verdict=probe_failed; kr_out=
  elif [[ "$kr_out" == *'"session":"refused"'* && "$kr_out" == *'"user":"refused"'* ]]; then
    kr_verdict=refused
  elif [[ "$kr_out" =~ \"session\":\"(refused|landed)\" && "$kr_out" =~ \"user\":\"(refused|landed)\" && "$kr_out" != *'_removed":false'* ]]; then
    kr_verdict=landed
  else
    kr_verdict=probe_failed
  fi
fi
case "$kr_verdict" in refused) kr_l8=PASS ;; landed) kr_l8=AMBER ;; *) kr_l8=FINDING ;; esac
printf '{"entrypoint":"keyring_probe","verdict":"%s","l8":"%s","exit":%d,"probe":%s}\n' "$kr_verdict" "$kr_l8" "$kr_rc" "${kr_out:-null}" >&2
unset kr_rc kr_out kr_verdict kr_l8
PASSPHRASE_SOURCE=ENKARA_MEDIATOR_BACKEND_PASSPHRASE
PINNED_RUST_LOG='info,affinidi_messaging_mediator::common::config=warn'   # condition 15's pinned filter (line D)
ALLOW=(DATABASE_URL MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE RUST_LOG)          # the record's allow side (L8)
# The record's floor deny names (bus 12048/12079.1), held here too so a deny file that lost one refuses by name.
FLOOR_DENY=(MEDIATOR_ACL_MODE BLOCK_REMOTE_ADMIN_MSGS ENABLE_INTER_MEDIATOR_RELAY PROCESSOR_FORWARDING_EXTERNAL
            GLOBAL_DEFAULT_ACL ADMIN_DID MEDIATOR_SECRETS_BACKEND MEDIATOR_FILE_BACKEND_PASSPHRASE)

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
# (searched where a start could find it: the mediator's own PATH and beside the binary; the image check searches the
# whole filesystem, Railroad 12195.1d)
for d in /usr/local/bin /usr/bin /bin "$(dirname "$bin")"; do [ -e "$d/mediator-setup" ] && refuse "mediator-setup is in the image"; done
# 2(i)
! host_has MEDIATOR_FILE_BACKEND_PASSPHRASE || refuse "MEDIATOR_FILE_BACKEND_PASSPHRASE is set on the host (use the _FILE road only)"
# 12079.2
host_matching '^MEDIATOR_TAG_'
[ "${#MATCH[@]}" -eq 0 ] || refuse "MEDIATOR_TAG_* present on the host: $(say_names "${MATCH[@]}")"
# Security 12491(b): no D-Bus bus handed in. The client keyring linked at the pin (affinidi-tdk-common's default,
# dbus-secret-service-keyring-store) writes over D-Bus; with no bus a reach we missed fails instead of storing.
# The rule, not the list (Security 12640): every bus-address variable libdbus reads refuses by name. Today that is
# the session, system and starter (activation) addresses; a dbus/zbus bump that adds one is caught at the re-pin.
# DBUS_STARTER_BUS_TYPE etc. carry no address and are dropped by env -i like any platform name.
host_matching '^DBUS_(SESSION_BUS|SYSTEM_BUS|STARTER)_ADDRESS$'
[ "${#MATCH[@]}" -eq 0 ] || refuse "D-Bus bus names on the host: $(say_names "${MATCH[@]}")"
# 3: the deny side of the record
while IFS= read -r n; do
  [ -n "$n" ] || continue
  ! host_has "$n" || refuse "$n is set on the host (deny list)"
done < "$denyfile"
# 12144.2: the families the mediator and its clients read, beyond the allow list
host_matching '^(MEDIATOR_|VAULT_|AWS_)'
fam=(); for n in "${MATCH[@]}"; do
  listed=0; for a in "${ALLOW[@]}"; do [ "$n" = "$a" ] && listed=1; done
  [ "$listed" = 1 ] || fam+=("$n")
done; unset listed
[ "${#fam[@]}" -eq 0 ] || refuse "host names in the MEDIATOR_/VAULT_/AWS_ families not on the allow list: $(say_names "${fam[@]}")"
# 16.3(b): the admin credential is absent from the backend's own storage; the store is there and is ours
store="$volume/secrets.json"
[ -L "$store" ] && refuse "the secret store is a symlink"
[ -f "$store" ] || refuse "no secret store on the volume (the backend would create an empty one)"
! grep -qF '"mediator_admin_credential"' "$store" || refuse "mediator_admin_credential is in the secret backend"
! grep -qF '\u' "$store" || refuse "the secret store has a \\u escape (a name could be spelled round the check)"
# 12247.4: the store path the checks read is the one the conf points the mediator at
conf=
_a=("$@"); for ((i = 0; i < ${#_a[@]}; i++)); do
  case "${_a[$i]}" in -c|--config) conf="${_a[$((i + 1))]:-}" ;; --config=*) conf="${_a[$i]#--config=}" ;; esac
done; unset _a i
[ -n "$conf" ] || refuse "no mediator conf (-c/--config) in the mediator's arguments"
[ -L "$conf" ] && refuse "the mediator conf is a symlink"
[ -f "$conf" ] || refuse "the mediator conf is not a regular file"
want_backend="file://$store?encrypt=1"
file_backends="$(grep -E '^[[:space:]]*backend[[:space:]]*=[[:space:]]*"file://' "$conf" | sed -E 's/^[[:space:]]*backend[[:space:]]*=[[:space:]]*"([^"]*)".*$/\1/' || true)"
[ "$(printf '%s' "$file_backends" | grep -c . || true)" = 1 ] || refuse "the mediator conf does not have exactly one file:// backend line"
[ "$file_backends" = "$want_backend" ] || refuse "the mediator conf's backend is not file://<volume>/secrets.json?encrypt=1"
# Security 12672.2: trust_task_verification = "enforce" as a typed literal, exactly once, in [security]. Under `warn`
# (upstream's default, security.rs:450, and the shipped conf) every acceptance failure is logged and let through
# (trust_task_verify.rs:176-187): a write with no proof, so the admin's X25519 key alone could write as the admin, and a
# stale or replayed one. Fail closed: the name (any case) on exactly one non-comment line of the whole file (a
# whole-line `#` comment changes nothing; setup's template names it in one, conf/mediator.toml:283), that line exactly
# `trust_task_verification = "enforce"` (bare key, basic string, nothing after it), under a `[security]` header. A
# quoted or dotted key, an inline table, a `${VAR:…}` expansion, `warn`, a duplicate or a missing line all refuse.
# TRUST_TASK_VERIFICATION on the host refuses by the deny list above (the record's deny side), and the mediator never
# gets one: env -i passes the allow list only. This is the cheap tripwire; the behaviour proof is E1 in the job.
# Security 12795.2: a TOML multi-line string (three double or three single quotes) can carry a line that reads as the
# key while the real key is absent, so the mediator runs its default `warn`. Neither upstream's template
# (conf/mediator.toml, which setup includes at config_writer.rs:45) nor setup's writer uses one at the pin, so any
# line holding either refuses, comment lines included (a line-based check can't tell where a string starts). 16.1's
# conf hash pin closes it for good once that conf exists.
grep -qF '"""' "$conf" && refuse "the mediator conf holds a TOML multi-line string (three double quotes)"
grep -qF "'''" "$conf" && refuse "the mediator conf holds a TOML multi-line string (three single quotes)"
[ "$(grep -vE '^[[:space:]]*#' "$conf" | grep -ci 'trust_task_verification' || true)" = 1 ] || refuse "the mediator conf does not name trust_task_verification on exactly one line"
grep -qE '^[[:space:]]*trust_task_verification[[:space:]]*=[[:space:]]*"enforce"[[:space:]]*$' "$conf" || refuse "the mediator conf's trust_task_verification is not the literal \"enforce\""
ttv_section="$(awk '/^[[:space:]]*#/ { next } /^[[:space:]]*\[/ { s = $0; gsub(/[[:space:]]/, "", s) } /trust_task_verification/ { print s; exit }' "$conf")"
[ "$ttv_section" = "[security]" ] || refuse "the mediator conf's trust_task_verification is not under [security]"
# Security 12892.3: TOML 1.1 (the pin parses with toml 1.1.8+spec-1.1.0) lets an inline table span lines, so
#   [security]
#   x = {
#   trust_task_verification = "enforce"
#   }
# passes every line check above, yet the mediator reads security.x.trust_task_verification, an unknown field it
# ignores (SecurityConfigRaw has no deny_unknown_fields), and runs its default `warn`. Neither upstream's template nor
# setup's writer puts a brace outside a comment at the pin, so any non-comment line holding `{` or `}` refuses (a
# trailing comment on a value line counts: a line-based check can't tell where a comment starts inside a string).
# Placed after the key checks so their own refusals still name themselves. 16.1's conf hash pin closes it for good.
grep -vE '^[[:space:]]*#' "$conf" | grep -q '[{}]' && refuse "the mediator conf holds a brace outside a comment (a TOML inline table can hide the key)"
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
# 12144.3c: what `env -i` drops, names only. From /proc (12180 iv) it is every name the host passed but DATABASE_URL,
# the one passed on, so the line is the complete host-name list binding 3(d)'s daily compare reads.
# (Every name here is plain, 12346.2, so one per line through sort is exact; the count is the array's own length.)
dropped=()
[ "${#HOST_NAMES[@]}" -gt 0 ] && mapfile -t dropped < <(printf '%s\n' "${HOST_NAMES[@]}" | grep -vx 'DATABASE_URL' | sort -u || true)
printf 'entrypoint: env -i dropped %d host names: %s\n' "${#dropped[@]}" "$(say_names "${dropped[@]}")" >&2
exec /usr/bin/env -i "${keep[@]}" "$bin" "$@"
