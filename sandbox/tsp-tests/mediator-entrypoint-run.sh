#!/usr/bin/env bash
# Condition 16.2(c) + 15(iv) on the real mediator (Security 11984 §2(iii)-(iv), 12144): the mediator started THROUGH
# mediator-entrypoint.sh, the way the host will start it, with a host environment shaped like the platform's (its own
# names, a planted extra, the passphrase's host secret holding a random marker). Then:
#   - 16.2(c): /proc/<mediator pid>/environ holds exactly the allow list (names compared; no value printed), and
#     carries neither the passphrase source's name, nor the marker, nor any planted host value;
#   - 15(iv): no stdout / stderr / JSON log line carries the marker passphrase or the Redis password marker;
#   - the entrypoint's one "dropped" start line names the planted extra, by name only;
#   - run D: whether the binary starts without PATH/HOME (if not, once more with --with-path-home, and say so);
#   - one refuse case on the real binary: a deny name on the host stops it before the mediator runs (exit 78);
#   - 12180: a host PATH whose first dir holds a fake `env` (drops -i, execs the rest) changes nothing: the
#     mediator's environ is still exactly the allow list (16.2(c) on the real binary).
# The conf is the upstream TEST-ONLY identity (docker/test/conf), copied to a volume dir with its relative paths made
# absolute, so the working directory stays empty (Q1). Prints names, counts and verdicts only, never a value.
#
# Usage: mediator-entrypoint-run.sh <mediator binary> <conf dir> <redis-server> <env-lists record> <out.json>
set -euo pipefail
set +x
BIN=$(readlink -f "$1"); CONF_SRC=$(readlink -f "$2"); REDIS=$3; RECORD=$(readlink -f "$4"); OUT=$5
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
EP="$HERE/mediator-entrypoint.sh"
FILTER='info,affinidi_messaging_mediator::common::config=warn'
WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/eprun.XXXXXX"); chmod 700 "$WORK"
SHM=$(mktemp -d /dev/shm/eprun.XXXXXX); chmod 700 "$SHM"
cleanup() { [ -n "${MPID:-}" ] && kill "$MPID" 2>/dev/null || true; [ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null || true; rm -rf "$WORK" "$SHM"; }
trap cleanup EXIT

marker() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
PASS_MARK=$(marker); REDIS_MARK=$(marker); EXTRA_MARK=$(marker)
RPORT=$((20000 + RANDOM % 20000)); MPORT=$((40000 + RANDOM % 20000))

"$REDIS" --port "$RPORT" --bind 127.0.0.1 --requirepass "$REDIS_MARK" --save '' --appendonly no --daemonize no \
  >"$WORK/redis.log" 2>&1 & RPID=$!
for _ in $(seq 150); do (exec 3<>/dev/tcp/127.0.0.1/$RPORT) 2>/dev/null && break; sleep 0.1; done

VOL="$WORK/vol"; mkdir -p "$VOL"; cp "$CONF_SRC"/* "$VOL/"
sed -i -e "s#^backend = \"file://.*#backend = \"file://$VOL/secrets.json\"#" \
       -e "s#^functions_file = .*#functions_file = \"$VOL/atm-functions.lua\"#" \
       -e "s#^listen_address = .*#listen_address = \"127.0.0.1:${MPORT}\"#" \
       -e "s#^log_json = .*#log_json = \"true\"#" \
       -e "s#^log_level = .*#log_level = \"info\"#" "$VOL/mediator.toml"
DENY="$WORK/deny.txt"; node "$HERE/mediator-deny-file.mjs" "$RECORD" "$DENY" > /dev/null

# The host: the platform's own names, one planted extra, the two required inputs. Nothing from the runner.
host=(PATH=/usr/local/bin:/usr/bin:/bin HOME="$WORK" PORT=8080 RAILWAY_ENVIRONMENT=test RAILWAY_SERVICE_NAME=mediator
      WPI_HOST_EXTRA="$EXTRA_MARK" DATABASE_URL="redis://:${REDIS_MARK}@127.0.0.1:${RPORT}/"
      ENKARA_MEDIATOR_BACKEND_PASSPHRASE="$PASS_MARK")

# One start: $1 label, then extra entrypoint flags. Leaves results in $WORK/<label>.json.
start() {
  local label=$1; shift
  local ph=false a; for a in "$@"; do [ "$a" = --with-path-home ] && ph=true; done
  local wd="$WORK/work-$label"; mkdir -p "$wd"; chmod 555 "$wd"
  env -i "${host[@]}" /bin/bash -p "$EP" --bin "$BIN" --volume "$VOL" --tmpfs "$SHM" --workdir "$wd" --deny-file "$DENY" "$@" \
    -- --config "$VOL/mediator.toml" >"$WORK/$label.out" 2>"$WORK/$label.err" & MPID=$!
  local started=false
  for _ in $(seq 150); do
    kill -0 "$MPID" 2>/dev/null || break
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${MPORT}/mediator/v1/healthchecker"; then started=true; break; fi
    sleep 0.2
  done
  local names='[]' only_allow=false source_name=false values=0
  if $started; then
    # 16.2(c): the running mediator's own environment. Names compared; values only counted against the markers.
    names=$(tr '\0' '\n' < "/proc/$MPID/environ" | cut -d= -f1 | LC_ALL=C sort | node -e 'console.log(JSON.stringify(require("fs").readFileSync(0,"utf8").split("\n").filter(Boolean)))')
    only_allow=$(node -e 'const n=JSON.parse(process.argv[1]); const a=JSON.parse(require("fs").readFileSync(process.argv[2],"utf8")).allow; const extra=JSON.parse(process.argv[3]); const want=[...a,...extra].sort(); console.log(JSON.stringify(n)===JSON.stringify(want))' "$names" "$RECORD" "$( $ph && echo '["HOME","PATH"]' || echo '[]')")
    if tr '\0' '\n' < "/proc/$MPID/environ" | cut -d= -f1 | grep -qx ENKARA_MEDIATOR_BACKEND_PASSPHRASE; then source_name=true; fi
    values=$(tr '\0' '\n' < "/proc/$MPID/environ" | grep -c -F -e "$PASS_MARK" -e "$EXTRA_MARK" || true)
    sleep 1; kill "$MPID" 2>/dev/null || true
  fi
  local code=0; wait "$MPID" 2>/dev/null || code=$?; MPID=
  local pass_lines redis_lines extra_lines dropped_line=false
  pass_lines=$(cat "$WORK/$label.out" "$WORK/$label.err" | grep -c -F "$PASS_MARK" || true)
  redis_lines=$(cat "$WORK/$label.out" "$WORK/$label.err" | grep -c -F "$REDIS_MARK" || true)
  extra_lines=$(cat "$WORK/$label.out" "$WORK/$label.err" | grep -c -F "$EXTRA_MARK" || true)
  if grep '^entrypoint: env -i dropped' "$WORK/$label.err" | grep -qw WPI_HOST_EXTRA; then dropped_line=true; fi
  local refusal; refusal=$(grep -o '^refused: [^:]*' "$WORK/$label.err" | head -1 | sed 's/"/'"'"'/g' || true)
  printf '{"label":"%s","started":%s,"exit":%s,"environ_names":%s,"environ_is_allow_list":%s,"passphrase_source_name_in_environ":%s,"environ_values_matching_markers":%s,"lines_with_passphrase_marker":%s,"lines_with_redis_password":%s,"lines_with_planted_value":%s,"dropped_line_names_planted_extra":%s,"refusal":"%s"}\n' \
    "$label" "$started" "$code" "$names" "$only_allow" "$source_name" "$values" "$pass_lines" "$redis_lines" "$extra_lines" "$dropped_line" "$refusal" > "$WORK/$label.json"
  cat "$WORK/$label.json"
}

# 16.3(b) on the real store: upstream's TEST-ONLY secrets.json carries mediator_admin_credential, so the entrypoint
# must refuse it as it comes; then the surgical delete (mediator-store.mjs), and only then the starts below.
start refuse-admin-credential
node "$HERE/mediator-store.mjs" delete-admin "$VOL/secrets.json" > "$WORK/delete-admin.json"
start bare
if ! grep -q '"started":true' "$WORK/bare.json"; then start with-path-home --with-path-home; fi
# 12180: a fake `env` first on the host's PATH. The entrypoint must not reach it (PATH set first, /usr/bin/env -i).
FAKE="$WORK/fakebin"; mkdir -p "$FAKE"
printf '#!/bin/sh\n[ "$1" = -i ] && shift\nexec /usr/bin/env "$@"\n' > "$FAKE/env"; chmod 755 "$FAKE/env"
saved_path=${host[0]}; host[0]="PATH=$FAKE:/usr/local/bin:/usr/bin:/bin"
if grep -q '"started":true' "$WORK/bare.json"; then start fake-env-path; else start fake-env-path --with-path-home; fi
host[0]=$saved_path
# One refuse case on the real binary: a deny name on the host. Expect exit 78, the mediator never up.
host+=(MEDIATOR_ACL_MODE=explicit_deny); start refuse-deny-name; unset 'host[-1]'

node -e '
const fs = require("fs"); const W = process.argv[1];
const rd = (l) => fs.existsSync(`${W}/${l}.json`) ? JSON.parse(fs.readFileSync(`${W}/${l}.json`, "utf8")) : null;
const bare = rd("bare"), ph = rd("with-path-home"), fake = rd("fake-env-path"), ref = rd("refuse-deny-name"), cred = rd("refuse-admin-credential");
const del = JSON.parse(fs.readFileSync(`${W}/delete-admin.json`, "utf8"));
const up = bare.started ? bare : ph;
const clean = (r) => r && r.environ_is_allow_list && !r.passphrase_source_name_in_environ && r.environ_values_matching_markers === 0;
const quiet = (r) => r && r.lines_with_passphrase_marker === 0 && r.lines_with_redis_password === 0 && r.lines_with_planted_value === 0;
const out = {
  what: "16.2(c) + 15(iv): the real mediator through mediator-entrypoint.sh (Security 11984, 12144)",
  rust_log_filter: process.argv[3],
  run_d_needs_path_home: !bare.started && !!(ph && ph.started),
  runs: [cred, bare, ph, fake, ref].filter(Boolean),
  surgical_delete: del,
  verdicts: {
    starts_through_entrypoint: !!(up && up.started),
    environ_16_2c: clean(up) ? "PASS" : "FAIL",
    marker_15_iv: [cred, bare, ph, fake].filter(Boolean).every(quiet) && quiet(ref) ? "PASS" : "FAIL",
    fake_env_on_host_path_12180: fake && fake.started && clean(fake) ? "PASS" : "FAIL",
    dropped_line_names_only: !!(up && up.dropped_line_names_planted_extra) && quiet(up) ? "PASS" : "FAIL",
    refuses_admin_credential_16_3b: cred && !cred.started && cred.exit === 78 && /mediator_admin_credential/.test(cred.refusal) ? "PASS" : "FAIL",
    surgical_delete: del.had_admin_credential && !del.admin_credential_present && del.others_unchanged && del.entries_after === del.entries_before - 1 ? "PASS" : "FAIL",
    refuses_deny_name: ref && !ref.started && ref.exit === 78 && /MEDIATOR_ACL_MODE/.test(ref.refusal) ? "PASS" : "FAIL",
  },
};
fs.writeFileSync(process.argv[2], JSON.stringify(out, null, 2) + "\n");
console.log(JSON.stringify(out.verdicts));
process.exit(out.verdicts.starts_through_entrypoint && Object.values(out.verdicts).every((v) => v === true || v === "PASS") ? 0 : 1);
' "$WORK" "$OUT" "$FILTER"
