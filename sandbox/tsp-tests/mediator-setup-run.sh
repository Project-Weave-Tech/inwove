#!/usr/bin/env bash
# The setup job's backend half, on the lean mediator (Security 11984 §2 (v), 16.3, Railroad note ii; WPI-BUILD 12115):
#   1. `mediator-setup --from <recipe>` (built --no-default-features: the file backends only) makes a fresh identity
#      into `file://<volume>/secrets.json?encrypt=1`, the passphrase reaching it only by
#      MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE on tmpfs (setup's own environment; never the mediator's).
#   2. The store is the encrypted shape, our reader opens it with the passphrase (cross-check of mediator-store.mjs
#      against the Rust writer) and not with a wrong one, and it holds mediator_admin_credential (the falsifier: the
#      16.3(b) check must SEE it before the delete).
#   3. The entrypoint refuses to start the mediator on that store (16.3(b), exit 78).
#   4. The surgical delete (mediator-store.mjs delete-admin): only that entry goes, every other entry byte-identical
#      and still opening.
#   5. Green case: the real mediator through the entrypoint opens the encrypted store with the passphrase and answers;
#      /proc/<pid>/environ is the allow list.
#   6. (v) rotation in place (mediator-store.mjs rekey, same entries so the DID is kept): the old passphrase no longer
#      opens the store; the mediator through the entrypoint with the OLD passphrase does not start; with the NEW one
#      it starts and answers.
#   7. No stdout/stderr line of setup or any start carries either passphrase or the Redis password (15(iv)).
# The conf is setup's own output with its relative paths made absolute; it is NOT the pinned production conf
# (16.1's hash pin and four-value check belong to that conf, which isn't written yet). Not yet here: the DIDComm
# admin calls and the read-back-is-truth test (they come with the DIDComm admin path).
# Prints names, counts and verdicts only, never a value.
#
# Usage: mediator-setup-run.sh <mediator binary> <mediator-setup binary> <redis-server> <env-lists record> <out.json>
set -euo pipefail
set +x
BIN=$(readlink -f "$1"); SETUP=$(readlink -f "$2"); REDIS=$3; RECORD=$(readlink -f "$4"); OUT=$5
HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
EP="$HERE/mediator-entrypoint.sh"; STORE="$HERE/mediator-store.mjs"
WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/setuprun.XXXXXX"); chmod 700 "$WORK"
SHM=$(mktemp -d /dev/shm/setuprun.XXXXXX); chmod 700 "$SHM"
cleanup() { [ -n "${MPID:-}" ] && kill "$MPID" 2>/dev/null || true; [ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null || true; rm -rf "$WORK" "$SHM"; }
trap cleanup EXIT

marker() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
P1=$(marker); P2=$(marker); REDIS_MARK=$(marker)
RPORT=$((20000 + RANDOM % 20000)); MPORT=$((40000 + RANDOM % 20000))
( umask 077; printf '%s' "$P1" > "$SHM/p1"; printf '%s' "$P2" > "$SHM/p2"; printf 'wrong-%s' "$P1" > "$SHM/pwrong" )

"$REDIS" --port "$RPORT" --bind 127.0.0.1 --requirepass "$REDIS_MARK" --save '' --appendonly no --daemonize no \
  >"$WORK/redis.log" 2>&1 & RPID=$!
for _ in $(seq 150); do (exec 3<>/dev/tcp/127.0.0.1/$RPORT) 2>/dev/null && break; sleep 0.1; done

VOL="$WORK/vol"; mkdir -p "$VOL"; chmod 700 "$VOL"
cat > "$WORK/recipe.toml" <<EOF
# TEST-ONLY recipe for the setup job's backend half: every key it makes dies with the job.
[deployment]
type = "container"
protocols = ["didcomm", "tsp"]
use_vta = false
[identity]
did_method = "peer"
public_url = "http://127.0.0.1:${MPORT}"
[secrets]
storage = "file://${VOL}/secrets.json?encrypt=1"
[security]
ssl = "none"
admin = "generate"
network_mode = "open"
cors = "none"
[database]
url = "redis://127.0.0.1:${RPORT}/"
[storage]
backend = "redis"
[output]
config_path = "${VOL}/mediator.toml"
listen_address = "127.0.0.1:${MPORT}"
[install]
enabled = false
EOF

# 1. setup, in its own environment: the passphrase by _FILE only
setup_code=0
( cd "$VOL" && env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$WORK" MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE="$SHM/p1" \
    "$SETUP" --from "$WORK/recipe.toml" --non-interactive ) >"$WORK/setup.out" 2>"$WORK/setup.err" || setup_code=$?
# relative paths in setup's conf made absolute, so the working directory stays empty (Q1); JSON logs for the marker scan
if [ -f "$VOL/mediator.toml" ]; then
  sed -i -e "s#^functions_file = \"\\(conf/\\)\\?#functions_file = \"$VOL/#" \
         -e "s#^log_json = .*#log_json = \"true\"#" -e "s#^log_level = .*#log_level = \"info\"#" "$VOL/mediator.toml"
fi
backend_line=$(grep -E '^backend = "file://' "$VOL/mediator.toml" 2>/dev/null | head -1 | sed "s#$VOL#<volume>#" | tr -d '"' || true)

# 2. the store as setup left it
names_before=$(node "$STORE" names "$VOL/secrets.json" 2>/dev/null || echo '{}')
opens_p1=$(node "$STORE" opens "$VOL/secrets.json" "$SHM/p1" >/dev/null 2>&1 && echo true || echo false)
opens_wrong=$(node "$STORE" opens "$VOL/secrets.json" "$SHM/pwrong" >/dev/null 2>&1 && echo true || echo false)

DENY="$WORK/deny.txt"; node "$HERE/mediator-deny-file.mjs" "$RECORD" "$DENY" > /dev/null
# One start through the entrypoint: $1 label, $2 the passphrase file to give the host secret. Results → $WORK/<label>.json
start() {
  local label=$1 pf=$2
  local wd="$WORK/work-$label"; mkdir -p "$wd"; chmod 555 "$wd"
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$WORK" PORT=8080 RAILWAY_ENVIRONMENT=test \
    DATABASE_URL="redis://:${REDIS_MARK}@127.0.0.1:${RPORT}/" ENKARA_MEDIATOR_BACKEND_PASSPHRASE="$(cat "$pf")" \
    bash "$EP" --bin "$BIN" --volume "$VOL" --tmpfs "$SHM" --workdir "$wd" --deny-file "$DENY" \
    -- --config "$VOL/mediator.toml" >"$WORK/$label.out" 2>"$WORK/$label.err" & MPID=$!
  local started=false
  for _ in $(seq 200); do
    kill -0 "$MPID" 2>/dev/null || break
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${MPORT}/mediator/v1/healthchecker"; then started=true; break; fi
    sleep 0.2
  done
  local names='[]' only_allow=false
  if $started; then
    names=$(tr '\0' '\n' < "/proc/$MPID/environ" | cut -d= -f1 | LC_ALL=C sort | node -e 'console.log(JSON.stringify(require("fs").readFileSync(0,"utf8").split("\n").filter(Boolean)))')
    only_allow=$(node -e 'const n=JSON.parse(process.argv[1]); const a=JSON.parse(require("fs").readFileSync(process.argv[2],"utf8")).allow; console.log(JSON.stringify(n)===JSON.stringify([...a].sort()))' "$names" "$RECORD")
    sleep 1; kill "$MPID" 2>/dev/null || true
  fi
  local code=0; wait "$MPID" 2>/dev/null || code=$?; MPID=
  local refusal; refusal=$(grep -o '^refused: [^:]*' "$WORK/$label.err" | head -1 | sed 's/"/'"'"'/g' || true)
  # the mediator's own reason when it won't open the store: one fixed phrase searched for, never the line printed
  local wrong_pass=false; grep -qiE 'AES-GCM open failed|different passphrase' "$WORK/$label.out" "$WORK/$label.err" && wrong_pass=true
  printf '{"label":"%s","started":%s,"exit":%s,"environ_names":%s,"environ_is_allow_list":%s,"refusal":"%s","mediator_said_wrong_passphrase":%s}\n' \
    "$label" "$started" "$code" "$names" "$only_allow" "$refusal" "$wrong_pass" > "$WORK/$label.json"
  cat "$WORK/$label.json"
}

# 3. refuse while the credential is in the store; 4. the surgical delete; 5. green on the encrypted store
start refuse-admin-credential "$SHM/p1"
node "$STORE" delete-admin "$VOL/secrets.json" "$SHM/p1" > "$WORK/delete-admin.json" 2>"$WORK/delete-admin.err" || true
start green-encrypted "$SHM/p1"
# 6. (v) rotation in place, then old refused by the mediator, new starts
node "$STORE" rekey "$VOL/secrets.json" "$SHM/p1" "$SHM/p2" > "$WORK/rekey.json" 2>"$WORK/rekey.err" || true
start rotated-old-passphrase "$SHM/p1"
start rotated-new-passphrase "$SHM/p2"
names_after=$(node "$STORE" names "$VOL/secrets.json" 2>/dev/null || echo '{}')

# 7. no line anywhere carries either passphrase or the Redis password
leaks=$(cat "$WORK"/*.out "$WORK"/*.err | grep -c -F -e "$P1" -e "$P2" -e "$REDIS_MARK" || true)

node -e '
const fs = require("fs"); const [W, out, setupCode, backend, nb, na, o1, ow, leaks] = process.argv.slice(1);
const rd = (f) => { try { return JSON.parse(fs.readFileSync(`${W}/${f}`, "utf8")); } catch { return null; } };
const before = JSON.parse(nb), after = JSON.parse(na);
const cred = rd("refuse-admin-credential.json"), green = rd("green-encrypted.json"), del = rd("delete-admin.json");
const rk = rd("rekey.json"), old = rd("rotated-old-passphrase.json"), neu = rd("rotated-new-passphrase.json");
const v = {
  setup_ran: setupCode === "0" ? "PASS" : `FAIL (exit ${setupCode})`,
  store_is_encrypted_with_admin_credential: before.shape === "encrypted" && before.admin_credential_present ? "PASS" : "FAIL",
  our_reader_opens_rust_store: o1 === "true" && ow === "false" ? "PASS" : "FAIL",
  refuses_admin_credential_16_3b: cred && !cred.started && cred.exit === 78 && /mediator_admin_credential/.test(cred.refusal) ? "PASS" : "FAIL",
  surgical_delete: del && del.had_admin_credential && !del.admin_credential_present && del.others_unchanged && del.still_opens && del.entries_after === del.entries_before - 1 ? "PASS" : "FAIL",
  green_encrypted_open: green && green.started && green.environ_is_allow_list ? "PASS" : "FAIL",
  rotation_v_store: rk && rk.values_unchanged && rk.salt_changed && !rk.old_opens && rk.new_opens ? "PASS" : "FAIL",
  rotation_v_old_refused_by_mediator: old && !old.started && old.exit !== 0 ? "PASS" : "FAIL",
  rotation_v_new_starts: neu && neu.started && neu.environ_is_allow_list ? "PASS" : "FAIL",
  marker_15_iv: leaks === "0" ? "PASS" : `FAIL (${leaks} lines)`,
};
const res = {
  what: "setup job, backend half: mediator-setup → ?encrypt=1, 16.3(b) refuse, surgical delete, green on the encrypted store, (v) rotation (Security 11984)",
  conf_backend_line: backend, entries_before: before.entries || null, entries_after: after.entries || null,
  surgical_delete: del, rekey: rk, runs: [cred, green, old, neu].filter(Boolean), verdicts: v,
  not_covered: ["the pinned production conf (16.1 hash + four values)", "DIDComm admin calls + read-back-is-truth"],
};
fs.writeFileSync(out, JSON.stringify(res, null, 2) + "\n");
console.log(JSON.stringify(v));
process.exit(Object.values(v).every((x) => x === "PASS") ? 0 : 1);
' "$WORK" "$OUT" "$setup_code" "$backend_line" "$names_before" "$names_after" "$opens_p1" "$opens_wrong" "$leaks"
