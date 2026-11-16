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
#   7. No stdout/stderr line of setup or any start carries either passphrase or the Redis password (15(iv)), nor
#      any value of the admin credential that setup made (Security 12247.2: on the real host setup's stdout goes to
#      Railway's log). The markers are the credential's own string values, read by `admin-out` to tmpfs before the
#      delete; the scan must first find them in the credential itself (a scan that can't hit isn't evidence).
#   9. Every private key of the admin DID, as one admin key (Security 12582.2(b)/(c)): admin-key-markers.mjs lists
#      the admin DID document's keys (verificationMethod + every relationship), matches each public key to a private
#      key the credential yields (the X25519 keyAgreement key is derived from the Ed25519 seed; none lives elsewhere),
#      and writes markers for both in every encoding (multibase ± prefix, JWK d, base64, hex), plus the values of
#      setup's own `admin-monitor.json` (the admin's secret beside the conf, admin_monitor_profile.rs:58-80). The scan
#      counts only after it hits a planted copy of each. That file joins the surgical delete; at the end no file on
#      the volume and no log line carries any marker, and the file is gone.
#   8. admin-out custody (Security 12247.3): its <out> only under this job's /dev/shm dir; a results/ path is refused
#      (tried, must exit 5); the file is removed right after the admin calls (none yet: they come with the DIDComm
#      admin client) and before delete-admin; the job fails if it still exists at the end, and the artifact dir is
#      listed by name for it. Condition 8 (Railroad 12701.1): the admin seed has one copy outside his hands, the
#      encrypted store, and only until the surgical delete.
#  10. Setup's own output stays off every log (Security 12672.3; finding 4: mediator-setup echoes the admin private key
#      to stdout, main.rs:1874-1879 / print_admin_key_echo :1917-1934). Setup runs with stdout AND stderr redirected to
#      one file in this job's /dev/shm dir (0600, this user, never the volume, never a link), stdin /dev/null, under
#      `setsid -w` so it has no controlling terminal (no tty for the OSC 52 clipboard path in clipboard.rs); no tee, no
#      pipe. The marker scan must first HIT that file (>= 1 line; today exactly 1), so a scan that can't see the echo
#      can't pass. Then 0 marker lines in everything that reaches a log or an artifact: this script's own stdout and
#      stderr (held in a file, scanned, and replayed only if clean, else withheld with a count), every start's output,
#      and every file in the results (artifact) dir. From setup's file only counts and line numbers are printed, never
#      a line's text; it is deleted with admin-monitor.json in the surgical delete, and the absence check at the end
#      covers admin-out, admin-monitor.json and setup.out. The results dir is also listed by name for setup.out,
#      setup.err and *admin-monitor*.
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
marker() { head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
P1=$(marker); P2=$(marker); REDIS_MARK=$(marker)
MARKS="$SHM/admin-markers"
# 10 (Security 12672.3): everything this script prints goes to a file first; at exit it is scanned for the passphrases,
# the Redis password and every admin marker, and replayed to the real stdout only when 0 lines hit.
JOBLOG="$WORK/job.log"
exec 3>&1 4>&2 >"$JOBLOG" 2>&1
job_log_hits() {
  local n=0 m=0
  [ -f "$JOBLOG" ] || { echo 0; return; }
  n=$(grep -c -F -e "$P1" -e "$P2" -e "$REDIS_MARK" "$JOBLOG" || true)
  [ -s "$MARKS" ] && m=$(grep -c -F -f "$MARKS" "$JOBLOG" || true)
  echo $(( ${n:-0} + ${m:-0} ))
}
cleanup() {
  local code=$?
  [ -n "${MPID:-}" ] && kill "$MPID" 2>/dev/null || true; [ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null || true
  local hits; hits=$(job_log_hits)
  if [ "$hits" = 0 ]; then cat "$JOBLOG" >&3 2>/dev/null || true
  else echo "setup-run: this step's own output withheld: $hits lines carry a marker (Security 12672.3)" >&4; code=1; fi
  exec 1>&3 2>&4
  rm -rf "$WORK" "$SHM"
  exit "$code"
}
trap cleanup EXIT
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

# 1. setup, in its own environment: the passphrase by _FILE only; its stdout + stderr to one tmpfs file (10)
SETUP_OUT="$SHM/setup.out"
setup_code=0
( umask 077; cd "$VOL" && exec setsid -w env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$WORK" MEDIATOR_FILE_BACKEND_PASSPHRASE_FILE="$SHM/p1" \
    "$SETUP" --from "$WORK/recipe.toml" --non-interactive < /dev/null > "$SETUP_OUT" 2>&1 ) || setup_code=$?
setup_out_shape=$( { [ -f "$SETUP_OUT" ] && [ ! -L "$SETUP_OUT" ] && [ "$(stat -c %a "$SETUP_OUT")" = 600 ] && [ "$(stat -c %u "$SETUP_OUT")" = "$(id -u)" ] \
  && [ "$(stat -f -c %T "$SETUP_OUT")" = tmpfs ] && [ "$(stat -c %d "$SETUP_OUT")" != "$(stat -c %d "$VOL")" ]; } && echo ok || echo bad)
# relative paths in setup's conf made absolute, so the working directory stays empty (Q1); JSON logs for the marker scan
if [ -f "$VOL/mediator.toml" ]; then
  sed -i -e "s#^functions_file = \"\\(conf/\\)\\?#functions_file = \"$VOL/#" \
         -e "s#^log_json = .*#log_json = \"true\"#" -e "s#^log_level = .*#log_level = \"info\"#" "$VOL/mediator.toml"
fi
# names only: what setup left on the volume (admin-monitor.json is the admin's secret, Security 12582.2(c))
vol_names_after_setup=$(cd "$VOL" && find . -type f -printf '%P\n' 2>/dev/null | LC_ALL=C sort | node -e 'console.log(JSON.stringify(require("fs").readFileSync(0,"utf8").split("\n").filter(Boolean)))')
admin_profile_after_setup=$([ -e "$VOL/admin-monitor.json" ] && echo present || echo absent)
backend_line=$(grep -E '^backend = "file://' "$VOL/mediator.toml" 2>/dev/null | head -1 | sed "s#$VOL#<volume>#" | tr -d '"' || true)

# 2. the store as setup left it
names_before=$(node "$STORE" names "$VOL/secrets.json" 2>/dev/null || echo '{}')
opens_p1=$(node "$STORE" opens "$VOL/secrets.json" "$SHM/p1" >/dev/null 2>&1 && echo true || echo false)
opens_wrong=$(node "$STORE" opens "$VOL/secrets.json" "$SHM/pwrong" >/dev/null 2>&1 && echo true || echo false)

# 8. admin-out to tmpfs, the markers from it, then the file goes before the delete (12247.2/.3)
RESDIR=$(dirname "$(readlink -f "$OUT" 2>/dev/null || echo "$OUT")"); mkdir -p "$RESDIR"
ao_results_code=0; node "$STORE" admin-out "$VOL/secrets.json" "$SHM/p1" "$RESDIR/admin.json" >/dev/null 2>&1 || ao_results_code=$?
ADMIN_OUT="$SHM/admin.json"
ao_code=0; node "$STORE" admin-out "$VOL/secrets.json" "$SHM/p1" "$ADMIN_OUT" > "$WORK/admin-out.json" 2>"$WORK/admin-out.err" || ao_code=$?
# Every private key of the admin DID in every encoding, and the profile's own values (12582.2(b)); then a planted
# copy of each must be hit, so a scan that can't hit isn't evidence.
PLANT="$SHM/planted"
( umask 077; node -e '
// 12247.2 as before: the private key value (AdminCredential.private_key_multibase, well_known.rs:111 at 34bbdea4), it
// without its multibase prefix, and the credential JSON itself. Not the DID: that is public and may be logged.
const fs = require("fs"); const out = [];
let raw = ""; try { raw = fs.readFileSync(process.argv[1], "utf8"); } catch {}
// admin-out writes the sealed entry, Envelope { version, kind, data, created_at } (envelope.rs:25-36): the key is
// data.private_key_multibase. (Before w-1116-0433 this read the top level only, so the key value itself was never a
// marker; only the whole JSON line was.)
try { const j = JSON.parse(raw); const c = j && j.kind === "admin-credential" && j.data ? j.data : j; const k = String(c.private_key_multibase || ""); if (k.length >= 16) out.push(k, k.slice(1)); } catch {}
const line = raw.trim(); if (line.length >= 16 && !line.includes("\n")) out.push(line);
fs.writeFileSync(process.argv[2], [...new Set(out)].join("\n") + (out.length ? "\n" : ""));
' "$ADMIN_OUT" "$MARKS" )
# 12582.2: every private key of the admin DID, added to the same marker file.
keys_summary=$( (umask 077; node "$HERE/admin-key-markers.mjs" markers "$ADMIN_OUT" "$MARKS.keys" "$PLANT" "$VOL/admin-monitor.json") 2>/dev/null || true)
[ -n "$keys_summary" ] || keys_summary='{"ok":false,"error":"no-output"}'
[ -s "$MARKS.keys" ] && { cat "$MARKS.keys" >> "$MARKS"; rm -f -- "$MARKS.keys"; }
planted_n=$(find "$PLANT" -type f 2>/dev/null | grep -c . || true)
planted_hit=$( [ -s "$MARKS" ] && { grep -l -F -f "$MARKS" "$PLANT"/* 2>/dev/null | grep -c . || true; } || echo 0)
vol_files_hit_before=$( [ -s "$MARKS" ] && { grep -r -l -F -f "$MARKS" "$VOL" 2>/dev/null | grep -c . || true; } || echo 0)
rm -rf -- "$PLANT"
admin_marks=$(grep -c . "$MARKS" || true)
admin_self_hits=$(grep -c -F -f "$MARKS" "$ADMIN_OUT" 2>/dev/null || true)
# 10: the scan must first hit setup's own file (the key echo). Counts and line numbers only; the text never leaves it.
setup_out_lines=$(grep -c '' "$SETUP_OUT" 2>/dev/null || true)
setup_out_hits=0; setup_out_hit_lines=''
if [ -s "$MARKS" ] && [ -f "$SETUP_OUT" ]; then
  setup_out_hits=$(grep -c -F -f "$MARKS" "$SETUP_OUT" || true)
  setup_out_hit_lines=$(grep -n -F -f "$MARKS" "$SETUP_OUT" | cut -d: -f1 | paste -sd, - || true)
fi
# (the DIDComm admin calls go here, reading $ADMIN_OUT)
rm -f -- "$ADMIN_OUT"; admin_out_removed_before_delete=$([ -e "$ADMIN_OUT" ] && echo false || echo true)

DENY="$WORK/deny.txt"; node "$HERE/mediator-deny-file.mjs" "$RECORD" "$DENY" > /dev/null
# One start through the entrypoint: $1 label, $2 the passphrase file to give the host secret. Results → $WORK/<label>.json
start() {
  local label=$1 pf=$2
  local wd="$WORK/work-$label"; mkdir -p "$wd"; chmod 555 "$wd"
  env -i PATH=/usr/local/bin:/usr/bin:/bin HOME="$WORK" PORT=8080 RAILWAY_ENVIRONMENT=test \
    DATABASE_URL="redis://:${REDIS_MARK}@127.0.0.1:${RPORT}/" ENKARA_MEDIATOR_BACKEND_PASSPHRASE="$(cat "$pf")" \
    /bin/bash -p "$EP" --bin "$BIN" --volume "$VOL" --tmpfs "$SHM" --workdir "$wd" --deny-file "$DENY" \
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
rm -f -- "$VOL/admin-monitor.json" "$SETUP_OUT"   # the second and third places the admin key sits (12582.2(c), 12672.3): gone with the surgical delete
start green-encrypted "$SHM/p1"
# 6. (v) rotation in place, then old refused by the mediator, new starts
# Security 12024.1: rekey runs only under exactly its allow list (what the rekey entrypoint's `env -i` hands it).
RK_HOME="$(mktemp -d)"; chmod 0555 "$RK_HOME"
/usr/bin/env -i REKEY_STORE="$VOL/secrets.json" REKEY_OLD_PASSPHRASE_FILE="$SHM/p1" REKEY_NEW_PASSPHRASE_FILE="$SHM/p2" \
  PATH=/usr/local/bin:/usr/bin:/bin HOME="$RK_HOME" "$(command -v node)" "$STORE" rekey "$VOL/secrets.json" "$SHM/p1" "$SHM/p2" > "$WORK/rekey.json" 2>"$WORK/rekey.err" || true
rmdir "$RK_HOME" 2> /dev/null || true
start rotated-old-passphrase "$SHM/p1"
start rotated-new-passphrase "$SHM/p2"
names_after=$(node "$STORE" names "$VOL/secrets.json" 2>/dev/null || echo '{}')

# 7. no line anywhere carries either passphrase or the Redis password
leaks=$(cat "$WORK"/*.out "$WORK"/*.err | grep -c -F -e "$P1" -e "$P2" -e "$REDIS_MARK" || true)
admin_leaks=$( [ "${admin_marks:-0}" -gt 0 ] && { cat "$WORK"/*.out "$WORK"/*.err | grep -c -F -f "$MARKS" || true; } || echo 0)
admin_out_at_end=$([ -e "$ADMIN_OUT" ] && echo present || echo absent)
vol_files_hit_after=$( [ -s "$MARKS" ] && { grep -r -l -F -f "$MARKS" "$VOL" 2>/dev/null | grep -c . || true; } || echo 0)
admin_profile_at_end=$([ -e "$VOL/admin-monitor.json" ] && echo present || echo absent)
results_named_admin=$(find "$RESDIR" \( -name 'admin.json' -o -name 'admin-out*' -o -name 'admin-markers' -o -name '*admin_credential*' -o -name 'setup.out' -o -name 'setup.err' -o -name '*admin-monitor*' \) 2>/dev/null | grep -c . || true)
# 10: setup's file is gone, and nothing that reaches a log or an artifact carries a marker
setup_out_at_end=$([ -e "$SETUP_OUT" ] && echo present || echo absent)
artifact_files_hit=$( [ -s "$MARKS" ] && { grep -r -l -F -f "$MARKS" "$RESDIR" 2>/dev/null | grep -c . || true; } || echo 0)
artifact_files_hit_pass=$(grep -r -l -F -e "$P1" -e "$P2" -e "$REDIS_MARK" "$RESDIR" 2>/dev/null | grep -c . || true)
joblog_hits_before_verdict=$(job_log_hits)

rc=0
node -e '
const fs = require("fs"); const [W, out, setupCode, backend, nb, na, o1, ow, leaks, aoRes, ao, marks, selfHits, removed, aLeaks, atEnd, resNamed, ksum, plN, plHit, volBefore, volAfter, profSetup, profEnd, volNames, soShape, soLines, soHits, soHitLines, soEnd, artHit, artHitPass, jobHits] = process.argv.slice(1);
let ks = {}; try { ks = JSON.parse(ksum); } catch {}
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
  marker_admin_credential_12247_2: ao === "0" && Number(marks) > 0 && Number(selfHits) > 0 && aLeaks === "0" ? "PASS" : `FAIL (admin-out ${ao}, ${marks} markers, self ${selfHits}, ${aLeaks} lines)`,
  admin_keys_every_private_key_12582: ks.ok && ks.every_document_key_held && ["ed25519", "x25519"].every((k) => (ks.kinds || []).includes(k)) && Number(plN) > 0 && plHit === plN && volAfter === "0" && aLeaks === "0" && profEnd === "absent" ? "PASS" : `FAIL (keys ok ${!!ks.ok}${ks.ok ? "" : ` error ${ks.error || "none"} ${JSON.stringify(ks.shape || {})}`}, did ${ks.did_method || "?"}, all held ${!!ks.every_document_key_held}, kinds ${(ks.kinds || []).join("+") || "none"}, planted ${plHit}/${plN}, volume files hit at end ${volAfter}, profile at end ${profEnd})`,
  setup_output_kept_off_logs_12672_3: soShape === "ok" && Number(soHits) >= 1 && aLeaks === "0" && artHit === "0" && artHitPass === "0" && jobHits === "0" && soEnd === "absent" && resNamed === "0" && atEnd === "absent" && profEnd === "absent" ? "PASS" : `FAIL (setup file ${soShape}, scan hit it ${soHits}, starts ${aLeaks}, artifact files ${artHit}+${artHitPass}, this step log ${jobHits}, setup file at end ${soEnd}, named in results ${resNamed})`,
  admin_out_custody_12247_3: aoRes === "5" && removed === "true" && atEnd === "absent" && resNamed === "0" ? "PASS" : `FAIL (results path ${aoRes}, removed ${removed}, at end ${atEnd}, ${resNamed} named in results)`,
};
const res = {
  what: "setup job, backend half: mediator-setup → ?encrypt=1, 16.3(b) refuse, surgical delete, green on the encrypted store, (v) rotation (Security 11984)",
  conf_backend_line: backend, entries_before: before.entries || null, entries_after: after.entries || null,
  admin_out: rd("admin-out.json"), admin_credential_markers: Number(marks),
  admin_keys: { ok: !!ks.ok, error: ks.ok ? null : (ks.error || null), error_shape: ks.ok ? null : (ks.shape || null), did_method: ks.did_method || null, keys: (ks.keys || []).map((k) => ({ kind: k.kind, held_by_credential: k.held_by_credential, derived: k.derived })), every_document_key_held: !!ks.every_document_key_held, markers: ks.markers || 0, planted: Number(plN), planted_hit: Number(plHit), profile_values: ks.profile_values || 0, volume_files_hit_before_delete: Number(volBefore), volume_files_hit_at_end: Number(volAfter), admin_monitor_after_setup: profSetup, admin_monitor_at_end: profEnd, volume_names_after_setup: JSON.parse(volNames || "[]") },
  setup_output: { file: soShape, lines: Number(soLines), marker_lines: Number(soHits), marker_line_numbers: soHitLines ? soHitLines.split(",").map(Number) : [], at_end: soEnd, starts_marker_lines: Number(aLeaks), artifact_files_with_a_marker: Number(artHit) + Number(artHitPass), step_log_marker_lines_before_verdict: Number(jobHits) },
  surgical_delete: del, rekey: rk, runs: [cred, green, old, neu].filter(Boolean), verdicts: v,
  not_covered: ["the pinned production conf (16.1 hash + four values)", "DIDComm admin calls + read-back-is-truth"],
};
fs.writeFileSync(out, JSON.stringify(res, null, 2) + "\n");
console.log(JSON.stringify(v));
process.exit(Object.values(v).every((x) => x === "PASS") ? 0 : 1);
' "$WORK" "$OUT" "$setup_code" "$backend_line" "$names_before" "$names_after" "$opens_p1" "$opens_wrong" "$leaks" \
  "$ao_results_code" "$ao_code" "${admin_marks:-0}" "${admin_self_hits:-0}" "$admin_out_removed_before_delete" "$admin_leaks" "$admin_out_at_end" "$results_named_admin" \
  "$keys_summary" "${planted_n:-0}" "${planted_hit:-0}" "${vol_files_hit_before:-0}" "${vol_files_hit_after:-0}" "$admin_profile_after_setup" "$admin_profile_at_end" "$vol_names_after_setup" \
  "$setup_out_shape" "${setup_out_lines:-0}" "${setup_out_hits:-0}" "$setup_out_hit_lines" "$setup_out_at_end" "${artifact_files_hit:-0}" "${artifact_files_hit_pass:-0}" "$joblog_hits_before_verdict" || rc=$?
# 10: the results file this step just wrote is an artifact too; a marker in it withholds it whole
if [ -f "$OUT" ] && { { [ -s "$MARKS" ] && grep -q -F -f "$MARKS" "$OUT"; } || grep -q -F -e "$P1" -e "$P2" -e "$REDIS_MARK" "$OUT"; }; then
  printf '{"error":"the results file carried a marker; withheld (Security 12672.3)"}\n' > "$OUT"; rc=1
fi
exit "$rc"
