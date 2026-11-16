#!/bin/bash
# The Dockerfile batch (Security 12422 e + the rekey image, 12491 b's image half, 12519 e, 12195.1 d): builds the
# service image and the one-off rekey image from the same commit, on the runner's Docker, and judges both. TEST
# BUILD: nothing is pushed to a registry, nothing deployed; every store and passphrase here is made up and dies with
# the job. Prints names, codes and verdicts only.
#
# Usage: mediator-images.sh <lean mediator binary> <out json>
# Writes beside <out>: service-image.json, rekey-image.json, and <out> (the summary; exit 1 if any line is FAIL).
#   service: the image check (mediator-image-check.mjs service), the binary's libraries all resolve in the image,
#            `mediator --help` runs in it, and the keyring probe as the service user: refused both = PASS,
#            landed = AMBER (the host's syscall filter, never red), anything else FAIL; and (Security 12940) the
#            image's own entrypoint, started bare, writes that probe as its first stderr line and still refuses (78).
#   rekey:   the image check (mediator-image-check.mjs rekey) on the shipped tool; (Security 11869.4) the base diff
#            against the pinned base (mediator-base-diff.mjs, added set rekey-added.json), whose base side (Security
#            12327) is built from the pinned layers (mediator-base-layers.mjs) with the local pull cross-checked
#            against it; in the image, with no network and
#            a read-only root: `rekey` refuses while mediator_admin_credential is in the store, the removed
#            subcommands answer "usage" (exit 2), and after the credential is gone `rekey` re-seals (old no longer
#            opens, new does, same entries).
set -uo pipefail
BIN="$1"; OUT="$2"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ODIR="$(dirname "$OUT")"; mkdir -p "$ODIR"
W="$(mktemp -d "${RUNNER_TEMP:-/tmp}/images.XXXXXX")"
SVC=wpi-mediator-service:test REK=wpi-mediator-rekey:test
COMMIT="$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo unknown)"
fail() { echo "mediator-images: $1" >&2; exit 1; }

# --- the service image's context: only what the service needs
C="$W/svc"; mkdir -p "$C"
cp "$BIN" "$C/mediator" || fail "no mediator binary"
cp "$HERE/mediator-entrypoint.sh" "$HERE/mediator-deny.sha256" "$C/"
node "$HERE/mediator-deny-file.mjs" "$HERE/mediator-env-lists.json" "$C/deny.txt" > "$W/deny.sha" || fail "deny file"
[ "$(cat "$W/deny.sha")" = "$(tr -d ' \n' < "$HERE/mediator-deny.sha256")" ] || fail "the deny file is not the baked sha256's"
gcc -static -O2 -Wall -o "$C/keyring-probe" "$HERE/keyring-probe.c" || fail "keyring probe build"
docker build -q --label "org.opencontainers.image.revision=$COMMIT" -f "$HERE/mediator-service.Dockerfile" -t "$SVC" "$C" > "$W/svc.id" || fail "service image build"

# --- the rekey image's context: the shipped tool (stripped here, then judged on the image's own copy) + its one dependency
R="$W/rek"; mkdir -p "$R/node_modules/@noble"
node "$HERE/mediator-store-ship.mjs" "$HERE/mediator-store.mjs" "$R/mediator-store.mjs" > "$W/ship.json" || fail "ship strip"
cp "$HERE/mediator-rekey-entrypoint.sh" "$R/rekey-entrypoint.sh" || fail "no rekey entrypoint"
cp -r "$HERE/node_modules/@noble/hashes" "$R/node_modules/@noble/" || fail "no @noble/hashes (npm ci first)"
docker build -q --label "org.opencontainers.image.revision=$COMMIT" -f "$HERE/mediator-rekey.Dockerfile" -t "$REK" "$R" > "$W/rek.id" || fail "rekey image build"

# --- each image's whole filesystem, as docker export writes it (device nodes left out; nothing is followed)
rootfs() {
  local img="$1" dir="$2" cid
  mkdir -p "$dir"; cid="$(docker create "$img")" || return 1
  docker export "$cid" | tar -x -C "$dir" --no-same-owner --exclude='dev/*' --exclude='proc/*' --exclude='sys/*'; local rc=$?
  docker rm -f "$cid" > /dev/null
  chmod -R u+rX "$dir" 2> /dev/null || true
  return $rc
}
rootfs "$SVC" "$W/svc-root" || fail "service export"
rootfs "$REK" "$W/rek-root" || fail "rekey export"
# --- Security 11869.4: the base-diff line. Both the rekey image and the base it is built FROM, as export streams (tar
# headers keep the image's own mode and owner), judged file by file against the added set (rekey-added.json).
BASE_REF="$(sed -n 's/^FROM \([^ ]*\).*/\1/p' "$HERE/mediator-rekey.Dockerfile" | head -1)"
[[ "$BASE_REF" == *@sha256:* ]] || fail "the rekey Dockerfile's base is not pinned by digest"
tarof() { local img="$1" out="$2" cid; cid="$(docker create "$img")" || return 1; docker export "$cid" > "$out"; local rc=$?; docker rm -f "$cid" > /dev/null; return $rc; }
tarof "$REK" "$W/rek.tar" || fail "rekey export (tar)"
tarof "$BASE_REF" "$W/base.tar" || fail "base export (tar)"
docker image inspect "$SVC" > "$W/svc-inspect.json" && docker image inspect "$REK" > "$W/rek-inspect.json" || fail "inspect"
# Security 11935 (a): the base half of the rekey config record is read from the pinned base itself, pulled by digest
# for linux/amd64, never typed by hand (mediator-image-config.mjs; hand half rekey-config.json).
docker pull -q --platform linux/amd64 "$BASE_REF" > /dev/null && docker image inspect "$BASE_REF" > "$W/base-inspect.json" || fail "base inspect"
# Security 12197.2 + 12232.1: the registry chain the pin names (index by the FROM digest, the one linux/amd64 manifest,
# its config blob), raw, so the config record checks every hash itself and ties inspect's read to the pinned blob. A
# failed fetch is not fatal here: the record reads the missing blob as FAIL, never as a pass.
node "$HERE/mediator-base-fetch.mjs" "$BASE_REF" "$W/base-chain" || echo "mediator-images: base registry chain not fully fetched (the config record and the base layers go red)" >&2
# Security 12327 + 12358: the base diff's base side is built from the layers the pinned manifest names, each checked
# (compressed digest + size, media type, count, decompressed digest = the blob's diff_ids[i]) and applied in order
# (whiteouts, opaque dirs, effective pax/GNU names; an escape or a write through a symlink is red). The tree is written
# only when all of it passes, so a failed fetch or check leaves no tree and the base diff is red.
bl=0; node "$HERE/mediator-base-layers.mjs" "$W/base-chain" "$HERE/rekey-config.json" "$W/base-tree.json" "$ODIR/rekey-base-layers.json" || bl=$?
rm -rf "$W/base-chain/layers"

# --- the planted tree: every search must hit each of these first
PL="$W/planted"; mkdir -p "$PL/usr/lib/node" "$PL/usr/local/bin" "$PL/usr/bin" "$PL/run/dbus" "$PL/run/user/10001" "$PL/opt"
cp "$HERE/mediator-store.mjs" "$PL/usr/lib/node/renamed-tool.js"
cp "$HERE/mediator-store.mjs" "$PL/opt/mediator-store.mjs"
# Security 13081.2: a gzip of the full tool, named so only its first bytes say it is an archive
gzip -9nc "$HERE/mediator-store.mjs" > "$PL/usr/lib/node/renamed-tool.bin"
: > "$PL/usr/local/bin/mediator-setup"; : > "$PL/usr/bin/dbus-daemon"; : > "$PL/run/dbus/system_bus_socket"; : > "$PL/run/user/10001/bus"

svc=0; node "$HERE/mediator-image-check.mjs" service "$W/svc-root" "$W/svc-inspect.json" "$PL" "$ODIR/service-image.json" || svc=$?
# The base side is the registry-built tree; the local pull's export is the 12327.4 cross-check against it.
bd=0; node "$HERE/mediator-base-diff.mjs" "$W/rek.tar" "$W/base-tree.json" "$W/base.tar" "$HERE/rekey-added.json" "$PL" "$HERE/mediator-store.mjs" "$ODIR/rekey-base-diff.json" || bd=$?
rm -f "$W/rek.tar" "$W/base.tar" "$W/base-tree.json"
cfg=0; node "$HERE/mediator-image-config.mjs" "$W/rek-inspect.json" "$W/base-inspect.json" "$HERE/rekey-config.json" "$HERE/mediator-rekey.Dockerfile" "$W/base-chain" "$ODIR/rekey-config-record.json" || cfg=$?
rek=0; node "$HERE/mediator-image-check.mjs" rekey "$W/rek-root" "$W/rek-inspect.json" /opt/rekey/mediator-store.mjs "$ODIR/rekey-image.json" "$PL" || rek=$?

# --- the service binary in its image: libraries resolve, it runs
ldd_out="$(docker run --rm --network none --entrypoint /usr/bin/ldd "$SVC" /opt/mediator/mediator 2>&1)"; ldd_rc=$?
missing="$(printf '%s\n' "$ldd_out" | grep -c 'not found' || true)"
help=0; docker run --rm --network none --read-only --entrypoint /opt/mediator/mediator "$SVC" --help > /dev/null 2>&1 || help=$?

# --- 12519 (e): the kernel-keyring probe, as the service user, inside the image, under the runner's Docker defaults
probe="$(docker run --rm --network none --read-only --entrypoint /opt/mediator/keyring-probe "$SVC" 2>/dev/null)"; probe_rc=$?
probe_v="$(printf '%s' "$probe" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    let j; try { j = JSON.parse(s); } catch { console.log("FAIL"); return; }
    const both = [j.session, j.user];
    if (j.uid === 0) console.log("FAIL");
    else if (both.every((x) => x === "refused")) console.log("PASS");
    // Security 13081.3: every label that reads landed must carry its own <label>_removed: true
    else if (both.every((x) => x === "refused" || x === "landed") && ["session", "user"].every((l) => j[l] !== "landed" || j[l + "_removed"] === true)) console.log("AMBER");
    else console.log("FAIL");
  });')"

# --- Security 12940: the same probe through the image's OWN entrypoint, started with no arguments (it refuses
# "missing --bin" after the probe, so nothing else runs). Its first stderr line must be the probe's JSON line:
# refused = PASS, landed = AMBER, anything else (no line, absent, probe_failed) = FAIL, and the start still refuses 78.
ep_rc=0; ep_err="$(docker run --rm --network none --read-only "$SVC" 2>&1 > /dev/null)" || ep_rc=$?
ep_first="$(printf '%s\n' "$ep_err" | head -1)"
ep_v="$(printf '%s' "$ep_first" | node -e '
  let s = ""; process.stdin.on("data", (d) => (s += d)).on("end", () => {
    let j; try { j = JSON.parse(s); } catch { console.log("FAIL"); return; }
    if (j.entrypoint !== "keyring_probe") console.log("FAIL");
    else if (j.verdict === "refused" && j.l8 === "PASS") console.log("PASS");
    else if (j.verdict === "landed" && j.l8 === "AMBER") console.log("AMBER");
    else console.log("FAIL");
  });')"
[ "$ep_rc" = 78 ] || ep_v=FAIL

# --- the rekey image's behaviour, on a made-up store (the full source tool writes it here, on the runner, never in the image)
D="$W/rekey-data"; PP="$(mktemp -d /dev/shm/rekeypp.XXXXXX)"; mkdir -p "$D"; chmod 0700 "$D" "$PP"
head -c 24 /dev/urandom | base64 > "$PP/old"; head -c 24 /dev/urandom | base64 > "$PP/new"; chmod 0444 "$PP/old" "$PP/new"
node "$HERE/mediator-store.mjs" seal-test "$D/secrets.json" "$PP/old" '{"mediator_secrets":"made-up","mediator_jwt_secret":"made-up","mediator_admin_credential":"{\"did\":\"did:key:zMadeUp\"}"}' > /dev/null || fail "made-up store"
# The tool's own subcommands are called past the entrypoint (by node, by path); `rekey` itself only through the image's
# entrypoint (Security 12024.1), with the two passphrases as service variables and planted service markers beside them.
rrun() { docker run --rm --network none --read-only --user "$(id -u):$(id -g)" -v "$D:/data" -v "$PP:/run/pp:ro" --entrypoint /usr/local/bin/node "$REK" /opt/rekey/mediator-store.mjs "$@"; }
MK_DB="marker-db-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"; MK_RD="marker-redis-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
erun() { docker run --rm --network none --read-only --user "$(id -u):$(id -g)" -v "$D:/data" \
  -e DATABASE_URL="postgres://u:$MK_DB@h/db" -e REDIS_PASSWORD="$MK_RD" \
  -e ENKARA_MEDIATOR_BACKEND_PASSPHRASE="$(cat "$PP/old")" -e ENKARA_MEDIATOR_BACKEND_PASSPHRASE_NEW="$(cat "$PP/new")" \
  "$REK" --volume /data --tmpfs /dev/shm; }
# Each call's exit and the first line it wrote to stderr (the tool prints names and verdicts only; a docker or node
# failure shows here instead of as a bare FAIL). Cut to 160 characters, JSON-escaped by node.
CALLS="$W/rekey-calls.jsonl"; : > "$CALLS"
note() { node -e 'const [c, x, e] = process.argv.slice(1); console.log(JSON.stringify({ call: c, exit: Number(x), stderr: (e.split("\n").find(Boolean) || "").slice(0, 160) }))' "$1" "$2" "$3" >> "$CALLS"; }
r1=0; r1_err="$(erun 2>&1 > /dev/null)" || r1=$?
note rekey-with-credential "$r1" "$(printf '%s\n' "$r1_err" | grep -v '^rekey-entrypoint:')"
r1_names_cred=$([[ "$r1_err" == *mediator_admin_credential* ]] && echo true || echo false)
removed=(); for s in admin-out delete-admin seal-test encrypt-test; do c=0; e="$(rrun "$s" /data/secrets.json /run/pp/old 2>&1 > /dev/null)" || c=$?; note "$s" "$c" "$e"; removed+=("\"$s\":$c"); done
node "$HERE/mediator-store.mjs" delete-admin "$D/secrets.json" "$PP/old" > /dev/null || fail "made-up store delete"
r2=0; r2_out="$(erun 2>"$W/r2.err")" || r2=$?; note rekey-after-delete "$r2" "$(grep -v '^rekey-entrypoint: env -i dropped' "$W/r2.err")"
# Security 12024.1: no marker value on either stream of either run; the tool past `env -i` refuses any other name, so
# its exit 0 is the proof the markers never reached it. 12024.2 (a): a second run refuses and leaves the store as it was.
markers=0; for v in "$MK_DB" "$MK_RD" "$(cat "$PP/old")" "$(cat "$PP/new")"; do
  [[ "$r1_err$r2_out$(cat "$W/r2.err")" == *"$v"* ]] && markers=$((markers + 1)); done
dropped_db=$(grep -c '^rekey-entrypoint: env -i dropped .*DATABASE_URL' "$W/r2.err" || true)
pre3="$(sha256sum < "$D/secrets.json")"; r3=0; e="$(erun 2>&1 > /dev/null)" || r3=$?; note rekey-second-run "$r3" "$(printf '%s\n' "$e" | grep -v '^rekey-entrypoint:')"
same3=$([ "$(sha256sum < "$D/secrets.json")" = "$pre3" ] && echo true || echo false)
o_old=0; e="$(rrun opens /data/secrets.json /run/pp/old 2>&1 > /dev/null)" || o_old=$?; note opens-old "$o_old" "$e"
o_new=0; e="$(rrun opens /data/secrets.json /run/pp/new 2>&1 > /dev/null)" || o_new=$?; note opens-new "$o_new" "$e"
rm -rf "$PP"; [ -e "$PP" ] && fail "passphrase dir still there"

node - "$OUT" "$ODIR" "$W" <<EOF
const fs = require('fs'); const [out, odir, w] = process.argv.slice(2);
const rd = (f) => { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } };
const svc = rd(odir + '/service-image.json'), rek = rd(odir + '/rekey-image.json'), ship = rd(w + '/ship.json'), bdiff = rd(odir + '/rekey-base-diff.json'), blay = rd(odir + '/rekey-base-layers.json');
const removed = JSON.parse('{${removed[*]}}'.replace(/ /g, ','));
let r2 = null; try { r2 = JSON.parse(\`$r2_out\`); } catch {}
const P = (b) => (b ? 'PASS' : 'FAIL');
const lines = {
  service_image_check: P(svc && svc.ok),
  service_libraries_resolve: P($ldd_rc === 0 && $missing === 0),
  service_mediator_help_runs: P($help === 0),
  service_keyring_probe: '$probe_v' || 'FAIL',
  service_entrypoint_first_line_is_the_keyring_probe: '$ep_v' || 'FAIL',
  rekey_image_check: P(rek && rek.ok),
  rekey_base_layers: P($bl === 0 && blay && blay.ok),
  rekey_base_diff: P($bd === 0 && bdiff && bdiff.ok),
  rekey_refuses_while_admin_credential_present: P($r1 !== 0 && $r1_names_cred),
  rekey_removed_subcommands_answer_usage: P(Object.values(removed).length === 4 && Object.values(removed).every((c) => c === 2)),
  rekey_config_record: P($cfg === 0),
  rekey_env_i_no_marker_reaches_tool_or_output: P($r2 === 0 && $markers === 0 && $dropped_db === 1),
  rekey_second_run_refuses_store_unchanged: P($r3 === 1 && $same3),
  rekey_reseals_once_credential_gone: P($r2 === 0 && r2 && r2.values_unchanged && r2.salt_changed && !r2.old_opens && r2.new_opens && $o_old === 4 && $o_new === 0),
};
const rec = {
  what: 'Dockerfile batch: service image + one-off rekey image (Security 12422 e, 12491 b, 12519 e, 12195.1 d)',
  commit: '$COMMIT', lines,
  service_image_id: fs.readFileSync(w + '/svc.id', 'utf8').trim(), rekey_image_id: fs.readFileSync(w + '/rek.id', 'utf8').trim(),
  shipped_tool_sha256: rek && rek.shipped_sha256, ship_strip_sha256: ship && ship.sha256,
  keyring_probe: (() => { try { return JSON.parse(\`$probe\`); } catch { return null; } })(), keyring_probe_host: 'GitHub ubuntu-latest runner, Docker default seccomp',
  entrypoint_probe_line: (() => { try { return JSON.parse(\`$ep_first\`); } catch { return null; } })(), entrypoint_exit: $ep_rc,
  removed_subcommand_exits: removed,
  rekey_calls: fs.readFileSync(w + '/rekey-calls.jsonl', 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
};
fs.writeFileSync(out, JSON.stringify(rec, null, 2) + '\n');
console.log(JSON.stringify(lines));
console.log(JSON.stringify(rec.rekey_calls));
// Security 13081.1: the shipped tool's sha256 in the log too, so it can be read against the L8 pin without the artifact
console.log(JSON.stringify({ shipped_tool_sha256: rec.shipped_tool_sha256, ship_strip_sha256: rec.ship_strip_sha256, rekey_archive_hits: rek && rek.archive_hits, rekey_archives_allowed_read: rek && rek.archives_allowed_read }));
// Security 11869.4: the base diff's verdict, and what the image added (path, sha256, mode, owner), once, for the pin
// Security 12327.6: per-layer digest verdicts and counts only
console.log(JSON.stringify({ rekey_base_layers: blay && { ok: blay.ok, checks: blay.checks, layers: blay.layers, counts: blay.counts, apply_red: blay.apply_red } }));
console.log(JSON.stringify({ rekey_base_diff: bdiff && { ok: bdiff.ok, checks: bdiff.checks, instrument: bdiff.instrument, changed: bdiff.changed, added_file_not_in_set: bdiff.added_file_not_in_set, added_dir_outside: bdiff.added_dir_outside, added_not_a_file: bdiff.added_not_a_file, added_setuid: bdiff.added_setuid, added_set_missing: bdiff.added_set_missing, container_init_bad: bdiff.container_init_bad, deleted_base_entries: bdiff.deleted_base_entries, anomalies: bdiff.anomalies } }));
// Security 12327.4: the local pull against the registry-built tree; and the container's own entries, for the pin
console.log(JSON.stringify({ rekey_base_cross_check: bdiff && { checks: bdiff.checks && { local_base_equals_registry_tree: bdiff.checks.local_base_equals_registry_tree, cross_check_bites: bdiff.checks.cross_check_bites }, only_local: bdiff.cross_check.only_local, only_registry: bdiff.cross_check.only_registry, differ: bdiff.cross_check.differ, init_bad: bdiff.cross_check.init_bad, entries: { rekey: bdiff.rek_entries, local_base: bdiff.local_base_entries, registry: bdiff.registry_entries } } }));
console.log(JSON.stringify({ container_init_read: bdiff && bdiff.runtime_entries_read, container_init_pinned: bdiff && bdiff.checks.container_init_pinned }));
console.log(JSON.stringify({ rekey_added_read: bdiff && bdiff.added_read }));
// Security 11935 (a), (e), 12197.2 (c), 12232.1: the base's manifest and config digests read from the registry chain
// (for the L8 pins), inspect's Id as evidence only, and the base half beside the verdict
const crec = rd(odir + '/rekey-config-record.json');
console.log(JSON.stringify({ rekey_config_record: crec && { ok: crec.ok, checks: crec.checks, base_manifest_digest_read: crec.base_manifest_digest_read, base_config_digest_read: crec.base_config_digest_read, base_inspect_id: crec.base_inspect_id, base_platform: crec.base_platform, base_half: crec.base_half, details: crec.details } }));
process.exit(Object.values(lines).some((v) => v === 'FAIL') ? 1 : 0);
EOF
