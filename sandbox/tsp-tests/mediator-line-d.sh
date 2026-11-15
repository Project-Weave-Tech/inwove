#!/usr/bin/env bash
# ref/09 §2.4 line D (Security 11528, Railroad 11542): the mediator with a Redis `requirepass`.
# Reported side by side:
#   (1) the default (log_level info, no RUST_LOG): the start-up config dump prints `database_url`, password and all.
#       Expected FAIL on "doesn't print the password": the finding stands.
#   (2) the pinned filter RUST_LOG=info,affinidi_messaging_mediator::common::config=warn: expected 0 lines.
# Each in text and in JSON logs (log_json). Right password: must start and answer. Wrong password: must refuse
# (exit non-zero). The password is a random marker made here, never a real one; the count is every line of
# stdout + stderr that carries it. Prints only counts and verdicts, never a line that carries the marker.
#
# Usage: mediator-line-d.sh <mediator binary> <conf dir: the pinned mediator's docker/test/conf> <redis-server> <out.json>
# The conf dir is the upstream TEST-ONLY identity (its secrets.json is committed upstream as test-only).
set -euo pipefail
set +x
BIN=$(readlink -f "$1"); CONF_SRC=$(readlink -f "$2"); REDIS=$3; OUT=$4
FILTER='info,affinidi_messaging_mediator::common::config=warn'
WORK=$(mktemp -d "${RUNNER_TEMP:-/tmp}/lined.XXXXXX"); chmod 700 "$WORK"
cleanup() { [ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

MARK=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')       # the right password
WRONG=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')      # a wrong one, also a marker
RPORT=$((20000 + RANDOM % 20000)); MPORT=$((40000 + RANDOM % 20000))

"$REDIS" --port "$RPORT" --bind 127.0.0.1 --requirepass "$MARK" --save '' --appendonly no --daemonize no \
  >"$WORK/redis.log" 2>&1 & RPID=$!
for _ in $(seq 150); do (exec 3<>/dev/tcp/127.0.0.1/$RPORT) 2>/dev/null && break; sleep 0.1; done

# One run: $1 label, $2 password, $3 RUST_LOG ('' = unset), $4 log_json true|false.
run() {
  local label=$1 pw=$2 rl=$3 js=$4 d="$WORK/$1"
  mkdir -p "$d/conf"; cp "$CONF_SRC"/* "$d/conf/"
  sed -i -e "s#^database_url = .*#database_url = \"redis://:${pw}@127.0.0.1:${RPORT}/\"#" \
         -e "s#^backend = \"file://.*#backend = \"file://$d/conf/secrets.json\"#" \
         -e "s#^listen_address = .*#listen_address = \"127.0.0.1:${MPORT}\"#" \
         -e "s#^log_json = .*#log_json = \"${js}\"#" \
         -e "s#^log_level = .*#log_level = \"info\"#" "$d/conf/mediator.toml"
  local code=0 started=false
  ( cd "$d"; if [ -n "$rl" ]; then export RUST_LOG="$rl"; else unset RUST_LOG; fi
    exec "$BIN" --config conf/mediator.toml ) >"$d/out" 2>"$d/err" & local pid=$!
  for _ in $(seq 150); do
    if ! kill -0 "$pid" 2>/dev/null; then break; fi
    if curl -s -o /dev/null --max-time 1 "http://127.0.0.1:${MPORT}/mediator/v1/healthchecker"; then started=true; break; fi
    sleep 0.2
  done
  if $started; then sleep 1; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; code=running
  else wait "$pid" 2>/dev/null || code=$?; [ "$code" = 0 ] && code=0; fi
  local lines_right lines_wrong total target refusal_leak
  refusal_leak=$(cat "$d/out" "$d/err" | grep -E 'WARN|ERROR|"level":"(WARN|ERROR)"' | grep -c -F -e "$MARK" -e "$WRONG" || true)
  lines_right=$(cat "$d/out" "$d/err" | grep -c -F "$MARK" || true)
  lines_wrong=$(cat "$d/out" "$d/err" | grep -c -F "$WRONG" || true)
  total=$(cat "$d/out" "$d/err" | wc -l)
  # The module target the config dump is logged under (proves the filter names the right string).
  target=$(cat "$d/out" "$d/err" | grep -F 'Configuration settings parsed' | grep -o 'affinidi_messaging_mediator[a-z_:]*' | head -1 || true)
  printf '{"label":"%s","rust_log":%s,"log_json":%s,"password":"%s","started":%s,"exit":"%s","lines":%s,"lines_with_right_password":%s,"lines_with_wrong_password":%s,"warn_error_lines_with_a_password":%s,"config_dump_target":"%s"}\n' \
    "$label" "$( [ -n "$rl" ] && printf '"%s"' "$rl" || echo null )" "$js" "$( [ "$pw" = "$MARK" ] && echo right || echo wrong )" \
    "$started" "$code" "$total" "$lines_right" "$lines_wrong" "$refusal_leak" "$target" >>"$WORK/results.jsonl"
  rm -rf "$d"
}

run default-text        "$MARK"  ''        false
run default-json        "$MARK"  ''        true
run filter-text         "$MARK"  "$FILTER" false
run filter-json         "$MARK"  "$FILTER" true
run wrong-default-text  "$WRONG" ''        false
run wrong-filter-json   "$WRONG" "$FILTER" true

node -e '
const rows = require("fs").readFileSync(process.argv[1], "utf8").trim().split("\n").map(JSON.parse)
const by = Object.fromEntries(rows.map((r) => [r.label, r]))
const leak = (r) => r.lines_with_right_password + r.lines_with_wrong_password
const out = {
  line: "D", rust_log_filter: process.argv[3], runs: rows,
  default: { verdict: [by["default-text"], by["default-json"]].every((r) => leak(r) === 0) ? "PASS" : "FAIL",
             note: "no RUST_LOG, log_level info: counts lines carrying the password" },
  filtered: { verdict: [by["filter-text"], by["filter-json"]].every((r) => r.started && leak(r) === 0) ? "PASS" : "FAIL" },
  right_password_starts: ["default-text", "filter-text"].every((k) => by[k].started),
  wrong_password_refuses: ["wrong-default-text", "wrong-filter-json"].every((k) => !by[k].started && by[k].exit !== "0"),
  refusal_lines_carry_no_password: ["wrong-default-text", "wrong-filter-json"].every((k) => by[k].warn_error_lines_with_a_password === 0),
}
require("fs").writeFileSync(process.argv[2], JSON.stringify(out, null, 2) + "\n")
console.log(JSON.stringify({ default: out.default.verdict, filtered: out.filtered.verdict, right_password_starts: out.right_password_starts, wrong_password_refuses: out.wrong_password_refuses }))
for (const r of rows) console.log(r.label.padEnd(20), "started", r.started, "exit", r.exit, "lines", r.lines, "with password", leak(r), "target", r.config_dump_target || "-")
' "$WORK/results.jsonl" "$OUT" "$FILTER"
