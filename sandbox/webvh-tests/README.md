# did:webvh library tests

Tests `didwebvh-ts` 3.1.0 (the repo's own dependency), `didwebvh-rs` 0.8.2 and, offline only, `didwebvh-py` against each other.
Run by `.github/workflows/webvh-library-tests.yml` (manual, or a push to `claude/wpi-build-webvh-**`). Test values only: every key, log and host
is generated inside the job and thrown away with it. No secret, no deploy, no real person's key.

| file | job | what |
| --- | --- | --- |
| `pins.json`, `check-pins.mjs`, `check-licences.mjs`, `licences.snapshot.json` | all | pins (upstream heads, versions, licences); a moved head or a changed licence field fails the job at its end |
| `audit.mjs` | audit | `npm audit --omit=dev` on `didwebvh-ts@pin` alone, `cargo audit` on `rs/Cargo.lock` |
| `suite.mjs`, `ci/fetch-suite.sh` | suite | each library's own entry in the pinned `didwebvh-test-suite` (`scripts/run <impl>`, Docker); counts PASS/FAIL/SKIP from `status.md` |
| `lib.mjs`, `ts-cli.mjs`, `rs/` (`wpi-webvh-rs`), `py_resolve.py` | | the three libraries behind one JSON-on-stdout command line each |
| `roundtrip.mjs`, `static-server.mjs` | roundtrip | TS and Rust each make the four-step log (pre-rotation, rotate, witness 2-of-2, witness 1-of-1) and resolve the other's; document comparison; the move; the witness-entry observation |
| `tamper.mjs` | tamper | seven breaks of each valid log plus controls, and the five parser-level negative vectors of the suite; all three libraries |
| `netwatch.mjs` | netwatch | resolve offline in an empty network namespace; resolve from the local server under `strace -e trace=connect`; the Python path-traversal probes |
| `report.mjs` | report | the markdown report of the run |

Each job writes JSON into `results/` and uploads it; `report` turns them into the step summary. A missing result is a failure.

## How the libraries are driven

- **Rust, local files:** `DIDWebVHState::resolve_log` (no network). **Rust, over HTTP:** `resolve` with `HostPolicy::AllowPrivate`, which fetches
  `*.localhost` names over plain `http://`, and a `reqwest` client that pins `a.localhost` / `b.localhost` to 127.0.0.1 (the port is in the DID).
- **TS, local files:** `resolveDIDFromLog` with `witnessProofs`. **TS, over HTTP:** `resolveDID` with a `fetch` that sends the request to 127.0.0.1 and
  keeps the test hostname in the `Host` header.
- **Python:** `did_webvh.resolver.resolve_did(did, local_history=<log>)`; the witness file is read from beside the log.
- The static server (`static-server.mjs`) serves `/.well-known/did.jsonl` and `did-witness.json` from a directory per `Host`.

## Running it by hand

```bash
npm ci --ignore-scripts                      # in the repo root
cargo build --locked --manifest-path sandbox/webvh-tests/rs/Cargo.toml
node sandbox/webvh-tests/roundtrip.mjs /tmp/wpi-work /tmp/wpi-results
node sandbox/webvh-tests/tamper.mjs /tmp/wpi-work/logs-for-tamper /tmp/wpi-tamper /tmp/wpi-results   # + <suite>/vectors for line (h)
node sandbox/webvh-tests/netwatch.mjs /tmp/wpi-work/logs-for-tamper /tmp/wpi-nw /tmp/wpi-results      # needs strace, unshare (root or passwordless sudo)
node sandbox/webvh-tests/report.mjs /tmp/wpi-results /tmp/report.md
```

`WPI_PYTHON` names a Python with `didwebvh-py` installed (otherwise `python3`; its rows then read "cannot import"). `WPI_VECTORS_DIR` names the suite's
`vectors/` (or any directory of scenario folders) for the witness-update vector.

## Line (d), the witness-rule meaning split

Pass means every gated library (ts, rs) produced a recorded accept/refuse answer on each witness-entry case, none crashing before it answered. It does not
require them to agree: the table in the report is the finding. didwebvh-py appears there as an information column only.

## Changing a pin

Edit `pins.json` in a reviewed change. For a moved head, read what changed upstream first. `licences.snapshot.json` is refreshed with
`node check-licences.mjs --write`, also in a reviewed change.
