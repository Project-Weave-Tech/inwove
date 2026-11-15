# ref/09: TSP 1.0 library and mediator tests

Railroad's spec `ref/09` (TSP 1.0 + mediator, for Enkara's L8 door), run by `.github/workflows/tsp-library-tests.yml`
on a push to `claude/wpi-build-tsp-**` or by dispatch. Test values only: every key and DID is made inside the job and
thrown away with it (the frames file holding them is deleted before the results are uploaded). No secret, no deploy,
no outside mediator. Not part of the app: its own `package.json`, nothing in the room imports it.

| file | job | what |
|---|---|---|
| `check-pins.mjs`, `pins.json` | audit | versions, licences (an `@openvtc` package not Apache-2.0/MIT fails), full shas of the pinned sources |
| `audit.mjs` | audit | `npm audit --omit=dev`, `cargo audit` on `rs/Cargo.lock`, vti-tsp-js loads in plain Node 22 |
| `rs/` | all | the Rust peer: affinidi-tsp 0.3.0 driven by JSON lines on stdin (`cargo build --locked --release`) |
| `lib.mjs` | all | test VIDs (did:key), a messaging/ping/0.2 Trust Task with an eddsa-jcs-2022 proof, the byte-concatenated binding envelope |
| `vectors.mjs` | vectors | §2.2: every Appendix A vector at `ccda6b33`: version code, opened by TS and by Rust, body as the vector, TS rebuilds byte for byte where the vector gives `ikmE`; sealed-box and post-quantum vectors recorded as answers |
| `roundtrip.mjs` | roundtrip | §2.3: TS→Rust and Rust→TS with the envelope; invite/accept; application frames with and without a relationship |
| `tamper.mjs` | roundtrip | §2.5 (a)–(j); (f) uses a real Rev 3 frame from `@openvtc/vti-tsp-js` 0.3.0 (aliased `vti-tsp-js-rev3`) |
| `netwatch.mjs` | roundtrip | §2.6 roundtrip half: roundtrip inside `unshare -n`, proving the namespace had no network |
| `report.mjs` | report | the §3 markdown report; red while any §0 line has no result |

Not built yet (the report shows each as not passed): `mediator` (Affinidi mediator in Docker, REST pickup, Security's lines A–D), and netwatch's mediator egress log.

Run locally: `npm ci --ignore-scripts` here, `cargo build --locked --release --manifest-path rs/Cargo.toml`, then
`node vectors.mjs results <tswg-tsp-specification>/spec/spec.md && node roundtrip.mjs results && node tamper.mjs results && sudo unshare -n -- node netwatch.mjs results`.
