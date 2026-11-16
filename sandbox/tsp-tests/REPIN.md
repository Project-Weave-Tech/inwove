# Re-pinning the mediator: the checklist

A re-pin moves `MED_SHA` / `MED_REF` in `.github/workflows/tsp-library-tests.yml` to a new upstream commit. It reaches
the host only when every step below holds on the new pin, in one job run, and Security has read it.

1. **Fetch by full sha, proven upstream's.** `fetch-pinned.sh` refuses a commit that isn't an ancestor of `MED_REF`.
2. **The environment-read record.** `mediator-env-reads.mjs <checkout> mediator-env-lists.json --write`, in its own
   commit; a new deny name is written `unread` and stays red until Security reads it (condition 16.2(b)).
3. **The resolved features.** Lean build: no `vta*`, no `secrets-*`, no `aws`; the default build (the control) must
   fail. The setup binary: only `vta-sdk`; its tree record is compared with register L8, never rewritten by the job.
4. **The client-keyring path.** Every path to `keyring-core` / the dbus store runs through `affinidi-tdk-common`; no
   `keyutils` crate in either tree.
5. **Admin over TSP is refused with the guard on (expected)** — the `expectred` step, `mediator-expect-red.mjs`
   (Security 12552; Railroad 12567.1; Security 12582.1). **A re-pin whose expect-red doesn't pass stops here, whatever
   else is green, and comes to SECURITY as a finding.** If the TSP update or an add is ever accepted, that is a
   finding, never a test to update.
6. **Every private key of the admin DID, as one admin key** (Security 12582.2): the setup run lists the admin DID
   document's keys, the credential must yield each one, the scan self-hits on each kind in each encoding, and at the
   end no volume file or log line carries any of them and `admin-monitor.json` is gone.
7. **`trust_task_verification = "enforce"`** in the conf the job runs. At 0.50.0 the upstream default and the shipped
   `conf/mediator.toml` are `warn`, under which a write task with no proof is accepted on the authcrypt key alone.
8. **The rest of the mediator job green**, and the units (`npm test`; `node --test admin-key-markers.test.mjs` here).
