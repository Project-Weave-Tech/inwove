#!/usr/bin/env node
// Job `netwatch`. Usage: node netwatch.mjs <logs-for-tamper dir (from roundtrip)> <workdir> <resultsdir>
//   1. OFFLINE: TS and Rust (and Python, reported only) resolve+verify the valid roundtrip logs inside an empty network
//      namespace (`unshare -n`: no interface, not even loopback). Pass: both TS and Rust succeed on the local files.
//   2. LOGGED: TS and Rust resolve over HTTP from the job's local static server under `strace -f -e trace=connect`.
//      Pass: every connect() they make is to the local static server (127.0.0.1:<port>); anything else fails.
//   3. PROBE: Python only, in the empty namespace under strace, with three DIDs it once fetched (path traversal, percent-encoded
//      traversal, an over-long DNS label). Pass: it refuses each and makes NO network connect() (AF_INET/AF_INET6) while doing so.
// Needs `strace` and `unshare`; as a non-root user it uses `sudo -n`.
import { readFileSync, existsSync, rmSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { run, ts, rs, verdict, RS_BIN, TS_CLI, PY_CLI, startStaticServer, publish, ensureDir, writeJson, readJson, traced as tracedRun, SUDO, probeLines } from './lib.mjs'

const [logsDir, work = 'work-netwatch', results = 'results'] = process.argv.slice(2)
rmSync(work, { recursive: true, force: true }); ensureDir(work); ensureDir(results)
const t0 = Date.now()
const index = readJson(join(logsDir, 'index.json'))
const PYTHON = process.env.WPI_PYTHON || 'python3'
const checks = []
const check = (name, ok, detail) => { checks.push({ name, ok: !!ok, detail }); console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? '  ' + detail : ''}`) }

const isNet = (c) => c.family === 'AF_INET' || c.family === 'AF_INET6'
const plain = (cmd, args, empty) => run(...((full) => [full[0], full.slice(1)])([...SUDO, ...(empty ? ['unshare', '-n', '--'] : []), cmd, ...args]))
const traced = (cmd, args, o) => tracedRun(cmd, args, { ...o, dir: work })

// ---- 1. offline ------------------------------------------------------------------------------------------------
const offline = {}
for (const maker of ['ts', 'rs']) {
  const did = index[maker].did; const log = resolve(join(logsDir, `${maker}.did.jsonl`)); const wit = resolve(join(logsDir, `${maker}.did-witness.json`))
  for (const [lib, cmd, base] of [['ts', 'node', [TS_CLI]], ['rs', RS_BIN, []], ['py', PYTHON, ['-I', PY_CLI]]]) {
    const r = plain(cmd, [...base, 'resolve-file', did, log, wit], true)
    const v = verdict(r)
    offline[`${lib} on ${maker}-made log`] = { accepted: v.accepted, versionNumber: v.versionNumber, scid: v.scid, error: v.error, ms: v.ms }
  }
}
for (const lib of ['ts', 'rs']) for (const maker of ['ts', 'rs']) {
  const o = offline[`${lib} on ${maker}-made log`]
  check(`offline (empty network namespace): ${lib} resolves and verifies the ${maker}-made log`, o.accepted && o.versionNumber === 4, o.accepted ? `v${o.versionNumber}, ${o.ms} ms` : o.error)
}

// ---- 2. logged (egress log of TS and Rust talking to the local static server) -------------------------------------
const www = join(work, 'www')
const server = await startStaticServer(www)
const P = server.port
// the logs are minted for a.localhost:<port-of-roundtrip>; the DID names that port, so re-mint here for THIS server's port
const logged = {}
{
  const mkdir = join(work, 'mint')
  const host = `a.localhost:${P}`
  const t = ts(['create-log', join(mkdir, 'ts'), host.replace(':', '%3A')])
  const q = rs(['create-log', join(mkdir, 'rs'), host])
  check('logs for the logged run were minted for this server (TS and Rust)', t.json?.ok && q.json?.ok, '')
  for (const maker of ['ts', 'rs']) {
    const j = maker === 'ts' ? t.json : q.json
    rmSync(www, { recursive: true, force: true })
    publish(www, 'a.localhost', join(mkdir, maker, 'did.jsonl'), join(mkdir, maker, 'did-witness.json'))
    for (const [lib, cmd, base] of [['ts', 'node', [TS_CLI]], ['rs', RS_BIN, []]]) {
      const { r, connects } = traced(cmd, [...base, 'resolve-http', j.did, 'a.localhost=127.0.0.1'], { tag: `${lib}-on-${maker}` })
      const v = verdict(r)
      const net = connects.filter(isNet)
      const strangers = net.filter((c) => !(c.addr === '127.0.0.1' && c.port === P))
      logged[`${lib} on ${maker}-made log`] = { accepted: v.accepted, versionNumber: v.versionNumber, connects: connects.map((c) => `${c.family} ${c.addr}${c.port ? ':' + c.port : ''} -> ${c.result}`), strangers: strangers.map((c) => `${c.addr}:${c.port}`) }
      check(`logged: ${lib} resolves the ${maker}-made log over HTTP from the local static server`, v.accepted && v.versionNumber === 4, v.accepted ? '' : v.error)
      check(`logged: ${lib} (${maker}-made log) made no connection other than to 127.0.0.1:${P}`, net.length > 0 && strangers.length === 0, `${net.length} network connect() call(s), ${strangers.length} elsewhere, ${connects.length - net.length} non-network`)
    }
  }
}
const requests = server.requests()
await server.close()

// ---- 3. Python probe: three DIDs it fetched before --------------------------------------------------------------------
const scid = 'QmZbNqX7y3o9UJ2m4s1f8d5r6w0cKt3hVgPaLeRiDnBxYz'
const probes = [
  ['path traversal', `did:webvh:${scid}:example.com:..:..:etc`],
  ['percent-encoded traversal', `did:webvh:${scid}:example.com:%2e%2e:%2e%2e:etc`],
  ['over-long DNS label (64 characters)', `did:webvh:${scid}:${'a'.repeat(64)}.example.com`],
]
const probeRows = []
for (const [name, did] of probes) {
  const { r, connects } = traced(PYTHON, ['-I', PY_CLI, 'probe', did], { empty: true, tag: `py-probe-${probeRows.length}` })
  const answer = probeLines(r.stdout)[0]
  const net = connects.filter(isNet)
  const refused = answer ? answer.ok === false : false // no answer at all is not a recorded refusal
  probeRows.push({ name, did, refused, answer: answer?.error ? String(answer.error).slice(0, 240) : (answer ? 'returned a document' : `no answer (exit ${r.code})`), networkConnects: net.map((c) => `${c.family} ${c.addr}:${c.port} -> ${c.result}`), otherConnects: connects.filter((c) => !isNet(c)).length })
  check(`python probe: ${name}: refused without connecting`, refused && net.length === 0, `refused=${refused}, network connect() calls=${net.length}${net.length ? ' (' + net.map((c) => c.addr + ':' + c.port).join(', ') + ')' : ''}`)
}

const pass = checks.every((c) => c.ok)
writeJson(join(results, 'netwatch.json'), { job: 'netwatch', pass, checks, offline, logged, probes: probeRows, staticServerRequests: requests, staticPort: P, ms: Date.now() - t0, note: 'offline python result is reported, not gated' })
console.log(`netwatch: ${checks.filter((c) => c.ok).length}/${checks.length} checks, ${Date.now() - t0} ms`)
