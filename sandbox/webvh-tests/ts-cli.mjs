#!/usr/bin/env node
// didwebvh-ts 3.1.0 as a command line, same shape as the Rust CLI. Prints ONE json object on stdout.
//   ts-cli.mjs create-log <dir> <host> [--one-proof]
//   ts-cli.mjs resolve-file <did> <log> [witness-file] [--version N]
//   ts-cli.mjs resolve-http <did> <host=ip>... [--version N]   (the DID's hostnames pinned to local addresses; http, not https)
//   ts-cli.mjs move <dir> <to-host>            (portable move of the log in <dir>: needs <dir>/keys.json, written by create-log)
import { readFileSync, writeFileSync } from 'node:fs'
import { resolveDID, tsFourStepLog, tsResolve, readLog, logText, ensureDir, writeJson, readJson, verifier } from './lib.mjs'
import { updateDID } from 'didwebvh-ts'
import { request as httpRequest } from 'node:http'

const args = process.argv.slice(2)
const take = (name, hasValue) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = hasValue ? args[i + 1] : true; args.splice(i, hasValue ? 2 : 1); return v }
const version = take('--version', true)
const oneProof = take('--one-proof', false)
const [cmd, ...rest] = args
const out = (o) => console.log(JSON.stringify(o))

try {
  if (cmd === 'create-log') {
    const [dir, host] = rest
    const r = await tsFourStepLog(host, { oneProofOnly: !!oneProof })
    ensureDir(dir)
    writeFileSync(`${dir}/did.jsonl`, logText(r.log))
    writeJson(`${dir}/did-witness.json`, r.witnessProofs)
    // Test keys, written only so the later `move` step can sign; they live in the job's workspace and die with it.
    writeJson(`${dir}/keys.json`, { updateKeySeedHex: r.keys.k1.id.seedHex, updateKey: r.keys.k1.mk, witnesses: [r.keys.w1.id.seedHex, r.keys.w2.id.seedHex] })
    out({ ok: true, did: r.did, entries: r.log.length })
  } else if (cmd === 'resolve-file') {
    const [did, logPath, witnessPath] = rest
    let proofs = []
    if (witnessPath) { try { proofs = readJson(witnessPath) } catch { proofs = [] } }
    let log
    try { log = readLog(logPath) } catch (e) { out({ ok: false, error: `unreadable log: ${e.message}` }); process.exit(0) }
    out(await tsResolve(log, did, { witnessProofs: proofs, version }))
  } else if (cmd === 'resolve-http') {
    const [did, ...maps] = rest
    const pin = Object.fromEntries(maps.map((m) => m.split('=')))
    const seen = []
    // fetch() cannot set the Host header, and the static server picks the test hostname from it, so go through node:http.
    const fetchLike = async (input) => {
      const u = new URL(String(input))
      seen.push(String(input))
      const ip = pin[u.hostname]
      if (!ip) throw new Error(`refusing to fetch ${u.hostname}: not a mapped local test name`)
      return new Promise((resolve, reject) => {
        const rq = httpRequest({ host: ip, port: u.port || 80, path: u.pathname + u.search, method: 'GET', headers: { host: u.host } }, (res) => {
          const chunks = []
          res.on('data', (c) => chunks.push(c))
          res.on('end', () => resolve(new Response(Buffer.concat(chunks), { status: res.statusCode, headers: res.headers })))
        })
        rq.on('error', reject); rq.end()
      })
    }
    const r = await resolveDID(did, { fetch: fetchLike, verifier, ...(version ? { versionNumber: Number(version) } : {}) })
    const m = r.didDocumentMetadata ?? {}
    out(r.didDocument
      ? { ok: true, scid: m.scid, versionId: m.versionId, versionNumber: Number(String(m.versionId).split('-')[0]), document: r.didDocument, id: r.didDocument.id, fetched: seen }
      : { ok: false, error: `${r.didResolutionMetadata?.error}: ${r.didResolutionMetadata?.problemDetails?.detail ?? ''}`, fetched: seen })
  } else if (cmd === 'probe') {
    // the library's NORMAL network path (global fetch), one json line per DID. Run only inside an empty network namespace under strace.
    for (const did of rest) {
      const r = await resolveDID(did, { verifier })
      console.log(JSON.stringify({ did, ok: !!r.didDocument, error: r.didDocument ? null : `${r.didResolutionMetadata?.error}: ${r.didResolutionMetadata?.problemDetails?.detail ?? ''}`.slice(0, 240) }))
    }
  } else if (cmd === 'move') {
    const [dir, toHost] = rest
    const keys = readJson(`${dir}/keys.json`)
    const { newIdentity } = await import('../../src/shared/did.js')
    const { fromHex, ed25519, multibase } = await import('../../src/shared/crypto.js')
    const { prepareDataForSigning } = await import('didwebvh-ts')
    const id = newIdentity(fromHex(keys.updateKeySeedHex))
    const mk = keys.updateKey
    const signer = { getVerificationMethodId: () => `did:key:${mk}#${mk}`, async sign ({ document, proof }) { return { proofValue: multibase(ed25519.sign(await prepareDataForSigning(document, proof), id.seed)) } } }
    const log = readLog(`${dir}/did.jsonl`)
    const witnessProofs = readJson(`${dir}/did-witness.json`)
    const last = Date.parse(log.at(-1).versionTime)
    const r = await updateDID({ log, signer, verifier, address: toHost, witnessProofs, updated: new Date(Math.max(Date.now() - 1000, last + 1000)).toISOString().replace(/\.\d+Z$/, 'Z') })
    ensureDir(`${dir}-moved`)
    // Witnesses must also approve the move entry (the 1-of-1 rule is active): w1 signs.
    const { signWitnessProofEntry } = await import('didwebvh-ts')
    const w1 = newIdentity(fromHex(keys.witnesses[0]))
    const wmk = w1.did.slice('did:key:'.length)
    const wsigner = { getVerificationMethodId: () => `${w1.did}#${wmk}`, async sign ({ document, proof }) { return { proofValue: multibase(ed25519.sign(await prepareDataForSigning(document, proof), w1.seed)) } } }
    const e = await signWitnessProofEntry({ trustedLog: log, candidateLog: r.log, witnessSigner: wsigner, witnessProofs, verifier })
    writeFileSync(`${dir}-moved/did.jsonl`, logText(r.log))
    writeJson(`${dir}-moved/did-witness.json`, [...witnessProofs, e])
    out({ ok: true, did: r.did, entries: r.log.length })
  } else {
    out({ ok: false, error: 'usage: create-log | resolve-file | resolve-http | move' })
  }
} catch (e) {
  out({ ok: false, error: `threw: ${e?.message ?? e}` })
}
