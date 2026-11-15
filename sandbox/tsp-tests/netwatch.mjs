#!/usr/bin/env node
// ref/09 §2.6 `netwatch`, roundtrip half: runs roundtrip.mjs (Rust peer included) with no network at all, then
// proves the namespace really had none. Run it as: sudo unshare -n -- sudo -u "$USER" env PATH="$PATH" node netwatch.mjs <dir>
// The mediator half (an egress log of the mediator job) joins with the mediator job.
import { spawnSync } from 'node:child_process'
import { networkInterfaces } from 'node:os'
import { join } from 'node:path'
import { HERE, recorder } from './lib.mjs'

const results = process.argv[2] ?? 'results'
const R = recorder('netwatch')
const ifaces = Object.keys(networkInterfaces()).filter((n) => n !== 'lo')
R.check('no network interface but loopback', ifaces.length === 0, ifaces.join(', ') || 'lo only')
const dns = spawnSync('node', ['-e', "require('dns').lookup('registry.npmjs.org',(e)=>{console.log(e?e.code:'resolved');process.exit(e?0:1)})"], { encoding: 'utf8', timeout: 20_000 })
R.check('an outside name cannot be reached', dns.status === 0, dns.stdout.trim())
const off = join(results, 'offline')
const r = spawnSync('node', [join(HERE, 'roundtrip.mjs'), off], { encoding: 'utf8', timeout: 300_000, env: process.env })
process.stdout.write(r.stdout); process.stderr.write(r.stderr)
R.check('roundtrip succeeds with no network', r.status === 0, `exit ${r.status}, ${(r.stdout.match(/roundtrip: .*/) ?? [''])[0]}`)
process.exit(R.finish(results) ? 0 : 1)
