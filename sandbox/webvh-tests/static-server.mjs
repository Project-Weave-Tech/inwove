#!/usr/bin/env node
// A static server for the job's own test files, 127.0.0.1 only: GET /.well-known/<file> is served from <root>/<hostname>/.well-known/<file>
// (the Host header picks the directory, so one server stands for many test hostnames). Prints the port on its first line.
// Every request is appended to <log> (default <root>/../requests.jsonl). Usage: node static-server.mjs <root> [log]
import { createServer } from 'node:http'
import { appendFileSync, existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'

const root = resolve(process.argv[2] ?? 'www')
const log = process.argv[3] ?? join(root, '..', 'requests.jsonl')
const server = createServer((req, res) => {
  const host = String(req.headers.host ?? '').replace(/:\d+$/, '').toLowerCase()
  let rel = '/'
  try { rel = decodeURIComponent((req.url ?? '/').split('?')[0]) } catch { /* keep / */ }
  const file = join(root, host, rel)
  const ok = /^[a-z0-9.-]+$/.test(host) && resolve(file).startsWith(root + '/') && existsSync(file)
  appendFileSync(log, JSON.stringify({ host, path: rel, status: ok ? 200 : 404 }) + '\n')
  if (!ok) { res.writeHead(404); res.end('not found'); return }
  res.writeHead(200, { 'content-type': 'application/octet-stream' })
  res.end(readFileSync(file))
})
server.listen(0, '127.0.0.1', () => console.log(server.address().port))
