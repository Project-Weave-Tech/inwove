#!/usr/bin/env node
// Security 12144.3a: the entrypoint's --deny-file is the deny side of the 16.2(b) record (mediator-env-lists.json),
// one name per line, sorted, ending in a newline. Its sha256 is baked beside the entrypoint as mediator-deny.sha256,
// and the entrypoint refuses any deny file that doesn't hash to it (an empty or cut file must never pass).
// Usage: node mediator-deny-file.mjs [<record>] [<out>]   (writes <out> if given; always prints the sha256)
import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export function denyFileText(record) {
  return Object.keys(record.deny).sort().map((n) => `${n}\n`).join('');
}
export const sha256 = (text) => createHash('sha256').update(text).digest('hex');

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const recPath = process.argv[2] || new URL('./mediator-env-lists.json', import.meta.url).pathname;
  const text = denyFileText(JSON.parse(readFileSync(recPath, 'utf8')));
  if (process.argv[3]) writeFileSync(process.argv[3], text);
  console.log(sha256(text));
}
