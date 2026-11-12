#!/usr/bin/env node
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

/*
 * Loads the built entry points the way Payload's CLI (`payload migrate`, `generate:importmap`) and
 * job runner do: plain Node, no bundler. Run after `pnpm build`.
 */
const expected = {
  '': [
    'OIDC_FIELDS',
    'OIDC_SYNC_CONTEXT',
    'PUBLIC_STATE_KEY',
    'RECONCILE_HEARTBEAT_KEY',
    'RECONCILE_TASK_SLUG',
    'authentikSource',
    'clearLinkingSnapshot',
    'findUserReferences',
    'oidcPlugin',
    'reconcileUsers',
    'removeUser',
    'roleForGroups',
    'roleTableGroups',
    'syncWriteOnly',
    'takeLinkingSnapshot',
  ],
  '/rsc': ['OidcLoginButton'],
  '/testing': ['startFakeProvider'],
}

for (const [subpath, names] of Object.entries(expected)) {
  const module = await import(`@signal58/payload-oidc${subpath}`)
  assert.deepEqual(Object.keys(module).sort(), [...names].sort(), `exports of .${subpath}`)
  for (const name of names) assert.notEqual(module[name], undefined, `.${subpath} ${name}`)
}

// The client entry imports @payloadcms/ui, which only a bundler can load (it imports CSS), so
// check it resolves and keeps its directive instead of importing it.
const client = readFileSync(
  fileURLToPath(import.meta.resolve('@signal58/payload-oidc/client')),
  'utf8',
)
assert.match(client, /^'use client';\n/, "'use client' is first in the client entry")
assert.doesNotMatch(client, /from '\.{1,2}\//, 'the client entry has no relative imports')

console.log('dist: every entry point resolves and loads in Node.')
