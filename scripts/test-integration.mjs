#!/usr/bin/env node
import { spawnSync } from 'node:child_process'

/*
 * Runs the end-to-end sign-in suite against a local MongoDB replica set. The suite owns its
 * database (`payload_oidc_test` unless PAYLOAD_OIDC_DATABASE_URI says otherwise) and refuses one
 * that holds anything else.
 */
const host = process.env.PAYLOAD_OIDC_MONGO_HOST?.trim() || '127.0.0.1:27017'
const replicaSet = process.env.PAYLOAD_OIDC_REPLICA_SET?.trim()
const uri =
  process.env.PAYLOAD_OIDC_DATABASE_URI?.trim() ||
  `mongodb://${host}/payload_oidc_test?${replicaSet ? `replicaSet=${replicaSet}&` : ''}directConnection=true`

const result = spawnSync(
  'vitest',
  [
    'run',
    'src/plugin.integration.test.ts',
    'src/password-login.integration.test.ts',
    'src/reconcile.integration.test.ts',
    'test/routes-api.integration.test.ts',
  ],
  {
    env: { ...process.env, PAYLOAD_OIDC_DATABASE_URI: uri },
    shell: process.platform === 'win32',
    stdio: 'inherit',
  },
)
process.exit(result.status ?? 1)
