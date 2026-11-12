import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoClient, type Db } from 'mongodb'
import { buildConfig, getPayload, handleEndpoints, type Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import type { ReconcileSource } from '../src/options'
import { oidcPlugin, PUBLIC_STATE_KEY, type OidcPublicState } from '../src/plugin'
import { startFakeProvider } from '../src/test/fake-provider'
import { CLIENT, databaseUri, ROLE_TABLE, SERVER_URL } from '../src/test/harness'

/*
 * Sign-in with Payload's REST API on a non-default route (`routes.api: '/payload'`): every
 * plugin endpoint, the redirect URI registered with the provider and the transaction cookie's
 * path follow the route. The shared harness always uses `/api`, so this suite builds its own
 * Payload; it opts in and owns its database the same way (see src/test/harness.ts).
 */
const API = '/payload'
const KEY = 'routes_api'
const SENTINEL = 'payload_oidc_harness'

const source: ReconcileSource = {
  cron: '*/15 * * * *',
  fetchGroupMembers: async (groups) => new Map(groups.map((group) => [group, []])),
  queue: 'oidc-reconcile',
}

describe.skipIf(!databaseUri)('payload-oidc with routes.api set to /payload', () => {
  let db: Db
  let mongo: MongoClient
  let payload: Payload
  let provider: Awaited<ReturnType<typeof startFakeProvider>>
  let config: ReturnType<typeof buildConfig>

  const request = (path: string, init?: RequestInit) =>
    handleEndpoints({
      config,
      payloadInstanceCacheKey: `payload-oidc-${KEY}`,
      request: new Request(path.startsWith('http') ? path : `${SERVER_URL}${path}`, init),
    })

  beforeAll(async () => {
    const url = new URL(databaseUri!)
    url.pathname = `${url.pathname.replace(/\/$/, '') || '/payload_oidc_test'}_${KEY}`
    mongo = await MongoClient.connect(url.href)
    db = mongo.db()
    const existing = (await db.listCollections().toArray()).map(({ name }) => name)
    if (existing.length > 0 && !existing.includes(SENTINEL)) {
      throw new Error(`${db.databaseName} holds data this suite doesn't own; refusing to use it.`)
    }
    await db.dropDatabase()
    await db.collection(SENTINEL).insertOne({ owner: 'payload-oidc' })

    provider = await startFakeProvider(CLIENT)
    config = buildConfig({
      collections: [
        {
          slug: 'users',
          auth: true,
          fields: [
            { name: 'firstName', type: 'text', required: true },
            { name: 'lastName', type: 'text', required: true },
            {
              name: 'roles',
              type: 'select',
              hasMany: true,
              options: ['superadmin', 'admin', 'editor'],
            },
          ],
        },
      ],
      db: mongooseAdapter({ url: url.href }),
      plugins: [
        oidcPlugin({
          allowInsecureIssuer: true,
          clientId: CLIENT.id,
          clientSecret: CLIENT.secret,
          issuer: provider.state.issuer,
          reconcile: source,
          roles: { field: 'roles', table: ROLE_TABLE },
        }),
      ],
      routes: { api: API },
      secret: 'payload-oidc-test-secret',
      serverURL: SERVER_URL,
      telemetry: false,
      typescript: { autoGenerate: false },
    })
    payload = await getPayload({ config, key: `payload-oidc-${KEY}` })
    // As in the harness: create the collections before anything writes inside a transaction.
    const models = Object.values(
      (
        payload.db as unknown as {
          collections: Record<
            string,
            { createCollection: () => Promise<unknown>; init: () => Promise<unknown> }
          >
        }
      ).collections,
    )
    for (const model of models) {
      await model.createCollection()
      await model.init()
    }
  })

  afterAll(async () => {
    await payload?.destroy()
    await provider?.close()
    await db?.dropDatabase()
    await mongo?.close()
  })

  it('points the login button at the authorize endpoint under the route', () => {
    const state = payload.config.custom?.[PUBLIC_STATE_KEY] as OidcPublicState
    expect(state.authorizePath).toBe(`${API}/users/oidc/authorize`)
  })

  it('signs in with the callback, redirect URI and cookie path under the route', async () => {
    provider.state.nextUser = {
      email: 'ada@example.test',
      email_verified: true,
      family_name: 'Lovelace',
      given_name: 'Ada',
      groups: ['cms-test-editor'],
      sub: 'sub-ada',
    }
    const authorize = await request(`${API}/users/oidc/authorize`)
    expect(authorize.status).toBe(302)
    const atProviderUrl = new URL(authorize.headers.get('location') ?? '')
    expect(atProviderUrl.searchParams.get('redirect_uri')).toBe(
      `${SERVER_URL}${API}/users/oidc/callback`,
    )
    const transactionSetCookie = authorize.headers.getSetCookie()[0]
    expect(transactionSetCookie).toMatch(new RegExp(`Path=${API}/users/oidc/callback;`))

    const atProvider = await fetch(atProviderUrl, { redirect: 'manual' })
    expect(atProvider.status).toBe(302)
    const callbackUrl = new URL(atProvider.headers.get('location') ?? '')
    expect(callbackUrl.pathname).toBe(`${API}/users/oidc/callback`)

    const callback = await request(callbackUrl.href, {
      headers: { cookie: transactionSetCookie.split(';')[0] },
    })
    expect(callback.status).toBe(302)
    expect(callback.headers.get('location')).toBe('/admin')
    const token = callback.headers
      .getSetCookie()
      .map((cookie) => cookie.split(';')[0])
      .find((cookie) => cookie.startsWith('payload-token=') && cookie !== 'payload-token=')
    expect(token).toBeDefined()

    const auth = await payload.auth({
      headers: new Headers({ cookie: token!, origin: SERVER_URL }),
    })
    expect(auth.user).toMatchObject({ email: 'ada@example.test', roles: ['editor'] })
  })

  it('serves the removal and health endpoints under the route, not under /api', async () => {
    expect((await request(`${API}/users/oidc/remove/someone`, { method: 'POST' })).status).toBe(401)
    // No reconcile has run yet, so the heartbeat is missing: unhealthy, but answered.
    expect((await request(`${API}/users/oidc/reconcile/health`)).status).toBe(503)

    for (const path of ['authorize', 'callback', 'reconcile/health']) {
      expect((await request(`/api/users/oidc/${path}`)).status).toBe(404)
    }
  })
})
