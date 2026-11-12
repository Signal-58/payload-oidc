import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { MongoClient } from 'mongodb'
import {
  buildConfig,
  getPayload,
  handleEndpoints,
  type Payload,
  type SanitizedConfig,
} from 'payload'
import { expect } from 'vitest'

import type { OidcPluginOptions } from '../options'
import { oidcPlugin } from '../plugin'
import { authCollectionModel, OIDC_SYNC_CONTEXT } from '../store'
import { startFakeProvider, type FakeUser } from './fake-provider'

/*
 * Shared setup for the end-to-end suites: a real Payload on MongoDB with the plugin, and a fake
 * OIDC provider. Opt in with PAYLOAD_OIDC_DATABASE_URI pointing at a replica set database the
 * suites may own, for example
 * mongodb://127.0.0.1:27017/payload_oidc_test?directConnection=true
 * Each suite uses its own database (the URI's name plus a suffix) and refuses one that holds
 * anything but its own data.
 */
export const databaseUri = process.env.PAYLOAD_OIDC_DATABASE_URI?.trim()
export const SERVER_URL = 'http://localhost:3000'
export const CLIENT = { id: 'test-client', secret: 'test-client-secret' }
export const BREAK_GLASS = 'break-glass@example.test'
export const ROLE_TABLE = {
  superadmin: ['cms-test-superadmin', 'org-admins'],
  admin: ['cms-test-admin'],
  editor: ['cms-test-editor'],
}
const SENTINEL = 'payload_oidc_harness'

export type Harness = Awaited<ReturnType<typeof startHarness>>

export const startHarness = async ({
  clock,
  key,
  plugin,
}: {
  clock: () => Date
  /** Names the suite's database and Payload instance. */
  key: string
  /** Overrides of the default plugin options; `issuer: undefined` turns the plugin off. */
  plugin?: Partial<OidcPluginOptions>
}) => {
  const url = new URL(databaseUri!)
  url.pathname = `${url.pathname.replace(/\/$/, '') || '/payload_oidc_test'}_${key}`
  const mongo = await MongoClient.connect(url.href)
  const db = mongo.db()
  const existing = (await db.listCollections().toArray()).map(({ name }) => name)
  if (existing.length > 0 && !existing.includes(SENTINEL)) {
    throw new Error(`${db.databaseName} holds data this suite doesn't own; refusing to use it.`)
  }
  await db.dropDatabase()
  await db.collection(SENTINEL).insertOne({ owner: 'payload-oidc' })

  const provider = await startFakeProvider(CLIENT)
  const pluginOptions: OidcPluginOptions = {
    allowInsecureIssuer: true,
    breakGlassEmail: BREAK_GLASS,
    clientId: CLIENT.id,
    clientSecret: CLIENT.secret,
    issuer: provider.state.issuer,
    additionalServerURLs: ['https://alt.example.test'],
    linkByEmailUntil: '2026-12-01',
    roles: { field: 'roles', table: ROLE_TABLE },
    ...plugin,
  }
  const config: Promise<SanitizedConfig> = buildConfig({
    collections: [
      {
        slug: 'users',
        auth: true,
        fields: [
          { name: 'firstName', type: 'text', required: true },
          { name: 'lastName', type: 'text', required: true },
          { name: 'bio', type: 'text' },
          {
            name: 'roles',
            type: 'select',
            hasMany: true,
            options: ['superadmin', 'admin', 'editor'],
          },
        ],
      },
      // Something that refers to users, so removal has to anonymise rather than delete.
      {
        slug: 'posts',
        fields: [
          { name: 'author', type: 'relationship', relationTo: 'users' },
          {
            name: 'credits',
            type: 'array',
            fields: [{ name: 'person', type: 'relationship', relationTo: 'users' }],
          },
          { name: 'owner', type: 'relationship', relationTo: ['users', 'posts'] },
        ],
        versions: { drafts: true },
      },
    ],
    db: mongooseAdapter({ url: url.href }),
    plugins: [oidcPlugin(pluginOptions, { clock })],
    secret: 'payload-oidc-test-secret',
    serverURL: SERVER_URL,
    telemetry: false,
    typescript: { autoGenerate: false },
  })
  const payload: Payload = await getPayload({ config, key: `payload-oidc-${key}` })
  // Create the collections up front: creating one inside a transaction fails with "catalog
  // changes" on a freshly dropped database.
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

  const cacheKey = `payload-oidc-${key}`
  const request = (path: string, init?: RequestInit) =>
    handleEndpoints({
      config,
      payloadInstanceCacheKey: cacheKey,
      request: new Request(`${SERVER_URL}${path}`, init),
    })

  /** Runs the whole browser round trip for `user`; returns the callback's outcome. */
  const signIn = async (user: FakeUser, redirect?: string) => {
    provider.state.nextUser = user
    const authorize = await request(
      `/api/users/oidc/authorize${redirect === undefined ? '' : `?redirect=${encodeURIComponent(redirect)}`}`,
    )
    expect(authorize.status).toBe(302)
    const transactionSetCookie = authorize.headers.getSetCookie()[0]
    const transactionCookie = transactionSetCookie.split(';')[0]
    const atProvider = await fetch(authorize.headers.get('location') ?? '', { redirect: 'manual' })
    expect(atProvider.status).toBe(302)
    const callbackUrl = new URL(atProvider.headers.get('location') ?? '')
    const callback = await handleEndpoints({
      config,
      payloadInstanceCacheKey: cacheKey,
      request: new Request(callbackUrl, { headers: { cookie: transactionCookie } }),
    })
    const cookies = callback.headers.getSetCookie()
    const token = cookies
      .map((cookie) => cookie.split(';')[0])
      .find((cookie) => cookie.startsWith('payload-token='))
    return {
      callback,
      callbackUrl,
      cookies,
      location: callback.headers.get('location') ?? '',
      token,
      transactionCookie,
      transactionSetCookie,
    }
  }

  /** Creates a user the way an existing (pre-plugin) account would exist. */
  const createUser = async (
    email: string,
    { linkable = false, password = 'password-123', roles = ['editor'] } = {},
  ) => {
    const created = await payload.create({
      collection: 'users',
      context: { [OIDC_SYNC_CONTEXT]: true },
      data: { email, firstName: 'Old', lastName: 'Name', password, roles } as never,
      overrideAccess: true,
    })
    if (linkable) {
      await authCollectionModel(payload, 'users').updateOne(
        { _id: created.id },
        { $set: { oidcLinkable: true } },
      )
    }
    return created as unknown as { email: string; id: string }
  }

  const clear = () =>
    payload.delete({
      collection: 'users',
      context: { [OIDC_SYNC_CONTEXT]: true },
      overrideAccess: true,
      where: { id: { exists: true } },
    })

  const stop = async () => {
    await payload.destroy()
    await provider.close()
    await db.dropDatabase()
    await mongo.close()
  }

  return {
    clear,
    config,
    createUser,
    payload,
    pluginOptions,
    provider,
    request,
    signIn,
    stop,
    users: () => authCollectionModel(payload, 'users'),
  }
}

/** A JSON request with the browser's Origin, which Payload's CSRF check needs for cookie auth. */
export const jsonRequest = (method: string, body: unknown, cookie?: string): RequestInit => ({
  body: body === undefined ? undefined : JSON.stringify(body),
  headers: {
    'content-type': 'application/json',
    origin: SERVER_URL,
    ...(cookie ? { cookie } : {}),
  },
  method,
})

export const tokenCookie = (response: Response): string | undefined =>
  response.headers
    .getSetCookie()
    .map((cookie) => cookie.split(';')[0])
    .find((cookie) => cookie.startsWith('payload-token=') && cookie !== 'payload-token=')

/** The `exp` claim of a Payload token cookie, in seconds since the epoch. */
export const tokenExp = (cookie: string): number =>
  JSON.parse(Buffer.from(cookie.split('=')[1].split('.')[1], 'base64url').toString()).exp
