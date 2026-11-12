import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { resolveOptions } from './options'
import { pushSession, writeManagedFields } from './store'
import {
  AFTER_LINKING,
  BREAK_GLASS,
  databaseUri,
  jsonRequest,
  SERVER_URL,
  startHarness,
  tokenCookie,
  tokenExp,
  type Harness,
} from './test/harness'

/*
 * End-to-end sign-in, password sign-in off, against a real Payload on MongoDB and a fake OIDC
 * provider, with openid-client doing the real validation. See test/harness.ts for the opt-in.
 */
let now = new Date('2026-11-10T12:00:00Z')
const clock = () => now

const editor = (sub: string, email: string, extra: Record<string, unknown> = {}) => ({
  email,
  email_verified: true,
  groups: ['cms-test-editor'],
  sub,
  ...extra,
})

describe.skipIf(!databaseUri)('payload-oidc sign-in', () => {
  let h: Harness

  const userBySubject = (sub: string) =>
    h.payload
      .find({ collection: 'users', overrideAccess: true, where: { oidcSubject: { equals: sub } } })
      .then(({ docs }) => docs[0] as Record<string, unknown> | undefined)

  beforeAll(async () => {
    h = await startHarness({ clock, key: 'sign_in' })
  })

  afterAll(async () => {
    await h?.stop()
  })

  beforeEach(async () => {
    now = new Date()
    await h.clear()
  })

  it('creates the user at first sign-in, with a session Payload accepts', async () => {
    const result = await h.signIn(
      {
        email: 'Ada@Example.test',
        email_verified: true,
        family_name: 'Lovelace',
        given_name: 'Ada',
        groups: ['cms-test-editor', 'unrelated'],
        sub: 'sub-ada',
      },
      '/admin/collections/users',
    )
    expect(result.location).toBe('/admin/collections/users')
    expect(result.token).toBeDefined()
    const user = await userBySubject('sub-ada')
    expect(user).toMatchObject({
      email: 'ada@example.test',
      firstName: 'Ada',
      lastName: 'Lovelace',
      roles: ['editor'],
    })
    const auth = await h.payload.auth({
      headers: new Headers({ cookie: result.token!, origin: SERVER_URL }),
    })
    expect(auth.user?.id).toBe(user?.id)
    expect(h.payload.collections.users.config.auth.tokenExpiration).toBe(8 * 3600)
    // The transaction cookie was scoped, HTTP-only and Lax, and the callback cleared it.
    expect(result.transactionSetCookie).toMatch(/Path=\/api\/users\/oidc\/callback/)
    expect(result.transactionSetCookie).toMatch(/Max-Age=600; HttpOnly; SameSite=Lax/)
    expect(result.cookies[0]).toMatch(/payload-oidc=;.*Max-Age=0/)
  })

  it('gives the highest role, follows role changes, and fills a missing family name', async () => {
    await h.signIn(
      editor('sub-b', 'b@example.test', { groups: ['cms-test-editor', 'org-admins'], name: 'Bea' }),
    )
    expect(await userBySubject('sub-b')).toMatchObject({
      firstName: 'Bea',
      lastName: '-',
      roles: ['superadmin'],
    })
    await h.signIn(editor('sub-b', 'b2@example.test', { groups: ['cms-test-admin'], name: 'Bea' }))
    expect(await userBySubject('sub-b')).toMatchObject({
      email: 'b2@example.test',
      roles: ['admin'],
    })
  })

  it('refuses a user with no role and disables an existing one', async () => {
    await h.signIn(editor('sub-c', 'c@example.test'))
    const refused = await h.signIn(editor('sub-c', 'c@example.test', { groups: ['unrelated'] }))
    expect(refused.location).toBe('/admin/login?oidc_error=no_role')
    expect(refused.token).toBeUndefined()
    const stored = await h.users().findOne({ oidcSubject: 'sub-c' }).lean()
    expect(stored).toMatchObject({ roles: [], sessions: [] })
    expect(stored?.oidcDisabledAt).toBeInstanceOf(Date)
    // A role again re-enables the account.
    await h.signIn(editor('sub-c', 'c@example.test'))
    expect((await h.users().findOne({ oidcSubject: 'sub-c' }).lean())?.oidcDisabledAt).toBeNull()
  })

  it('refuses an unverified email and creates nobody', async () => {
    const refused = await h.signIn(editor('sub-d', 'd@example.test', { email_verified: false }))
    expect(refused.location).toBe('/admin/login?oidc_error=email_not_verified')
    expect(await userBySubject('sub-d')).toBeUndefined()
  })

  it('links a snapshot user by email, rotating the password and ending old sessions', async () => {
    const created = await h.createUser('eve@example.test', {
      linkable: true,
      password: 'old-password-1',
    })
    await h.users().updateOne(
      { _id: created.id },
      {
        $set: {
          sessions: [
            { createdAt: now, expiresAt: new Date(now.getTime() + 3600e3), id: 'old-session' },
          ],
        },
      },
    )
    const before = await h.users().findOne({ _id: created.id }).lean()

    await h.signIn(
      editor('sub-eve', 'eve@example.test', {
        family_name: 'New',
        given_name: 'Eve',
        groups: ['cms-test-admin'],
      }),
    )

    const after = await h.users().findOne({ _id: created.id }).lean()
    expect(after).toMatchObject({ lastName: 'New', oidcSubject: 'sub-eve', roles: ['admin'] })
    expect(after?.oidcLinkable).toBeUndefined()
    expect(after?.hash).not.toBe(before?.hash)
    expect(after?.salt).not.toBe(before?.salt)
    expect(after?.sessions?.map(({ id }) => id)).toEqual([expect.not.stringMatching('old-session')])
  })

  it('never takes over an account that is not linkable, or after the cut-off', async () => {
    await h.createUser('frank@example.test', { roles: ['superadmin'] })
    const refused = await h.signIn(editor('sub-attacker', 'frank@example.test'))
    expect(refused.location).toBe('/admin/login?oidc_error=account_conflict')

    await h.users().updateOne({ email: 'frank@example.test' }, { $set: { oidcLinkable: true } })
    now = AFTER_LINKING
    const late = await h.signIn(editor('sub-frank', 'frank@example.test'))
    expect(late.location).toBe('/admin/login?oidc_error=account_conflict')
    expect(await userBySubject('sub-frank')).toBeUndefined()
  })

  it('never links or syncs the break-glass account, even if the snapshot marked it', async () => {
    const breakGlass = await h.createUser(BREAK_GLASS, { linkable: true, roles: ['superadmin'] })
    const before = await h.users().findOne({ _id: breakGlass.id }).lean()
    const refused = await h.signIn(editor('sub-bg', BREAK_GLASS))
    expect(refused.location).toBe('/admin/login?oidc_error=account_conflict')
    const after = await h.users().findOne({ _id: breakGlass.id }).lean()
    expect(after).toMatchObject({ hash: before?.hash, oidcLinkable: true, roles: ['superadmin'] })
    expect(after?.oidcSubject).toBeUndefined()
  })

  it('lets two concurrent first sign-ins for one subject both succeed, with one user', async () => {
    const [first, second] = await Promise.all([
      h.signIn(editor('sub-twice', 'twice@example.test')),
      h.signIn(editor('sub-twice', 'twice@example.test')),
    ])
    expect([first.location, second.location]).toEqual(['/admin', '/admin'])
    const { totalDocs } = await h.payload.count({
      collection: 'users',
      overrideAccess: true,
      where: { oidcSubject: { equals: 'sub-twice' } },
    })
    expect(totalDocs).toBe(1)
  })

  it('refuses a provider email that another user already has', async () => {
    await h.createUser('taken@example.test')
    await h.signIn(editor('sub-g2', 'g2@example.test'))
    const conflict = await h.signIn(editor('sub-g2', 'taken@example.test'))
    expect(conflict.location).toBe('/admin/login?oidc_error=account_conflict')
    expect(await userBySubject('sub-g2')).toMatchObject({ email: 'g2@example.test' })
  })

  it('refuses a missing transaction, a state mismatch and a forged ID token', async () => {
    const missing = await h.request('/api/users/oidc/callback?code=x&state=y')
    expect(missing.headers.get('location')).toBe('/admin/login?oidc_error=expired')

    // A valid transaction cookie with another sign-in's state.
    h.provider.state.nextUser = editor('sub-s', 's@example.test')
    const authorize = await h.request('/api/users/oidc/authorize')
    const atProvider = await fetch(authorize.headers.get('location') ?? '', { redirect: 'manual' })
    const callbackUrl = new URL(atProvider.headers.get('location') ?? '')
    callbackUrl.searchParams.set('state', 'not-the-state')
    const mismatch = await h.request(`${callbackUrl.pathname}${callbackUrl.search}`, {
      headers: { cookie: authorize.headers.getSetCookie()[0].split(';')[0] },
    })
    expect(mismatch.headers.get('location')).toBe('/admin/login?oidc_error=provider')
    expect(await userBySubject('sub-s')).toBeUndefined()

    h.provider.state.forgeSignature = true
    try {
      const forged = await h.signIn(editor('sub-g', 'g@example.test'))
      expect(forged.location).toBe('/admin/login?oidc_error=provider')
      expect(await userBySubject('sub-g')).toBeUndefined()
    } finally {
      h.provider.state.forgeSignature = false
    }
  })

  it('signs in on an allowed second origin, and never on one a header invents', async () => {
    const authorizeOn = async (headers: Record<string, string>) => {
      const response = await h.request('/api/users/oidc/authorize', { headers })
      const location = new URL(response.headers.get('location') ?? '')
      return {
        cookie: response.headers.getSetCookie()[0],
        redirectUri: location.searchParams.get('redirect_uri'),
      }
    }
    const alt = await authorizeOn({
      'x-forwarded-host': 'alt.example.test',
      'x-forwarded-proto': 'https',
    })
    expect(alt.redirectUri).toBe('https://alt.example.test/api/users/oidc/callback')
    expect(alt.cookie).toMatch(/; Secure$/)
    const spoofed = await authorizeOn({
      'x-forwarded-host': 'evil.example',
      'x-forwarded-proto': 'https',
    })
    expect(spoofed.redirectUri).toBe(`${SERVER_URL}/api/users/oidc/callback`)
    expect(spoofed.cookie).not.toMatch(/Secure/)
  })

  it('only returns to paths under the admin route', async () => {
    for (const redirect of [
      '//evil.example/admin',
      'https://evil.example/admin',
      '/\\evil.example',
      '/api/users',
      '/admin/../api',
    ]) {
      const result = await h.signIn(editor('sub-h', 'h@example.test'), redirect)
      expect(result.location).toBe('/admin')
    }
  })

  it('never adds a session to a disabled user, and never rewrites sessions when syncing', async () => {
    await h.signIn(editor('sub-i', 'i@example.test'))
    const stored = await h.users().findOne({ oidcSubject: 'sub-i' }).lean()
    const options = resolveOptions(h.pluginOptions)
    await h.users().updateOne({ _id: stored?._id }, { $set: { oidcDisabledAt: now, sessions: [] } })
    expect(await pushSession(h.payload, options, stored?._id, 'sub-i', now)).toBeUndefined()
    expect((await h.users().findOne({ _id: stored?._id }).lean())?.sessions).toEqual([])

    // The profile write touches only its own paths, so sessions a disable cleared stay cleared.
    expect(
      await writeManagedFields(h.payload, options, stored?._id, 'sub-i', { firstName: 'I' }, now),
    ).toBe(true)
    expect((await h.users().findOne({ _id: stored?._id }).lean())?.sessions).toEqual([])
    // And it never writes to a user relinked to another subject.
    expect(
      await writeManagedFields(
        h.payload,
        options,
        stored?._id,
        'sub-other',
        { firstName: 'X' },
        now,
      ),
    ).toBe(false)
  })

  it('ignores non-sync updates of the provider-owned fields, and refuses passwords', async () => {
    const admin = await h.signIn(
      editor('sub-admin', 'admin@example.test', { groups: ['org-admins'] }),
    )
    const target = await h.createUser('target@example.test')
    const patched = await h.request(
      `/api/users/${target.id}`,
      jsonRequest(
        'PATCH',
        { bio: 'kept', email: 'evil@example.test', firstName: 'Evil', roles: ['superadmin'] },
        admin.token,
      ),
    )
    expect(patched.status).toBe(200)
    expect(await h.users().findOne({ _id: target.id }).lean()).toMatchObject({
      bio: 'kept',
      email: 'target@example.test',
      firstName: 'Old',
      roles: ['editor'],
    })
    const password = await h.request(
      `/api/users/${target.id}`,
      jsonRequest('PATCH', { password: 'new-password-1' }, admin.token),
    )
    expect(password.status).toBe(403)
  })

  it('refuses password operations through REST, the Local API and first-register', async () => {
    await h.createUser(BREAK_GLASS, { roles: ['superadmin'] })
    for (const [path, body] of [
      ['/api/users/login', { email: BREAK_GLASS, password: 'password-123' }],
      ['/api/users/forgot-password', { email: BREAK_GLASS }],
      ['/api/users/reset-password', { password: 'x-123456', token: 'anything' }],
      ['/api/users/unlock', { email: BREAK_GLASS }],
      [
        '/api/users/first-register',
        { email: 'new@example.test', firstName: 'N', lastName: 'U', password: 'password-123' },
      ],
      [
        '/api/users',
        { email: 'new@example.test', firstName: 'N', lastName: 'U', password: 'password-123' },
      ],
    ] as const) {
      const response = await h.request(path, jsonRequest('POST', body))
      expect(response.status, path).toBe(403)
    }
    await expect(
      h.payload.login({
        collection: 'users',
        data: { email: BREAK_GLASS, password: 'password-123' },
      }),
    ).rejects.toThrow(/turned off/)
  })

  it('caps a refreshed token at the absolute limit, and refuses refresh after it', async () => {
    const signedIn = await h.signIn(editor('sub-r', 'r@example.test'))
    const stored = await h.users().findOne({ oidcSubject: 'sub-r' }).lean()
    const sid = stored!.sessions![0].id

    // Ten hours in: two hours remain, so the refreshed token lasts two hours, not eight.
    await h
      .users()
      .updateOne(
        { _id: stored?._id, 'sessions.id': sid },
        { $set: { 'sessions.$.createdAt': new Date(now.getTime() - 10 * 3600e3) } },
      )
    const refreshed = await h.request(
      '/api/users/refresh-token',
      jsonRequest('POST', undefined, signedIn.token),
    )
    expect(refreshed.status).toBe(200)
    const exp = tokenExp(tokenCookie(refreshed)!)
    expect(exp - Date.now() / 1000).toBeGreaterThan(2 * 3600 - 60)
    expect(exp - Date.now() / 1000).toBeLessThanOrEqual(2 * 3600 + 1)

    await h
      .users()
      .updateOne(
        { _id: stored?._id, 'sessions.id': sid },
        { $set: { 'sessions.$.createdAt': new Date(now.getTime() - 13 * 3600e3) } },
      )
    const late = await h.request(
      '/api/users/refresh-token',
      jsonRequest('POST', undefined, signedIn.token),
    )
    expect(late.status).toBe(403)
  })
})
