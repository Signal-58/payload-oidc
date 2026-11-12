import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import {
  BREAK_GLASS,
  databaseUri,
  jsonRequest,
  startHarness,
  tokenCookie,
  type Harness,
} from './test/harness'

/*
 * The break-glass flag (`passwordLogin: true`) and the plugin switched off, through Payload's real
 * REST routes. See test/harness.ts for the opt-in.
 */
let now = new Date()
const clock = () => now

describe.skipIf(!databaseUri)('payload-oidc with password sign-in on', () => {
  let h: Harness

  beforeAll(async () => {
    h = await startHarness({ clock, key: 'password_on', plugin: { passwordLogin: true } })
  })
  afterAll(async () => {
    await h?.stop()
  })
  beforeEach(async () => {
    now = new Date()
    await h.clear()
  })

  const login = (email: string, password = 'password-123') =>
    h.request('/api/users/login', jsonRequest('POST', { email, password }))

  it('lets the break-glass account register itself on an empty database, without plugin fields', async () => {
    const response = await h.request(
      '/api/users/first-register',
      jsonRequest('POST', {
        email: BREAK_GLASS,
        firstName: 'Break',
        lastName: 'Glass',
        oidcLinkable: true,
        oidcSubject: 'sub-sneaky',
        password: 'password-123',
        roles: ['superadmin'],
      }),
    )
    expect(response.status).toBe(200)
    const stored = await h.users().findOne({ email: BREAK_GLASS }).lean()
    expect(stored?.oidcSubject).toBeUndefined()
    expect(stored?.oidcLinkable).toBeUndefined()

    // A second registration, or anyone else's, is refused.
    const again = await h.request(
      '/api/users/first-register',
      jsonRequest('POST', {
        email: 'x@example.test',
        firstName: 'X',
        lastName: 'Y',
        password: 'password-123',
      }),
    )
    expect(again.status).toBe(403)
  })

  it('opens password sign-in to the break-glass account and unlinked snapshot users only', async () => {
    await h.createUser(BREAK_GLASS, { roles: ['superadmin'] })
    await h.createUser('snapshot@example.test', { linkable: true })
    await h.createUser('linked@example.test', { linkable: false })

    expect((await login('Break-Glass@Example.test')).status).toBe(200)
    expect((await login('snapshot@example.test')).status).toBe(200)

    // Not allowed: the same answer as an unknown address or a wrong password, so nobody can tell
    // which addresses may use one.
    const notAllowed = await login('linked@example.test')
    const unknown = await login('nobody@example.test')
    const wrong = await login(BREAK_GLASS, 'wrong-password')
    expect([notAllowed.status, unknown.status, wrong.status]).toEqual([401, 401, 401])
    expect(await notAllowed.json()).toEqual(await unknown.json())

    // A stray username on an email-only collection is ignored, as Payload ignores it.
    const stray = await h.request(
      '/api/users/login',
      jsonRequest('POST', { email: BREAK_GLASS, password: 'password-123', username: 'someone' }),
    )
    expect(stray.status).toBe(200)

    // After the cut-off only the break-glass account remains.
    now = new Date('2026-12-02T00:00:00Z')
    expect((await login('snapshot@example.test')).status).toBe(401)
    expect((await login(BREAK_GLASS)).status).toBe(200)
  })

  it('answers a forgotten password the same way for everyone, and resets only allowed users', async () => {
    await h.createUser(BREAK_GLASS, { roles: ['superadmin'] })
    await h.createUser('linked@example.test')
    for (const email of [BREAK_GLASS, 'linked@example.test', 'nobody@example.test']) {
      const response = await h.request('/api/users/forgot-password', jsonRequest('POST', { email }))
      expect(response.status, email).toBe(200)
    }
    const reset = async (email: string) => {
      const token = (await h.users().findOne({ email }).lean())?.resetPasswordToken
      return h.request(
        '/api/users/reset-password',
        jsonRequest('POST', { password: 'reset-password-1', token }),
      )
    }
    expect((await reset(BREAK_GLASS)).status).toBe(200)
    // Payload stored a token (it reads the address before the hook) but sent no email, and the
    // token can't be used.
    expect((await reset('linked@example.test')).status).toBe(403)
  })

  it('lets only the break-glass account change its own password', async () => {
    const breakGlass = await h.createUser(BREAK_GLASS, { roles: ['superadmin'] })
    const other = await h.createUser('snapshot@example.test', { linkable: true })
    const cookie = tokenCookie(await login(BREAK_GLASS))
    const own = await h.request(
      `/api/users/${breakGlass.id}`,
      jsonRequest('PATCH', { password: 'new-password-1' }, cookie),
    )
    expect(own.status).toBe(200)
    expect((await login(BREAK_GLASS, 'new-password-1')).status).toBe(200)
    // Not even the break-glass account may set someone else's password.
    const theirs = await h.request(
      `/api/users/${other.id}`,
      jsonRequest('PATCH', { password: 'taken-over-1' }, cookie),
    )
    expect(theirs.status).toBe(403)
    expect((await login('snapshot@example.test', 'taken-over-1')).status).toBe(401)
  })
})

describe.skipIf(!databaseUri)('payload-oidc switched off', () => {
  let h: Harness

  beforeAll(async () => {
    h = await startHarness({ clock, key: 'off', plugin: { issuer: undefined } })
  })
  afterAll(async () => {
    await h?.stop()
  })

  it('leaves password sign-in, creation and session length as they were', async () => {
    const created = await h.request(
      '/api/users/first-register',
      jsonRequest('POST', {
        email: 'first@example.test',
        firstName: 'F',
        lastName: 'R',
        password: 'password-123',
        roles: ['admin'],
      }),
    )
    expect(created.status).toBe(200)
    const login = await h.request(
      '/api/users/login',
      jsonRequest('POST', { email: 'first@example.test', password: 'password-123' }),
    )
    expect(login.status).toBe(200)
    const cookie = tokenCookie(login)
    const patched = await h.request(
      `/api/users/${(await login.json()).user.id}`,
      jsonRequest('PATCH', { firstName: 'Changed', password: 'password-456' }, cookie),
    )
    expect(patched.status).toBe(200)
    expect((await h.users().findOne({ email: 'first@example.test' }).lean())?.firstName).toBe(
      'Changed',
    )
    expect(h.payload.collections.users.config.auth.tokenExpiration).toBe(7200)
    expect((await h.request('/api/users/oidc/authorize')).status).toBe(404)
    expect((await h.request('/api/users/oidc/callback')).status).toBe(404)
  })
})
