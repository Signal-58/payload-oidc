import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  canLinkByEmail,
  isBreakGlassEmail,
  resolveOptions,
  roleForGroups,
  roleTableGroups,
  type OidcPluginOptions,
} from './options'

const table = {
  superadmin: ['org-superadmin', 'org-admins'],
  admin: ['org-admin'],
  editor: ['org-editor'],
}

const base: OidcPluginOptions = {
  clientId: 'client',
  clientSecret: 'secret',
  issuer: 'https://idp.example/application/o/app/',
  roles: { field: 'roles', table },
}

afterEach(() => {
  vi.unstubAllEnvs()
})

describe('roleForGroups', () => {
  it('gives the highest role whose group the user is in', () => {
    expect(roleForGroups(table, ['org-editor', 'org-admins'])).toBe('superadmin')
    expect(roleForGroups(table, ['org-editor', 'org-admin'])).toBe('admin')
    expect(roleForGroups(table, ['org-editor'])).toBe('editor')
  })

  it('gives no role for no matching group or a malformed claim', () => {
    expect(roleForGroups(table, ['other'])).toBeUndefined()
    expect(roleForGroups(table, [])).toBeUndefined()
    expect(roleForGroups(table, 'org-admin')).toBeUndefined()
    expect(roleForGroups(table, undefined)).toBeUndefined()
    expect(roleForGroups(table, [{ name: 'org-admin' }])).toBeUndefined()
  })

  it('lists every role-table group once', () => {
    expect(roleTableGroups({ a: ['x', 'y'], b: ['y', 'z'] })).toEqual(['x', 'y', 'z'])
  })
})

describe('resolveOptions', () => {
  it('is off, without throwing, when the issuer or client is unset', () => {
    expect(resolveOptions({ ...base, issuer: undefined }).enabled).toBe(false)
    expect(resolveOptions({ ...base, clientSecret: '' }).enabled).toBe(false)
    expect(resolveOptions({ ...base, clientId: ' ', passwordLogin: true }).enabled).toBe(false)
    expect(resolveOptions(base).enabled).toBe(true)
  })

  it('fills in defaults', () => {
    expect(resolveOptions(base)).toMatchObject({
      collection: 'users',
      firstNameField: 'firstName',
      lastNameField: 'lastName',
      passwordLogin: false,
      roleHasMany: true,
      scopes: ['openid', 'email', 'profile'],
      sessionMaxSeconds: 12 * 3600,
      sessionSeconds: 8 * 3600,
    })
  })

  it('refuses unsafe or inconsistent configuration', () => {
    expect(() => resolveOptions({ ...base, roles: { field: 'roles', table: {} } })).toThrow(
      /at least one role/,
    )
    expect(() =>
      resolveOptions({ ...base, roles: { field: 'roles', table: { admin: [] } } }),
    ).toThrow(/needs at least one group/)
    expect(() => resolveOptions({ ...base, sessionHours: 12, sessionMaxHours: 8 })).toThrow(
      /at least sessionHours/,
    )
    expect(() => resolveOptions({ ...base, sessionHours: 0 })).toThrow(/positive/)
    expect(() => resolveOptions({ ...base, linkByEmailUntil: 'soon' })).toThrow(/ISO 8601/)
    expect(() => resolveOptions({ ...base, passwordLogin: true })).toThrow(/breakGlassEmail/)
    expect(() => resolveOptions({ ...base, issuer: 'http://idp.example/' })).toThrow(/https/)
  })

  it('allows an http issuer only when asked and never in production', () => {
    expect(
      resolveOptions({ ...base, allowInsecureIssuer: true, issuer: 'http://127.0.0.1:9000/' })
        .enabled,
    ).toBe(true)
    vi.stubEnv('NODE_ENV', 'production')
    expect(() =>
      resolveOptions({ ...base, allowInsecureIssuer: true, issuer: 'http://127.0.0.1:9000/' }),
    ).toThrow(/https/)
  })

  it('matches the break-glass email case-insensitively and only that one', () => {
    const options = resolveOptions({
      ...base,
      breakGlassEmail: ' Ops@Example.test ',
      passwordLogin: true,
    })
    expect(isBreakGlassEmail(options, 'ops@example.test')).toBe(true)
    expect(isBreakGlassEmail(options, 'OPS@EXAMPLE.TEST ')).toBe(true)
    expect(isBreakGlassEmail(options, 'other@example.test')).toBe(false)
    expect(isBreakGlassEmail(options, undefined)).toBe(false)
    expect(isBreakGlassEmail(resolveOptions(base), 'ops@example.test')).toBe(false)
  })

  it('releases stale reconcile runs after 10 minutes unless told otherwise', () => {
    expect(resolveOptions(base).reconcileStaleAfterSeconds).toBe(600)
    expect(
      resolveOptions({ ...base, reconcileStaleAfterMinutes: 30 }).reconcileStaleAfterSeconds,
    ).toBe(1800)
    expect(
      resolveOptions({ ...base, reconcileStaleAfterMinutes: false }).reconcileStaleAfterSeconds,
    ).toBeUndefined()
    // A tiny threshold would round to nothing, or stop every live run.
    for (const minutes of [0, 0.005, 0.5, Number.NaN]) {
      expect(() => resolveOptions({ ...base, reconcileStaleAfterMinutes: minutes })).toThrow(
        /reconcileStaleAfterMinutes must be a number of minutes, at least 1/,
      )
    }
  })

  it('links by email only before the cut-off, and never without one', () => {
    const options = resolveOptions({ ...base, linkByEmailUntil: '2026-12-01' })
    expect(canLinkByEmail(options, new Date('2026-11-30T23:59:59Z'))).toBe(true)
    expect(canLinkByEmail(options, new Date('2026-12-01T00:00:00Z'))).toBe(false)
    expect(canLinkByEmail(resolveOptions(base), new Date('2000-01-01'))).toBe(false)
  })
})
