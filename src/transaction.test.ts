import { describe, expect, it } from 'vitest'

import {
  openTransaction,
  safeReturnPath,
  sealTransaction,
  TRANSACTION_MAX_AGE_SECONDS,
  type SignInTransaction,
} from './transaction'

const secret = 'a-payload-secret'
const now = new Date('2026-11-10T12:00:00Z')
const transaction: SignInTransaction = {
  createdAt: now.getTime(),
  nonce: 'nonce',
  returnTo: '/admin/collections/pages',
  state: 'state',
  verifier: 'verifier',
}

describe('sign-in transaction', () => {
  it('round-trips and hides its contents', () => {
    const sealed = sealTransaction(secret, transaction)
    expect(sealed).not.toContain('verifier')
    expect(openTransaction(secret, sealed, now)).toEqual(transaction)
  })

  it('refuses a tampered value, another secret, garbage, or nothing', () => {
    const sealed = sealTransaction(secret, transaction)
    const [iv, body, tag] = sealed.split('.')
    const flipped = Buffer.from(body, 'base64url')
    flipped[0] ^= 1
    expect(
      openTransaction(secret, [iv, flipped.toString('base64url'), tag].join('.'), now),
    ).toBeUndefined()
    expect(openTransaction('another-secret', sealed, now)).toBeUndefined()
    expect(openTransaction(secret, 'not.a.transaction', now)).toBeUndefined()
    expect(openTransaction(secret, 'nope', now)).toBeUndefined()
    expect(openTransaction(secret, undefined, now)).toBeUndefined()
  })

  it('expires', () => {
    const sealed = sealTransaction(secret, transaction)
    const justInTime = new Date(now.getTime() + TRANSACTION_MAX_AGE_SECONDS * 1000)
    expect(openTransaction(secret, sealed, justInTime)).toBeDefined()
    expect(openTransaction(secret, sealed, new Date(justInTime.getTime() + 1))).toBeUndefined()
    expect(openTransaction(secret, sealed, new Date(now.getTime() - 1))).toBeUndefined()
  })
})

describe('safeReturnPath', () => {
  it('keeps paths under the admin route, with query and hash', () => {
    expect(safeReturnPath('/admin', '/admin')).toBe('/admin')
    expect(safeReturnPath('/admin/collections/pages?limit=10#x', '/admin')).toBe(
      '/admin/collections/pages?limit=10#x',
    )
  })

  it.each([
    undefined,
    '',
    'admin',
    '//evil.example/admin',
    '/\\evil.example',
    '\\\\evil.example',
    'https://evil.example/admin',
    'javascript:alert(1)',
    '/administrator',
    '/api/users/me',
    '/admin/../api/users',
    '/admin/%2e%2e/api',
    '/admin\nSet-Cookie: x=1',
    '/admin\u0000',
    `/admin/${'a'.repeat(3000)}`,
  ])('falls back to the admin route for %j', (requested) => {
    expect(safeReturnPath(requested, '/admin')).toBe('/admin')
  })
})
