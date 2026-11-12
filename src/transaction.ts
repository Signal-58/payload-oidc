import crypto from 'node:crypto'

/**
 * The sign-in transaction: what `authorize` hands to `callback` through the browser. It is sealed
 * with AES-256-GCM under a key derived from the Payload secret, so the browser can neither read
 * the PKCE verifier and nonce nor change the return path.
 */
export type SignInTransaction = {
  /** When the transaction was created, in milliseconds since the epoch. */
  createdAt: number
  nonce: string
  returnTo: string
  state: string
  verifier: string
}

/** How long the provider round trip may take. */
export const TRANSACTION_MAX_AGE_SECONDS = 600

const KEY_INFO = 'payload-oidc sign-in transaction v1'

const transactionKey = (secret: string): Buffer =>
  Buffer.from(crypto.hkdfSync('sha256', secret, Buffer.alloc(0), KEY_INFO, 32))

/** Seals a transaction for the cookie. */
export const sealTransaction = (secret: string, transaction: SignInTransaction): string => {
  const iv = crypto.randomBytes(12)
  const cipher = crypto.createCipheriv('aes-256-gcm', transactionKey(secret), iv)
  const body = Buffer.concat([cipher.update(JSON.stringify(transaction), 'utf8'), cipher.final()])
  return [iv, body, cipher.getAuthTag()].map((part) => part.toString('base64url')).join('.')
}

const isTransaction = (value: unknown): value is SignInTransaction => {
  if (!value || typeof value !== 'object') return false
  const record = value as Record<string, unknown>
  return (
    typeof record.createdAt === 'number' &&
    ['nonce', 'returnTo', 'state', 'verifier'].every((key) => typeof record[key] === 'string')
  )
}

/**
 * Opens a sealed transaction.
 *
 * @returns The transaction, or `undefined` if it was tampered with, sealed under another secret,
 *   malformed, or older than {@link TRANSACTION_MAX_AGE_SECONDS}.
 */
export const openTransaction = (
  secret: string,
  sealed: string | undefined,
  now: Date,
): SignInTransaction | undefined => {
  if (!sealed) return undefined
  const parts = sealed.split('.')
  if (parts.length !== 3) return undefined
  try {
    const [iv, body, tag] = parts.map((part) => Buffer.from(part, 'base64url'))
    // A full 16-byte tag only: GCM would otherwise accept a truncated one.
    if (iv.length !== 12 || tag.length !== 16) return undefined
    const decipher = crypto.createDecipheriv('aes-256-gcm', transactionKey(secret), iv, {
      authTagLength: 16,
    })
    decipher.setAuthTag(tag)
    const json = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8')
    const transaction: unknown = JSON.parse(json)
    if (!isTransaction(transaction)) return undefined
    const age = now.getTime() - transaction.createdAt
    if (age < 0 || age > TRANSACTION_MAX_AGE_SECONDS * 1000) return undefined
    return transaction
  } catch {
    return undefined
  }
}

/**
 * The path to return to after sign-in: only paths under the admin route.
 *
 * Rejects absolute and scheme-relative URLs (`//host`, `/\host`), backslashes, control
 * characters, and anything that doesn't stay under `adminRoute` once normalised.
 *
 * @param requested - The `redirect` the admin passed, if any.
 * @param adminRoute - The admin route, such as `/admin`.
 * @returns A safe same-origin path.
 */
export const safeReturnPath = (requested: unknown, adminRoute: string): string => {
  const fallback = adminRoute || '/'
  if (typeof requested !== 'string' || requested.length === 0 || requested.length > 2048) {
    return fallback
  }
  // Raw input checks first: a backslash or control character is never needed in an admin path.
  // oxlint-disable-next-line no-control-regex
  if (!requested.startsWith('/') || /[\\\u0000-\u001f\u007f]/.test(requested)) return fallback
  if (requested.startsWith('//')) return fallback
  let parsed: URL
  try {
    parsed = new URL(requested, 'http://payload-oidc.invalid')
  } catch {
    return fallback
  }
  if (parsed.origin !== 'http://payload-oidc.invalid') return fallback
  const path = `${parsed.pathname}${parsed.search}${parsed.hash}`
  const root = adminRoute.replace(/\/+$/, '')
  if (root && parsed.pathname !== root && !parsed.pathname.startsWith(`${root}/`)) return fallback
  return path
}
