import {
  APIError,
  AuthenticationError,
  getFieldsToSign,
  jwtSign,
  type CollectionBeforeOperationHook,
  type CollectionRefreshHook,
  type PayloadRequest,
} from 'payload'

import { canLinkByEmail, isBreakGlassEmail, type ResolvedOidcOptions } from './options'
import {
  authCollectionModel,
  findSession,
  OIDC_FIELDS,
  OIDC_SYNC_CONTEXT,
  type StoredUser,
} from './store'

/** `name` of the plugin's refusals, which the plugin logs at `info` (`config.loggingLevels`). */
export const OIDC_REFUSAL_NAME = 'OidcRefusal'

/**
 * An expected refusal (password sign-in off, session ended): a public 403. Its own `name`, set
 * explicitly like Payload's errors so minifying can't change it, keeps these out of error logs.
 */
export class OidcRefusal extends APIError {
  constructor(message: string) {
    super(message, 403, undefined, true)
    this.name = OIDC_REFUSAL_NAME
  }
}

const refused = (message: string) => new OidcRefusal(message)

const PASSWORD_OFF = 'Password sign-in is turned off. Use the single sign-on button.'
const SESSION_ENDED = 'Your session has ended. Sign in again.'

type Credentials = { email?: unknown; username?: unknown }

const PASSWORD_FIELDS = { email: 1, [OIDC_FIELDS.linkable]: 1, [OIDC_FIELDS.subject]: 1 } as const

/**
 * Finds a stored user matching any of `alternatives`. `login` reads through Payload's adapter
 * with `req`, inside the request's transaction, because first-register creates the user and logs
 * in within one. Other operations read outside it: a read inside forgotPassword's transaction
 * makes Payload's own update of the same user fail with a write conflict.
 */
const findStored = async (
  req: PayloadRequest,
  options: ResolvedOidcOptions,
  alternatives: Array<Record<string, string>>,
  inTransaction: boolean,
): Promise<StoredUser | null> => {
  if (alternatives.length === 0) return null
  if (inTransaction) {
    const where = {
      or: alternatives.map((filter) =>
        Object.fromEntries(Object.entries(filter).map(([key, value]) => [key, { equals: value }])),
      ),
    }
    return (await req.payload.db.findOne({
      collection: options.collection as never,
      req,
      where: where as never,
    })) as unknown as StoredUser | null
  }
  return authCollectionModel(req.payload, options.collection)
    .findOne({ $or: alternatives }, PASSWORD_FIELDS)
    .lean()
}

const normalised = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() ? value.trim().toLowerCase() : undefined

/**
 * The stored user a login or forgotten-password request targets, looked up the way Payload will
 * (`auth/operations/login.js`, `forgotPassword.js`). Without `loginWithUsername` only the email
 * counts, and a stray `username` is ignored. With it, login matches the username, or either field
 * when email login is also allowed; a forgotten password prefers the email when that is allowed.
 */
const targetUser = async (
  req: PayloadRequest,
  options: ResolvedOidcOptions,
  operation: 'forgotPassword' | 'login',
  data: Credentials | undefined,
): Promise<StoredUser | null> => {
  const email = normalised(data?.email)
  const username = normalised(data?.username)
  const inTransaction = operation === 'login'
  if (!options.loginWithUsername) {
    return email ? findStored(req, options, [{ email }], inTransaction) : null
  }
  const emailAllowed = options.loginWithUsername.allowEmailLogin
  if (operation === 'forgotPassword') {
    if (emailAllowed && email) return findStored(req, options, [{ email }], false)
    return username ? findStored(req, options, [{ username }], false) : null
  }
  if (username) {
    return findStored(
      req,
      options,
      emailAllowed ? [{ username }, { email: username }] : [{ username }],
      true,
    )
  }
  return emailAllowed && email ? findStored(req, options, [{ email }], true) : null
}

/**
 * Whether a user may use a password while `passwordLogin` is on: the break-glass account, or,
 * until the linking cut-off, a snapshot user who hasn't linked yet.
 */
const passwordAllowedFor = (
  options: ResolvedOidcOptions,
  user: StoredUser | null,
  now: Date,
): boolean => {
  if (!options.passwordLogin || !user) return false
  if (isBreakGlassEmail(options, user.email)) return true
  return canLinkByEmail(options, now) && Boolean(user.oidcLinkable && !user.oidcSubject)
}

/**
 * Closes password sign-in for the auth collection while the plugin is on. A `beforeOperation`
 * hook runs for the REST routes, the admin views and the Local API alike; wrapping endpoints
 * can't, and `disableLocalStrategy` would also break Payload's JWT strategy, refresh and logout.
 *
 * - `login`, `forgotPassword`, `resetPassword`: refused while `passwordLogin` is off. While it is
 *   on, a user who may not use a password gets the status and body an unknown email gets (401,
 *   or a success that sends no email for a forgotten password). Timing and lockout still differ:
 *   only allowed users' passwords are hashed and their failed attempts counted.
 * - `update` with a password: refused, except the break-glass account changing its own password
 *   while `passwordLogin` is on. Sync never sets passwords this way.
 * - `unlock`: refused.
 * - `create`: refused unless the plugin's sync makes it, or the collection is empty and the
 *   break-glass account registers itself with password sign-in on (first-register), which may
 *   not set the plugin's fields.
 * - `refresh`: refused once the session is older than `sessionMaxHours`, or the user is disabled.
 */
export const createBeforeOperationHook =
  (
    options: ResolvedOidcOptions,
    clock: () => Date = () => new Date(),
  ): CollectionBeforeOperationHook =>
  async ({ args, operation, req }) => {
    if (!options.enabled) return args
    const now = clock()
    const data = (args as { data?: Record<string, unknown> }).data
    const isSync = req.context?.[OIDC_SYNC_CONTEXT] === true

    switch (operation) {
      case 'login':
      case 'forgotPassword': {
        if (!options.passwordLogin) throw refused(PASSWORD_OFF)
        const user = await targetUser(req, options, operation, data)
        if (passwordAllowedFor(options, user, now)) return args
        if (operation === 'login') throw new AuthenticationError(req.t)
        // Payload has already read the address, so answer as usual but send nothing; resetting
        // with the token it stores is refused below.
        return { ...args, disableEmail: true }
      }
      case 'resetPassword': {
        if (!options.passwordLogin) throw refused(PASSWORD_OFF)
        const token = data?.token
        const user =
          typeof token === 'string' && token
            ? await findStored(req, options, [{ resetPasswordToken: token }], false)
            : null
        if (passwordAllowedFor(options, user, now)) return args
        throw refused(PASSWORD_OFF)
      }
      case 'update': {
        if (isSync || data?.password === undefined || data.password === null) return args
        const self = req.user as { email?: string; id?: unknown } | null
        const id = (args as { id?: unknown }).id
        const ownBreakGlass =
          options.passwordLogin &&
          id !== undefined &&
          self?.id !== undefined &&
          String(self.id) === String(id) &&
          isBreakGlassEmail(options, self.email)
        if (ownBreakGlass) return args
        throw refused('Passwords are managed by the identity provider.')
      }
      case 'unlock':
        throw refused(PASSWORD_OFF)
      case 'create': {
        if (isSync) return args
        if (options.passwordLogin && isBreakGlassEmail(options, data?.email)) {
          const { totalDocs } = await req.payload.count({
            collection: options.collection as never,
            overrideAccess: true,
          })
          if (totalDocs === 0) {
            const {
              [OIDC_FIELDS.disabledAt]: _disabledAt,
              [OIDC_FIELDS.linkable]: _linkable,
              [OIDC_FIELDS.subject]: _subject,
              ...rest
            } = data ?? {}
            return { ...args, data: rest }
          }
        }
        throw refused('Users are created when they first sign in with single sign-on.')
      }
      case 'refresh': {
        const user = req.user as { _sid?: string; collection?: string; id?: unknown } | null
        if (!user?._sid || user.collection !== options.collection) return args
        const session = await findSession(req.payload, options, user.id, user._sid)
        const age = session ? now.getTime() - session.createdAt.getTime() : Number.NaN
        // A session without a readable createdAt fails closed (NaN compares false).
        if (!session || session.disabled || !(age >= 0 && age < options.sessionMaxSeconds * 1000)) {
          throw refused(SESSION_ENDED)
        }
        return args
      }
      default:
        return args
    }
  }

/**
 * Caps a refreshed token at the session's absolute limit. Payload signs every refreshed token for
 * the full `tokenExpiration`, and its JWT strategy never reads the session's `expiresAt`, so
 * without this a refresh just before `sessionMaxHours` would last another `sessionHours`.
 */
export const createRefreshHook =
  (options: ResolvedOidcOptions, clock: () => Date = () => new Date()): CollectionRefreshHook =>
  async ({ args, user }) => {
    if (!options.enabled) return undefined
    const reqUser = args.req.user as { _sid?: string; _strategy?: string; id?: unknown } | null
    if (!reqUser?._sid) return undefined
    const session = await findSession(args.req.payload, options, reqUser.id, reqUser._sid)
    if (!session) throw refused(SESSION_ENDED)
    const remaining = Math.floor(
      (session.createdAt.getTime() + options.sessionMaxSeconds * 1000 - clock().getTime()) / 1000,
    )
    if (!(remaining > 0)) throw refused(SESSION_ENDED)
    if (remaining >= options.sessionSeconds) return undefined
    const collectionConfig = args.collection.config
    const { exp, token } = await jwtSign({
      fieldsToSign: getFieldsToSign({
        collectionConfig,
        email: (user as { email?: string }).email ?? '',
        sid: reqUser._sid,
        user: args.req.user as never,
      }),
      secret: args.req.payload.secret,
      tokenExpiration: remaining,
    })
    return {
      exp,
      refreshedToken: token,
      setCookie: true,
      strategy: reqUser._strategy,
      user,
    } as never
  }
