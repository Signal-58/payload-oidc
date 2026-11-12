import crypto from 'node:crypto'

import { ValidationError, type Payload, type SanitizedCollectionConfig } from 'payload'

import type { ResolvedOidcOptions } from './options'

/** `req.context` key that marks a write made by the plugin's sync. */
export const OIDC_SYNC_CONTEXT = 'oidcSync'

/** The fields the plugin adds to the auth collection. */
export const OIDC_FIELDS = {
  disabledAt: 'oidcDisabledAt',
  linkable: 'oidcLinkable',
  subject: 'oidcSubject',
} as const

type StoredSession = { createdAt: Date | string; expiresAt: Date | string; id: string }

/** The stored shape of an auth-collection document, as far as the plugin reads it. */
export type StoredUser = {
  _id: unknown
  email?: string
  oidcDisabledAt?: Date | null
  oidcLinkable?: boolean
  oidcSubject?: string
  sessions?: StoredSession[]
  [key: string]: unknown
}

type UpdateResult = { matchedCount: number; modifiedCount?: number }

/** The subset of a Mongoose model the plugin needs for conditional, atomic writes. */
export type AuthCollectionModel = {
  find: (filter: Record<string, unknown>) => { lean: () => Promise<StoredUser[]> }
  findOne: (
    filter: Record<string, unknown>,
    projection?: Record<string, 0 | 1>,
  ) => { lean: () => Promise<StoredUser | null> }
  updateOne: (
    filter: Record<string, unknown>,
    update: Record<string, unknown> | Record<string, unknown>[],
    options?: Record<string, unknown>,
  ) => Promise<UpdateResult>
}

/**
 * The auth collection's Mongoose model. Session pushes and disables must be conditional, atomic
 * updates, which Payload's adapter API can't express, so the plugin needs MongoDB.
 */
export const authCollectionModel = (payload: Payload, slug: string): AuthCollectionModel => {
  const model = (payload.db as unknown as { collections?: Record<string, AuthCollectionModel> })
    .collections?.[slug]
  if (!model) {
    throw new Error(`payload-oidc needs the MongoDB adapter (no model for "${slug}").`)
  }
  return model
}

/**
 * The auth collection's sanitized config. Typed loosely on purpose: an app's generated Payload
 * types narrow collection slugs to its own, which a plugin can't name.
 */
export const authCollectionConfig = (payload: Payload, slug: string): SanitizedCollectionConfig =>
  (payload.collections as unknown as Record<string, { config: SanitizedCollectionConfig }>)[slug]
    .config

/** A password hash and salt that no password matches. */
export const unusablePassword = () => ({
  hash: crypto.randomBytes(64).toString('hex'),
  salt: crypto.randomBytes(32).toString('hex'),
})

/** The value the role field stores for `role` (or for no role). */
export const roleValue = (options: ResolvedOidcOptions, role: string | undefined) =>
  options.roleHasMany ? (role ? [role] : []) : (role ?? null)

/**
 * Disables a user: clears the role and every session and sets `oidcDisabledAt`, in one atomic
 * update. Clearing sessions ends access on the next request, because Payload checks the session
 * ID on every request. The break-glass account is never matched.
 *
 * @returns Whether a user was disabled.
 */
export const disableUser = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  id: unknown,
  now: Date,
  /** Further conditions, such as "unchanged since it was read". */
  condition: Record<string, unknown> = {},
): Promise<boolean> => {
  const filter: Record<string, unknown> = { ...condition, _id: id }
  if (options.breakGlassEmail) filter.email = { $ne: options.breakGlassEmail }
  const result = await authCollectionModel(payload, options.collection).updateOne(filter, {
    $set: {
      [OIDC_FIELDS.disabledAt]: now,
      [options.roleField]: roleValue(options, undefined),
      sessions: [],
    },
  })
  return result.matchedCount > 0
}

/**
 * Links an existing, never-linked snapshot user to a provider subject, by email. One atomic,
 * conditional update sets the subject, clears `oidcLinkable` and every session, and replaces the
 * password with one nobody knows, so the old password and old sessions stop working.
 *
 * @returns Whether a user was linked.
 */
export const linkByEmail = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  email: string,
  subject: string,
): Promise<boolean> => {
  // The break-glass account keeps its password: it is never linked, even if the migration marked it.
  if (options.breakGlassEmail && email === options.breakGlassEmail) return false
  const result = await authCollectionModel(payload, options.collection).updateOne(
    {
      email,
      [OIDC_FIELDS.linkable]: true,
      [OIDC_FIELDS.subject]: { $exists: false },
    },
    {
      $set: {
        [OIDC_FIELDS.subject]: subject,
        sessions: [],
        ...unusablePassword(),
        ...(options.verify ? { _verified: true } : {}),
      },
      $unset: { [OIDC_FIELDS.linkable]: '' },
    },
  )
  return result.matchedCount > 0
}

/**
 * Writes the provider-owned fields of a linked user and clears `oidcDisabledAt`, as one update of
 * just those paths. A Payload update would write back the whole document as it read it, sessions
 * included, so a disable landing in between would be undone.
 *
 * @returns Whether the user (still linked to `subject`) was updated.
 */
export const writeManagedFields = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  id: unknown,
  subject: string,
  fields: Record<string, unknown>,
  now: Date,
): Promise<boolean> => {
  const result = await authCollectionModel(payload, options.collection).updateOne(
    { _id: id, [OIDC_FIELDS.subject]: subject },
    { $set: { ...fields, [OIDC_FIELDS.disabledAt]: null, updatedAt: now } },
  )
  return result.matchedCount > 0
}

/** Marks a user Payload created as verified, for collections with `auth.verify`. */
export const markVerified = async (payload: Payload, options: ResolvedOidcOptions, id: unknown) => {
  if (!options.verify) return
  await authCollectionModel(payload, options.collection).updateOne(
    { _id: id },
    { $set: { _verified: true }, $unset: { _verificationToken: '' } },
  )
}

/**
 * Whether an error is a unique index refusing the write: MongoDB's duplicate-key error from a raw
 * model write, the `ValidationError` db-mongodb turns it into for a Payload write (with the
 * unique field as its path, and no cause), or a transaction's write conflict on the same key.
 */
export const isDuplicateKeyError = (
  error: unknown,
  uniqueFields: readonly string[] = [],
): boolean => {
  if (typeof error !== 'object' || error === null) return false
  const candidate = error as {
    cause?: { code?: unknown }
    code?: unknown
    data?: { errors?: Array<{ path?: unknown }> }
  }
  if (candidate.code === 11000 || candidate.cause?.code === 11000) return true
  // Inside a replica-set transaction a concurrent insert of the same key is a write conflict.
  if (candidate.code === 112 || candidate.cause?.code === 112) return true
  return Boolean(
    error instanceof ValidationError &&
    candidate.data?.errors?.some((entry) => uniqueFields.includes(String(entry.path))),
  )
}

/**
 * Adds a session, conditional on the user still being linked to `subject` and not disabled, as one
 * atomic update. A whole-document write (Payload's `addSessionToUser`) could undo a disable that
 * landed between the read and the write; this can't. Expired sessions are dropped in the same
 * update.
 *
 * @returns The new session ID, or `undefined` if the user was disabled or relinked meanwhile.
 */
export const pushSession = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  id: unknown,
  subject: string,
  now: Date,
): Promise<string | undefined> => {
  const sid = crypto.randomUUID()
  const session = {
    createdAt: now,
    expiresAt: new Date(now.getTime() + options.sessionSeconds * 1000),
    id: sid,
  }
  const result = await authCollectionModel(payload, options.collection).updateOne(
    { _id: id, [OIDC_FIELDS.disabledAt]: null, [OIDC_FIELDS.subject]: subject },
    [
      {
        $set: {
          sessions: {
            $concatArrays: [
              {
                $filter: {
                  cond: { $gt: ['$$this.expiresAt', now] },
                  input: { $ifNull: ['$sessions', []] },
                },
              },
              [session],
            ],
          },
        },
      },
    ],
  )
  return result.matchedCount > 0 ? sid : undefined
}

/** One stored session, with the fields the refresh cap needs. */
export const findSession = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  id: unknown,
  sid: string,
): Promise<{ createdAt: Date; disabled: boolean } | undefined> => {
  const user = await authCollectionModel(payload, options.collection)
    .findOne({ _id: id }, { [OIDC_FIELDS.disabledAt]: 1, sessions: 1 })
    .lean()
  const session = user?.sessions?.find((candidate) => candidate.id === sid)
  if (!user || !session) return undefined
  return { createdAt: new Date(session.createdAt), disabled: Boolean(user.oidcDisabledAt) }
}
