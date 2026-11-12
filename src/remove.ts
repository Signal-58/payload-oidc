import type { Field, Payload, SanitizedCollectionConfig, SanitizedGlobalConfig } from 'payload'

import { isBreakGlassEmail, type ResolvedOidcOptions } from './options'
import { authCollectionModel, OIDC_FIELDS, OIDC_SYNC_CONTEXT, unusablePassword } from './store'

/** A place a document can point at a user: a collection or global, and a dotted field path. */
export type UserReference = {
  entity: 'collection' | 'global'
  path: string
  slug: string
  versions: boolean
}

const pointsAt = (relationTo: unknown, collection: string): boolean =>
  Array.isArray(relationTo) ? relationTo.includes(collection) : relationTo === collection

/** Every relationship or upload field under `fields` that can point at `collection`. */
const referencePaths = (fields: Field[], collection: string, prefix = ''): string[] =>
  fields.flatMap((field): string[] => {
    const named = 'name' in field && field.name ? `${prefix}${field.name}` : undefined
    if ((field.type === 'relationship' || field.type === 'upload') && named) {
      if (!pointsAt(field.relationTo, collection)) return []
      // A polymorphic relationship stores `{ relationTo, value }`.
      return [Array.isArray(field.relationTo) ? `${named}.value` : named]
    }
    if (field.type === 'array' || field.type === 'group') {
      return referencePaths(field.fields, collection, named ? `${named}.` : prefix)
    }
    if (field.type === 'blocks' && named) {
      return field.blocks.flatMap((block) =>
        referencePaths(typeof block === 'string' ? [] : block.fields, collection, `${named}.`),
      )
    }
    if (field.type === 'tabs') {
      return field.tabs.flatMap((tab) =>
        referencePaths(
          tab.fields,
          collection,
          'name' in tab && tab.name ? `${prefix}${tab.name}.` : prefix,
        ),
      )
    }
    if ((field.type === 'row' || field.type === 'collapsible') && 'fields' in field) {
      return referencePaths(field.fields, collection, prefix)
    }
    return []
  })

/**
 * Every field in the config that can refer to a user of `collection`, except Payload's own
 * bookkeeping (preferences, locks, jobs, migrations), which belongs to the user and goes with it.
 * Rich-text relationships aren't seen; anything referenced only there is left as a dangling link.
 */
export const findUserReferences = (
  collections: SanitizedCollectionConfig[],
  globals: SanitizedGlobalConfig[],
  collection: string,
): UserReference[] => [
  ...collections
    .filter(({ slug }) => !slug.startsWith('payload-'))
    .flatMap((config) =>
      referencePaths(config.fields, collection).map((path) => ({
        entity: 'collection' as const,
        path,
        slug: config.slug,
        versions: Boolean(config.versions),
      })),
    ),
  ...globals.flatMap((config) =>
    referencePaths(config.fields, collection).map((path) => ({
      entity: 'global' as const,
      path,
      slug: config.slug,
      versions: Boolean(config.versions),
    })),
  ),
]

const isReferenced = async (
  payload: Payload,
  references: UserReference[],
  id: string | number,
): Promise<boolean> => {
  for (const reference of references) {
    if (reference.entity === 'global') {
      const global = (await payload.findGlobal({
        depth: 0,
        overrideAccess: true,
        slug: reference.slug as never,
      })) as Record<string, unknown>
      if (JSON.stringify(global).includes(JSON.stringify(String(id)))) return true
      continue
    }
    const where = { [reference.path]: { equals: id } } as never
    const { totalDocs } = await payload.count({
      collection: reference.slug as never,
      overrideAccess: true,
      where,
    })
    if (totalDocs > 0) return true
    if (reference.versions) {
      const versions = await payload.countVersions({
        collection: reference.slug as never,
        overrideAccess: true,
        where: { [`version.${reference.path}`]: { equals: id } } as never,
      })
      if (versions.totalDocs > 0) return true
    }
  }
  return false
}

export type RemoveOutcome =
  | { kind: 'anonymised' | 'deleted' }
  | { kind: 'refused'; reason: 'break_glass' | 'not_disabled' | 'not_found' }

/** Payload's auth bookkeeping that names or can act for the person. */
const AUTH_FIELDS_TO_CLEAR = [
  '_verificationToken',
  'lockUntil',
  'loginAttempts',
  'resetPasswordExpiration',
  'resetPasswordRequestedAt',
  'resetPasswordToken',
]

/**
 * Everything an anonymised user loses: every top-level data field of the collection (photo,
 * social links, anything an app added) except the ones anonymising sets or keeps, plus Payload's
 * auth bookkeeping. `keepOnRemove` names fields an app wants kept.
 */
const fieldsToClear = (payload: Payload, options: ResolvedOidcOptions): string[] => {
  const keep = new Set([
    'createdAt',
    'email',
    'hash',
    'id',
    'salt',
    'sessions',
    'updatedAt',
    OIDC_FIELDS.disabledAt,
    options.firstNameField,
    options.lastNameField,
    options.roleField,
    ...options.keepOnRemove,
  ])
  const config = payload.collections[options.collection as never] as unknown as {
    config: SanitizedCollectionConfig
  }
  const dataFields = config.config.flattenedFields
    .filter((field) => 'name' in field && field.type !== 'join')
    .map((field) => field.name)
  return [...new Set([...dataFields, ...AUTH_FIELDS_TO_CLEAR])].filter((name) => !keep.has(name))
}

/**
 * Removes a disabled user. Only disabled users: an active one would be created again at their
 * next sign-in. If nothing refers to the user they are deleted; otherwise they are anonymised
 * (names "Removed user", email `removed-<id>@removed.invalid`, every other profile field, the
 * subject, password and sessions gone) so bylines and audit rows still resolve. Someone added back at the provider later signs
 * in as a new user.
 */
export const removeUser = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  id: string | number,
): Promise<RemoveOutcome> => {
  const model = authCollectionModel(payload, options.collection)
  const user = await model.findOne({ _id: id }, { email: 1, [OIDC_FIELDS.disabledAt]: 1 }).lean()
  if (!user) return { kind: 'refused', reason: 'not_found' }
  if (isBreakGlassEmail(options, user.email)) return { kind: 'refused', reason: 'break_glass' }
  if (!user.oidcDisabledAt) return { kind: 'refused', reason: 'not_disabled' }

  const references = findUserReferences(
    payload.config.collections,
    payload.config.globals,
    options.collection,
  )
  if (!(await isReferenced(payload, references, id))) {
    // Re-checked in the delete itself: a user who signed in again since the read above is no
    // longer disabled and is kept.
    const { docs } = await payload.delete({
      collection: options.collection as never,
      context: { [OIDC_SYNC_CONTEXT]: true },
      overrideAccess: true,
      where: {
        and: [{ id: { equals: id } }, { [OIDC_FIELDS.disabledAt]: { exists: true } }],
      } as never,
    })
    return docs.length > 0 ? { kind: 'deleted' } : { kind: 'refused', reason: 'not_disabled' }
  }

  const clear = fieldsToClear(payload, options)
  const result = await model.updateOne(
    { _id: id, [OIDC_FIELDS.disabledAt]: { $ne: null } },
    {
      $set: {
        // A valid address (Payload's email check needs a dotted domain), unique per user, and
        // under a reserved TLD so it can never receive mail.
        email: `removed-${String(id)}@removed.invalid`,
        [options.firstNameField]: 'Removed',
        [options.lastNameField]: 'user',
        sessions: [],
        ...unusablePassword(),
      },
      $unset: Object.fromEntries(
        [OIDC_FIELDS.linkable, OIDC_FIELDS.subject, ...clear].map((field) => [field, '']),
      ),
    },
  )
  return result.matchedCount > 0
    ? { kind: 'anonymised' }
    : { kind: 'refused', reason: 'not_disabled' }
}
