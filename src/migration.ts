import type { Payload } from 'payload'

import { OIDC_FIELDS } from './store'

/**
 * What the helpers need from a migration's arguments (`MigrateUpArgs` or `MigrateDownArgs` from
 * `@payloadcms/db-mongodb`): pass those straight through.
 */
export type OidcMigrationArgs = {
  payload: Payload
  /** The migration's MongoDB session, when `payload migrate` runs it in a transaction. */
  session?: unknown
}

export type OidcMigrationOptions = {
  /** The auth collection the plugin is on. */
  collection?: string
}

type OperationOptions = { session?: unknown }
type RawCollection = {
  countDocuments: (filter: Record<string, unknown>, options: OperationOptions) => Promise<number>
  updateMany: (
    filter: Record<string, unknown>,
    update: Record<string, unknown>,
    options: OperationOptions,
  ) => Promise<{ modifiedCount: number }>
}
type CompiledModel = { collection?: { name?: string }; createIndexes: () => Promise<unknown> }

/** The collection's MongoDB collection, written directly, and its compiled model. */
const usersCollection = (payload: Payload, slug: string) => {
  const db = payload.db as unknown as {
    collections?: Record<string, CompiledModel | undefined>
    connection?: { db?: { collection: (name: string) => RawCollection } }
  }
  const model = db.collections?.[slug]
  const name = model?.collection?.name
  const database = db.connection?.db
  if (!model || !name || !database) {
    throw new Error(
      `payload-oidc: the migration needs the MongoDB adapter (no model for "${slug}").`,
    )
  }
  const config = (
    payload.collections as unknown as Record<string, { config: { fields: unknown[] } } | undefined>
  )[slug]?.config
  const hasPluginFields = config?.fields.some(
    (field) => (field as { name?: unknown }).name === OIDC_FIELDS.subject,
  )
  if (!hasPluginFields) {
    throw new Error(
      `payload-oidc: "${slug}" has no ${OIDC_FIELDS.subject} field; add the plugin to the config before this migration runs.`,
    )
  }
  // Direct writes: through the model, Mongoose would also stamp `updatedAt` on every user.
  return { collection: database.collection(name), model }
}

/**
 * For an app's migration, before sign-in is turned on: marks every existing user that isn't
 * linked yet `oidcLinkable`, so each can be linked once, by verified email, until
 * `linkByEmailUntil`. Users created later (at their first sign-in) are never linkable, so a new
 * provider account can never claim one of them by email.
 *
 * It builds the collection's indexes first, among them the sparse unique `oidcSubject` index:
 * Mongoose starts that build in the background when `payload migrate` boots, and writing in the
 * migration's transaction while it runs fails with a transient catalog-change error. The build is
 * idempotent and runs outside the transaction, so call this before anything else in the migration
 * touches the collection: a build that has work to do waits for every transaction holding the
 * collection, and the transaction would be waiting for the build. It refuses, before any change,
 * a user that stores `oidcSubject: null`, which the sparse index would still index (and collide
 * on). A user with an `oidcSubject` is already linked and left alone, so a rerun is a no-op.
 *
 * ```ts
 * export async function up(args: MigrateUpArgs): Promise<void> {
 *   await takeLinkingSnapshot(args)
 * }
 * ```
 *
 * @returns How many users were marked.
 */
export const takeLinkingSnapshot = async (
  { payload, session }: OidcMigrationArgs,
  { collection: slug = 'users' }: OidcMigrationOptions = {},
): Promise<number> => {
  const { collection, model } = usersCollection(payload, slug)
  // Outside the transaction, like the build: a read in it would hold the collection until commit.
  const nullSubjects = await collection.countDocuments(
    { [OIDC_FIELDS.subject]: { $type: 'null' } },
    {},
  )
  if (nullSubjects > 0) {
    throw new Error(`payload-oidc: a user of "${slug}" stores ${OIDC_FIELDS.subject} as null.`)
  }
  await model.createIndexes()
  const { modifiedCount } = await collection.updateMany(
    { [OIDC_FIELDS.linkable]: { $exists: false }, [OIDC_FIELDS.subject]: { $exists: false } },
    { $set: { [OIDC_FIELDS.linkable]: true } },
    { session },
  )
  payload.logger.info(`payload-oidc: marked ${modifiedCount} users of "${slug}" linkable.`)
  return modifiedCount
}

/**
 * The `down` of {@link takeLinkingSnapshot}: clears every `oidcLinkable` mark. Links already made
 * (`oidcSubject`) and disables (`oidcDisabledAt`) stay: they are the provider's record of who
 * these users are, and with the plugin off they do nothing.
 *
 * @returns How many marks were cleared.
 */
export const clearLinkingSnapshot = async (
  { payload, session }: OidcMigrationArgs,
  { collection: slug = 'users' }: OidcMigrationOptions = {},
): Promise<number> => {
  const { collection } = usersCollection(payload, slug)
  const { modifiedCount } = await collection.updateMany(
    { [OIDC_FIELDS.linkable]: { $exists: true } },
    { $unset: { [OIDC_FIELDS.linkable]: '' } },
    { session },
  )
  payload.logger.info(`payload-oidc: cleared ${modifiedCount} linkable marks on "${slug}".`)
  return modifiedCount
}
