import {
  validations,
  type CollectionBeforeChangeHook,
  type CollectionConfig,
  type Config,
  type Field,
  type FieldAccess,
  type Plugin,
  type Validate,
} from 'payload'

import { createBeforeOperationHook, createRefreshHook, OIDC_REFUSAL_NAME } from './before-operation'
import { createEndpoints } from './endpoints'
import { createReconcileTask } from './reconcile-task'
import { resolveOptions, type OidcPluginOptions, type ResolvedOidcOptions } from './options'
import { createProviderClient, type ProviderClient } from './provider'
import { OIDC_FIELDS, OIDC_SYNC_CONTEXT } from './store'

/** Key under `config.custom` with the plugin's public (non-secret) state, for the login view. */
export const PUBLIC_STATE_KEY = 'payloadOidc'

export type OidcPublicState = {
  authorizePath: string
  buttonLabel: string
  enabled: boolean
  passwordLogin: boolean
}

/** Field access that lets only the plugin's sync write a field. */
export const syncWriteOnly: FieldAccess = ({ req }) => req.context?.[OIDC_SYNC_CONTEXT] === true

const denyField: FieldAccess = () => false

const pluginFields = (options: ResolvedOidcOptions): Field[] => [
  {
    name: OIDC_FIELDS.subject,
    type: 'text',
    label: 'Identity provider subject',
    // Sparse unique index: the field is unset, never null, when there is no link.
    unique: true,
    index: true,
    access: { create: denyField, update: denyField },
    admin: {
      description: 'The identity provider subject this account is linked to.',
      position: 'sidebar',
      readOnly: true,
    },
  },
  {
    name: OIDC_FIELDS.disabledAt,
    type: 'date',
    label: 'Disabled by identity provider',
    access: { create: denyField, update: denyField },
    admin: {
      date: { pickerAppearance: 'dayAndTime' },
      description: 'Set when the identity provider removed this account’s role.',
      position: 'sidebar',
      readOnly: true,
    },
  },
  {
    name: OIDC_FIELDS.linkable,
    type: 'checkbox',
    access: { create: denyField, update: denyField },
    admin: { hidden: true },
  },
  {
    // "Remove user" on a disabled user; also hides "Change Password" while passwords are off.
    // Stores nothing.
    name: 'oidcRemove',
    type: 'ui',
    admin: {
      components: {
        Field: {
          clientProps: { hidePasswordChange: options.enabled && !options.passwordLogin },
          path: '@signal58/payload-oidc/client#RemoveUserButton',
        },
      },
      position: 'sidebar',
    },
  },
]

const hasField = (fields: Field[], name: string): boolean =>
  fields.some(
    (field) =>
      ('name' in field && field.name === name) ||
      ((field.type === 'row' || field.type === 'collapsible') && hasField(field.fields, name)),
  )

/**
 * Copies the fields, replacing each named top-level, row or collapsible data field with
 * `replace(field)`. Copies, never edits: a field config the host shares with another collection
 * must not change there too.
 */
const mapNamedFields = (
  fields: Field[],
  names: Set<string>,
  found: Set<string>,
  replace: (field: Field) => Field,
): Field[] =>
  fields.map((field) => {
    if ('name' in field && names.has(field.name)) {
      found.add(field.name)
      return replace(field)
    }
    if (field.type === 'row' || field.type === 'collapsible') {
      return { ...field, fields: mapNamedFields(field.fields, names, found, replace) } as Field
    }
    return field
  })

/** Gives a field `update` access that only sync passes. */
const syncOnlyUpdate = (field: Field): Field => {
  const access = (field as { access?: Record<string, unknown> }).access
  return { ...field, access: { ...access, update: syncWriteOnly } } as Field
}

/** No role: an empty list, or no single value. */
const isNoRole = (value: unknown): boolean =>
  Array.isArray(value) ? value.length === 0 : value === null || value === undefined || value === ''

/**
 * Lets a disabled user have no role. Disabling clears the role, so with a `required` role field
 * every later save of that user, such as an admin editing a profile field, would fail. No role
 * passes only while `oidcDisabledAt` is set; anything else goes to the field's own `validate`, or
 * to Payload's default for its type (known options, `required` and so on).
 */
const allowNoRoleWhenDisabled = (field: Field): Field => {
  const own = (field as { validate?: Validate }).validate
  const fallback = (validations as unknown as Record<string, Validate | undefined>)[field.type]
  const validate: Validate = (value, args) => {
    const siblingData = args?.siblingData as Record<string, unknown> | undefined
    if (isNoRole(value) && Boolean(siblingData?.[OIDC_FIELDS.disabledAt])) return true
    if (own) return own(value, args)
    // As Payload applies its default (it does so only to fields without a `validate`).
    return fallback ? fallback(value, { ...field, ...args }) : true
  }
  return { ...field, validate } as Field
}

/** The fields with the role field's validation allowing no role on a disabled user. */
const withRoleValidation = (fields: Field[], options: ResolvedOidcOptions): Field[] =>
  mapNamedFields(fields, new Set([options.roleField]), new Set(), allowNoRoleWhenDisabled)

/** Makes the provider-owned fields updatable only by sync, adding `email` so it can be locked too. */
const lockManagedFields = (collection: CollectionConfig, options: ResolvedOidcOptions) => {
  const fields = [...(collection.fields ?? [])]
  if (!hasField(fields, 'email')) fields.push({ name: 'email', type: 'email' })
  const names = new Set(['email', options.firstNameField, options.lastNameField, options.roleField])
  const found = new Set<string>()
  // Only update: creation is already limited to sync (and the break-glass first-register) by
  // the beforeOperation hook, and first-register needs to write these fields.
  const locked = mapNamedFields(fields, names, found, syncOnlyUpdate)
  for (const name of names) {
    if (!found.has(name)) throw new Error(`payload-oidc: ${collection.slug}.${name} not found.`)
  }
  return locked
}

/** Never store `oidcSubject: null`: the sparse unique index would make a second one collide. */
const dropNullSubject: CollectionBeforeChangeHook = ({ data }) => {
  if (data && (data[OIDC_FIELDS.subject] === null || data[OIDC_FIELDS.subject] === '')) {
    delete data[OIDC_FIELDS.subject]
  }
  return data
}

/**
 * Signs staff in to the Payload admin through an OpenID Connect provider, which becomes the source
 * of truth for the auth collection's users and roles.
 *
 * With the issuer, client ID or client secret unset, the plugin adds its fields and inert
 * endpoints so the schema stays the same, and changes nothing else: password sign-in works as
 * before.
 */
export const oidcPlugin =
  (
    pluginOptions: OidcPluginOptions,
    testing?: { client?: ProviderClient; clock?: () => Date },
  ): Plugin =>
  (incoming: Config): Config => {
    const options = resolveOptions(pluginOptions)
    const client = testing?.client ?? createProviderClient(options)
    const collections = incoming.collections ?? []
    const target = collections.find(({ slug }) => slug === options.collection)
    if (!target) throw new Error(`payload-oidc: no "${options.collection}" collection.`)
    if (!target.auth)
      throw new Error(`payload-oidc: "${options.collection}" is not an auth collection.`)
    // `endpoints: false` would be replaced by our list, and Payload would then add back every
    // auth route, password ones included.
    if (target.endpoints === false) {
      throw new Error(`payload-oidc: "${options.collection}" must keep its REST endpoints.`)
    }
    options.verify = typeof target.auth === 'object' && Boolean(target.auth.verify)
    const loginWithUsername =
      typeof target.auth === 'object' ? target.auth.loginWithUsername : undefined
    options.loginWithUsername = loginWithUsername
      ? {
          allowEmailLogin:
            typeof loginWithUsername === 'object' && Boolean(loginWithUsername.allowEmailLogin),
        }
      : undefined

    const auth = typeof target.auth === 'object' ? target.auth : {}
    const collection: CollectionConfig = {
      ...target,
      // The admin then hides "Force Unlock"; the unlock operation is refused regardless.
      access: options.enabled ? { ...target.access, unlock: () => false } : target.access,
      auth: options.enabled
        ? { ...auth, tokenExpiration: options.sessionSeconds, useSessions: true }
        : auth,
      endpoints: [...(target.endpoints ?? []), ...createEndpoints(options, client, testing?.clock)],
      fields: [
        // Role validation whether or not sign-in is on: users disabled before it was turned off
        // keep no role, and must still be editable.
        ...withRoleValidation(
          options.enabled ? lockManagedFields(target, options) : (target.fields ?? []),
          options,
        ),
        ...pluginFields(options),
      ],
      hooks: {
        ...target.hooks,
        beforeChange: [...(target.hooks?.beforeChange ?? []), dropNullSubject],
        beforeOperation: [
          ...(target.hooks?.beforeOperation ?? []),
          createBeforeOperationHook(options, testing?.clock),
        ],
        // First: Payload stops at the first refresh hook that returns a result, so a host hook
        // placed before this one could sign an uncapped token.
        refresh: [createRefreshHook(options, testing?.clock), ...(target.hooks?.refresh ?? [])],
      },
    }

    const apiRoute = incoming.routes?.api ?? '/api'
    const publicState: OidcPublicState = {
      authorizePath: `${apiRoute}/${options.collection}/oidc/authorize`,
      buttonLabel: options.buttonLabel,
      enabled: options.enabled,
      passwordLogin: options.passwordLogin,
    }

    const onInit = incoming.onInit
    return {
      ...incoming,
      // In an app that already has jobs, registered whether or not reconcile is configured, so the
      // job schema doesn't depend on the environment (it is only scheduled when configured). In an
      // app without jobs, only with a source, so the plugin never turns jobs on by itself.
      ...(incoming.jobs?.tasks?.length || options.reconcile
        ? {
            jobs: {
              ...incoming.jobs,
              tasks: [
                ...(incoming.jobs?.tasks ?? []),
                createReconcileTask(options, {
                  clock: testing?.clock,
                  concurrencyControl: Boolean(incoming.jobs?.enableConcurrencyControl),
                }),
              ],
            },
          }
        : {}),
      admin: {
        ...incoming.admin,
        components: {
          ...incoming.admin?.components,
          beforeLogin: [
            ...(incoming.admin?.components?.beforeLogin ?? []),
            '@signal58/payload-oidc/rsc#OidcLoginButton',
          ],
        },
      },
      collections: collections.map((candidate) => (candidate === target ? collection : candidate)),
      // Refused password sign-ins and ended sessions are expected: not errors.
      loggingLevels: {
        ...incoming.loggingLevels,
        [OIDC_REFUSAL_NAME]: 'info',
      } as Config['loggingLevels'],
      custom: { ...incoming.custom, [PUBLIC_STATE_KEY]: publicState },
      onInit: async (payload) => {
        if (onInit) await onInit(payload)
        payload.logger.info(
          options.enabled
            ? `payload-oidc: single sign-on is on for "${options.collection}"; password sign-in is ${options.passwordLogin ? 'open to the break-glass account' : 'off'}.`
            : `payload-oidc: off (issuer, client ID or client secret unset); password sign-in is unchanged.`,
        )
        if (options.enabled) {
          const table = Object.entries(options.roleTable)
            .map(([role, groups]) => `${role} ← ${groups.join(', ')}`)
            .join('; ')
          payload.logger.info(`payload-oidc: role table (highest first): ${table}.`)
          payload.logger.info(
            options.reconcile
              ? `payload-oidc: reconcile runs on queue "${options.reconcile.queue}" (${options.reconcile.cron}); the app must auto-run that queue.`
              : 'payload-oidc: reconcile is off (no source configured); removals apply at the next sign-in only.',
          )
        }
      },
    }
  }
