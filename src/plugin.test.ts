import type { CollectionConfig, Config, Field, SelectField, Validate } from 'payload'
import { describe, expect, it, vi } from 'vitest'

import { OIDC_REFUSAL_NAME, OidcRefusal } from './before-operation'
import { oidcPlugin, PUBLIC_STATE_KEY, syncWriteOnly } from './plugin'
import { OIDC_SYNC_CONTEXT } from './store'

const usersCollection = (roles: Partial<SelectField> = {}): CollectionConfig => ({
  slug: 'users',
  auth: { tokenExpiration: 7200 },
  fields: [
    {
      type: 'row',
      fields: [
        { name: 'firstName', type: 'text', required: true },
        { name: 'lastName', type: 'text', required: true },
      ],
    },
    {
      name: 'roles',
      type: 'select',
      hasMany: true,
      options: ['admin', 'editor'],
      ...roles,
    } as Field,
  ],
})

const baseConfig = (roles?: Partial<SelectField>): Config =>
  ({ collections: [usersCollection(roles), { slug: 'pages', fields: [] }], secret: 's' }) as Config

const options = {
  clientId: 'client',
  clientSecret: 'secret',
  issuer: 'https://idp.example/',
  roles: { field: 'roles', table: { admin: ['g-admin'], editor: ['g-editor'] } },
}

const apply = (pluginOptions: Parameters<typeof oidcPlugin>[0]) =>
  oidcPlugin(pluginOptions)(baseConfig()) as Config

const users = (config: Config) => config.collections!.find(({ slug }) => slug === 'users')!

/** The client props of the sidebar component that hides "Change Password". */
const sidebarProps = (collection: CollectionConfig) =>
  (
    field(collection, 'oidcRemove') as {
      admin: { components: { Field: { clientProps: { hidePasswordChange: boolean } } } }
    }
  ).admin.components.Field.clientProps

const field = (collection: CollectionConfig, name: string): Field | undefined => {
  const all = collection.fields.flatMap((candidate) =>
    candidate.type === 'row' ? candidate.fields : [candidate],
  )
  return all.find((candidate) => 'name' in candidate && candidate.name === name)
}

describe('oidcPlugin', () => {
  it('is inert when unconfigured: same session length, no locked fields, same shape otherwise', () => {
    const config = apply({ ...options, issuer: undefined })
    const collection = users(config)
    expect(collection.auth).toEqual({ tokenExpiration: 7200 })
    expect((field(collection, 'firstName') as { access?: unknown }).access).toBeUndefined()
    expect(field(collection, 'oidcSubject')).toBeDefined()
    expect(collection.endpoints).toHaveLength(4)
    expect(collection.access).toBeUndefined()
    expect(sidebarProps(collection)).toEqual({ hidePasswordChange: false })
    expect(config.custom?.[PUBLIC_STATE_KEY]).toMatchObject({ enabled: false })
  })

  it('when on, sets the idle timeout and lets only sync update the provider-owned fields', () => {
    const config = apply(options)
    const collection = users(config)
    expect(collection.auth).toMatchObject({ tokenExpiration: 8 * 3600, useSessions: true })
    for (const name of ['email', 'firstName', 'lastName', 'roles']) {
      const access = (field(collection, name) as { access?: { update?: unknown } }).access
      expect(access?.update, name).toBe(syncWriteOnly)
    }
    expect(syncWriteOnly({ req: { context: { [OIDC_SYNC_CONTEXT]: true } } } as never)).toBe(true)
    expect(syncWriteOnly({ req: { context: {} } } as never)).toBe(false)
    expect(collection.hooks?.beforeOperation).toHaveLength(1)
    expect(config.admin?.components?.beforeLogin).toContain(
      '@signal58/payload-oidc/rsc#OidcLoginButton',
    )
    expect(config.custom?.[PUBLIC_STATE_KEY]).toEqual({
      authorizePath: '/api/users/oidc/authorize',
      buttonLabel: 'Sign in with single sign-on',
      enabled: true,
      passwordLogin: false,
    })
  })

  it('when on, hides the password controls Payload would show, and logs refusals at info', () => {
    const collection = users(apply(options))
    expect(collection.access?.unlock?.({} as never)).toBe(false)
    expect(sidebarProps(collection)).toEqual({ hidePasswordChange: true })
    // The break-glass account changes its own password while password sign-in is on.
    const breakGlass = users(
      apply({ ...options, breakGlassEmail: 'ops@example.test', passwordLogin: true }),
    )
    expect(sidebarProps(breakGlass)).toEqual({ hidePasswordChange: false })

    const refusal = new OidcRefusal('Password sign-in is turned off.')
    expect(refusal).toMatchObject({ isPublic: true, name: OIDC_REFUSAL_NAME, status: 403 })
    expect(apply(options).loggingLevels).toMatchObject({ [OIDC_REFUSAL_NAME]: 'info' })
  })

  it('keeps secrets out of the public state', () => {
    const config = apply(options)
    expect(JSON.stringify(config.custom)).not.toContain('secret')
  })

  it('refuses a missing or non-auth collection', () => {
    expect(() => oidcPlugin({ ...options, collection: 'nope' })(baseConfig())).toThrow(/no "nope"/)
    expect(() => oidcPlugin({ ...options, collection: 'pages' })(baseConfig())).toThrow(
      /not an auth collection/,
    )
  })
})

describe('role field validation', () => {
  /** Validation arguments as Payload passes them, with a translator that returns the key. */
  const args = (siblingData: Record<string, unknown>) =>
    ({ req: { t: (key: string) => key }, siblingData }) as never
  const disabled = { oidcDisabledAt: '2026-11-01T00:00:00.000Z' }
  const roleValidate = (config: Config) =>
    (field(users(config), 'roles') as { validate: Validate }).validate

  it('allows no role on a disabled user only, keeping Payload’s own checks otherwise', async () => {
    const validate = roleValidate(oidcPlugin(options)(baseConfig({ required: true })) as Config)
    expect(await validate([], args(disabled))).toBe(true)
    expect(await validate([], args({}))).toBe('validation:required')
    expect(await validate([], args({ oidcDisabledAt: null }))).toBe('validation:required')
    expect(await validate(['editor'], args({}))).toBe(true)
    // Unknown options are still refused, disabled or not.
    expect(await validate(['owner'], args(disabled))).toBe('validation:invalidSelection')
  })

  it('handles a single-value role field', async () => {
    const validate = roleValidate(
      oidcPlugin({ ...options, roles: { ...options.roles, hasMany: false } })(
        baseConfig({ hasMany: false, required: true }),
      ) as Config,
    )
    expect(await validate(null, args(disabled))).toBe(true)
    expect(await validate(null, args({}))).toBe('validation:required')
    expect(await validate('admin', args({}))).toBe(true)
  })

  it('passes everything else to the app’s own validate', async () => {
    const own = vi.fn(() => 'from the app')
    const validate = roleValidate(oidcPlugin(options)(baseConfig({ validate: own })) as Config)
    expect(await validate([], args(disabled))).toBe(true)
    expect(own).not.toHaveBeenCalled()
    const editorArgs = args({})
    expect(await validate(['editor'], editorArgs)).toBe('from the app')
    expect(own).toHaveBeenCalledExactlyOnceWith(['editor'], editorArgs)
  })

  it('applies while sign-in is off too, without editing the app’s field config', async () => {
    const config = baseConfig({ required: true })
    const original = field(config.collections![0], 'roles')
    const validate = roleValidate(oidcPlugin({ ...options, issuer: undefined })(config) as Config)
    expect(await validate([], args(disabled))).toBe(true)
    expect(await validate([], args({}))).toBe('validation:required')
    expect((original as { validate?: unknown }).validate).toBeUndefined()
  })
})
