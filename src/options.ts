import type { PayloadRequest, TaskConfig } from 'payload'

/**
 * Role name → the provider groups that grant it, **highest role first**. A user in groups for
 * several roles gets the first one listed, and a user in none of them gets no role.
 */
export type RoleTable = Readonly<Record<string, readonly string[]>>

/** Hooks for the reconcile task's schedule (Payload's `ScheduleConfig['hooks']`). */
export type ReconcileScheduleHooks = NonNullable<
  NonNullable<NonNullable<TaskConfig['schedule']>[number]['hooks']>
>

/** One member of a role-table group, as the provider's directory reports it. */
export type ReconcileMember = {
  /** Whether the provider still lets this user sign in. Inactive members count as removed. */
  active: boolean
  /** The same value as the ID token's `sub` for this user. */
  subject: string
}

/** Reads the current members of every role-table group from the provider. */
export type ReconcileSource = {
  /**
   * Returns the members of each group. Must throw if any group can't be read: reconcile only acts
   * on a complete answer.
   */
  fetchGroupMembers: (groups: readonly string[]) => Promise<Map<string, ReconcileMember[]>>
  /** How often reconcile runs, as a cron expression. */
  cron: string
  /** The Payload jobs queue the reconcile task runs on. The app must auto-run this queue. */
  queue: string
}

export type OidcPluginOptions = {
  /**
   * Reopens password sign-in, for the `breakGlassEmail` account and, until `linkByEmailUntil`,
   * for users the migration marked `oidcLinkable` who haven't linked yet.
   */
  passwordLogin?: boolean
  /** Text of the admin sign-in button. */
  buttonLabel?: string
  /**
   * The one account that may use a password while `passwordLogin` is on, and that sync and
   * reconcile never disable. Compared case-insensitively.
   */
  breakGlassEmail?: string
  clientId?: string
  clientSecret?: string
  /** The auth collection staff sign in to. */
  collection?: string
  /** Names of the profile fields the provider owns. */
  fields?: { firstName?: string; lastName?: string }
  /**
   * The provider's issuer URL. With it, `clientId` or `clientSecret` unset, the plugin is off:
   * nothing changes and password sign-in works as before.
   */
  issuer?: string
  /** Written to `lastName` when the provider sends no `family_name`. */
  lastNamePlaceholder?: string
  /**
   * Until this date (ISO 8601), a first sign-in may link an existing user that the app's
   * migration marked `oidcLinkable`, by verified email. After it, linking stops.
   */
  linkByEmailUntil?: string
  /** Reconcile source (optional). Without one, removal applies at the next sign-in only. */
  reconcile?: ReconcileSource
  /** The largest share of linked users one reconcile run may disable (at least one always may). */
  reconcileMaxDisableShare?: number
  /** How old the last successful reconcile may be before the health endpoint reports it, in minutes. */
  reconcileHeartbeatMaxMinutes?: number
  /** Fields an anonymised user keeps (by default every profile field is cleared). */
  keepOnRemove?: string[]
  /**
   * Hooks for the reconcile schedule. A `beforeSchedule` hook runs after stale runs are released
   * (`reconcileStaleAfterMinutes`), in place of Payload's default rule.
   */
  reconcileScheduleHooks?: ReconcileScheduleHooks
  /**
   * A reconcile run still processing after this many minutes was cut off, for example by a deploy
   * that replaced the process mid-run, and would block the queue for good. Before each schedule,
   * such runs are marked failed with Payload's own cancel, so a new one can be queued. `false`
   * turns this off.
   */
  reconcileStaleAfterMinutes?: number | false
  /** Who may remove a disabled user. Defaults to nobody, so an app must decide. */
  removeAccess?: (req: PayloadRequest) => boolean | Promise<boolean>
  roles: {
    /** The role field on the auth collection. */
    field: string
    /** Whether the role field stores a list (a `hasMany` select) or a single value. */
    hasMany?: boolean
    table: RoleTable
  }
  /**
   * The public origin the callback is registered under (`<origin>/api/<collection>/oidc/callback`).
   * Defaults to Payload's `serverURL`; set it when that is unset, as some apps do in development.
   */
  serverURL?: string
  /**
   * Further public origins the app is also served from (each registered with the provider as a
   * callback too). Sign-in uses the request's own origin when it is one of these, so its cookie and
   * callback stay on one host; any other origin falls back to `serverURL`.
   */
  additionalServerURLs?: string[]
  /** Scopes requested at sign-in. */
  scopes?: string[]
  /** Idle timeout: the collection's `tokenExpiration`, in hours. */
  sessionHours?: number
  /** Absolute cap on a session from sign-in, in hours. Refresh is refused after it. */
  sessionMaxHours?: number
  /**
   * Allows an `http:` issuer. Only for a provider on the local machine in development or tests;
   * refused when `NODE_ENV` is `production`.
   */
  allowInsecureIssuer?: boolean
}

export type ResolvedOidcOptions = {
  allowInsecureIssuer: boolean
  breakGlassEmail?: string
  buttonLabel: string
  clientId: string
  clientSecret: string
  collection: string
  enabled: boolean
  firstNameField: string
  issuer: string
  lastNameField: string
  lastNamePlaceholder: string
  linkByEmailUntil?: Date
  passwordLogin: boolean
  reconcile?: ReconcileSource
  keepOnRemove: string[]
  reconcileScheduleHooks?: ReconcileScheduleHooks
  /** Unset when releasing stale reconcile runs is off. */
  reconcileStaleAfterSeconds?: number
  reconcileHeartbeatMaxSeconds: number
  reconcileMaxDisableShare: number
  removeAccess: (req: PayloadRequest) => boolean | Promise<boolean>
  roleField: string
  roleHasMany: boolean
  roleTable: RoleTable
  scopes: string[]
  sessionMaxSeconds: number
  sessionSeconds: number
  /** The public origin the callback is registered under, if not Payload's `serverURL`. */
  serverURL?: string
  /** Further allowed public origins, normalised. */
  additionalServerURLs: string[]
  /** Whether the collection uses `auth.verify`; set by the plugin from the collection config. */
  verify: boolean
  /** The collection's `loginWithUsername` setting; set by the plugin from the collection config. */
  loginWithUsername?: { allowEmailLogin: boolean }
}

const positiveHours = (value: number | undefined, fallback: number, name: string): number => {
  const hours = value ?? fallback
  if (!Number.isFinite(hours) || hours <= 0) {
    throw new Error(`payload-oidc: ${name} must be a positive number of hours.`)
  }
  return hours
}

const positiveMinutes = (value: number | undefined, fallback: number, name: string): number => {
  const minutes = value ?? fallback
  if (!Number.isFinite(minutes) || minutes <= 0) {
    throw new Error(`payload-oidc: ${name} must be a positive number of minutes.`)
  }
  return minutes
}

const toOrigin = (url: string, name: string): string => {
  try {
    return new URL(url.trim()).origin
  } catch {
    throw new Error(`payload-oidc: ${name} must be absolute URLs.`)
  }
}

const shareBetweenZeroAndOne = (share: number): number => {
  if (!Number.isFinite(share) || share < 0 || share > 1) {
    throw new Error('payload-oidc: reconcileMaxDisableShare must be between 0 and 1.')
  }
  return share
}

/**
 * Validates the options and fills in defaults. Throws for a configuration that can't be safe,
 * so a mistake fails at startup rather than at someone's first sign-in.
 */
export const resolveOptions = (options: OidcPluginOptions): ResolvedOidcOptions => {
  const issuer = options.issuer?.trim() ?? ''
  const clientId = options.clientId?.trim() ?? ''
  const clientSecret = options.clientSecret ?? ''
  const enabled = Boolean(issuer && clientId && clientSecret)

  const roleTable = options.roles?.table ?? {}
  if (!options.roles?.field) throw new Error('payload-oidc: roles.field is required.')
  if (Object.keys(roleTable).length === 0) {
    throw new Error('payload-oidc: roles.table needs at least one role.')
  }
  for (const [role, groups] of Object.entries(roleTable)) {
    if (!Array.isArray(groups) || groups.length === 0 || groups.some((group) => !group)) {
      throw new Error(`payload-oidc: role "${role}" needs at least one group.`)
    }
  }

  const sessionHours = positiveHours(options.sessionHours, 8, 'sessionHours')
  const sessionMaxHours = positiveHours(options.sessionMaxHours, 12, 'sessionMaxHours')
  if (sessionMaxHours < sessionHours) {
    throw new Error('payload-oidc: sessionMaxHours must be at least sessionHours.')
  }

  let linkByEmailUntil: Date | undefined
  if (options.linkByEmailUntil) {
    linkByEmailUntil = new Date(options.linkByEmailUntil)
    if (Number.isNaN(linkByEmailUntil.getTime())) {
      throw new Error('payload-oidc: linkByEmailUntil must be an ISO 8601 date.')
    }
  }

  if (enabled) {
    const url = new URL(issuer)
    if (url.protocol !== 'https:') {
      if (!options.allowInsecureIssuer || process.env.NODE_ENV === 'production') {
        throw new Error('payload-oidc: the issuer must use https.')
      }
    }
  }

  const breakGlassEmail = options.breakGlassEmail?.trim().toLowerCase() || undefined
  if (enabled && options.passwordLogin && !breakGlassEmail) {
    throw new Error('payload-oidc: passwordLogin needs breakGlassEmail.')
  }

  return {
    allowInsecureIssuer: Boolean(options.allowInsecureIssuer),
    breakGlassEmail,
    buttonLabel: options.buttonLabel ?? 'Sign in with single sign-on',
    clientId,
    clientSecret,
    collection: options.collection ?? 'users',
    enabled,
    firstNameField: options.fields?.firstName ?? 'firstName',
    issuer,
    lastNameField: options.fields?.lastName ?? 'lastName',
    lastNamePlaceholder: options.lastNamePlaceholder ?? '-',
    linkByEmailUntil,
    passwordLogin: Boolean(options.passwordLogin),
    reconcile: options.reconcile,
    keepOnRemove: options.keepOnRemove ?? [],
    reconcileScheduleHooks: options.reconcileScheduleHooks,
    reconcileStaleAfterSeconds:
      options.reconcileStaleAfterMinutes === false
        ? undefined
        : Math.round(
            positiveMinutes(options.reconcileStaleAfterMinutes, 10, 'reconcileStaleAfterMinutes') *
              60,
          ),
    reconcileHeartbeatMaxSeconds: Math.round(
      positiveHours(
        (options.reconcileHeartbeatMaxMinutes ?? 45) / 60,
        0.75,
        'reconcileHeartbeatMaxMinutes',
      ) * 3600,
    ),
    reconcileMaxDisableShare: shareBetweenZeroAndOne(options.reconcileMaxDisableShare ?? 0.25),
    removeAccess: options.removeAccess ?? (() => false),
    roleField: options.roles.field,
    roleHasMany: options.roles.hasMany ?? true,
    roleTable,
    scopes: options.scopes ?? ['openid', 'email', 'profile'],
    sessionMaxSeconds: Math.round(sessionMaxHours * 3600),
    sessionSeconds: Math.round(sessionHours * 3600),
    serverURL: options.serverURL ? toOrigin(options.serverURL, 'serverURL') : undefined,
    additionalServerURLs: (options.additionalServerURLs ?? [])
      .map((url) => url.trim())
      .filter(Boolean)
      .map((url) => toOrigin(url, 'additionalServerURLs')),
    verify: false,
  }
}

/**
 * The role a user's groups grant: the first role in the table with a matching group.
 *
 * @param table - The role table, highest role first.
 * @param groups - The `groups` claim (or a reconcile member's groups); anything else is no role.
 * @returns The role, or `undefined` for none.
 */
export const roleForGroups = (table: RoleTable, groups: unknown): string | undefined => {
  if (!Array.isArray(groups)) return undefined
  const names = new Set(groups.filter((group): group is string => typeof group === 'string'))
  for (const [role, roleGroups] of Object.entries(table)) {
    if (roleGroups.some((group) => names.has(group))) return role
  }
  return undefined
}

/** Every group named in the role table, once. */
export const roleTableGroups = (table: RoleTable): string[] => [
  ...new Set(Object.values(table).flat()),
]

/** Whether an email is the break-glass account's. */
export const isBreakGlassEmail = (options: ResolvedOidcOptions, email: unknown): boolean =>
  Boolean(
    options.breakGlassEmail &&
    typeof email === 'string' &&
    email.trim().toLowerCase() === options.breakGlassEmail,
  )

/** Whether linking by email is still allowed at `now`. */
export const canLinkByEmail = (options: ResolvedOidcOptions, now: Date): boolean =>
  Boolean(options.linkByEmailUntil && now < options.linkByEmailUntil)
