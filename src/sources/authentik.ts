import type { ReconcileMember, ReconcileSource } from '../options'

type AuthentikGroup = {
  name?: unknown
  users_obj?: Array<{ is_active?: unknown; uid?: unknown }> | null
}

/**
 * A reconcile source that reads the role-table groups' members from Authentik's API.
 *
 * The token needs only object-level `view_group` on those groups: reading a group returns its
 * direct members with their `uid`, which equals the OIDC `sub` when the provider's subject mode
 * is "based on the user's hashed ID". Every group must exist and be readable, or the fetch throws
 * and reconcile changes nothing.
 *
 * @param options.url - Authentik's base URL, such as `https://auth.example.com`.
 * @param options.token - An API token for a service account with `view_group` on the groups.
 * @param options.queue - The Payload jobs queue the reconcile task runs on.
 * @param options.cron - How often it runs (default every 15 minutes).
 * @param options.fetch - For tests.
 */
export const authentikSource = (options: {
  /** Allows an `http:` URL, for a local Authentik; refused when `NODE_ENV` is `production`. */
  allowInsecure?: boolean
  cron?: string
  fetch?: typeof fetch
  queue?: string
  /** Per request, in milliseconds (default 30 seconds). */
  timeoutMs?: number
  token?: string
  url?: string
}): ReconcileSource | undefined => {
  const url = options.url?.trim().replace(/\/+$/, '')
  const token = options.token?.trim()
  if (!url || !token) return undefined
  // The token travels in the Authorization header: never in clear text outside local development.
  if (new URL(url).protocol !== 'https:') {
    if (!options.allowInsecure || process.env.NODE_ENV === 'production') {
      throw new Error('payload-oidc: the Authentik reconcile URL must use https.')
    }
  }
  const request = options.fetch ?? fetch
  const timeoutMs = options.timeoutMs ?? 30_000

  const fetchGroup = async (name: string): Promise<ReconcileMember[]> => {
    const query = new URLSearchParams({ include_users: 'true', name, page_size: '2' })
    const response = await request(`${url}/api/v3/core/groups/?${query}`, {
      headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeoutMs),
    })
    if (!response.ok) throw new Error(`Authentik answered ${response.status} for group ${name}.`)
    const body = (await response.json()) as { results?: AuthentikGroup[] }
    const matches = (body.results ?? []).filter((group) => group.name === name)
    // A missing group (renamed, or the token lost its permission) is a failure, not an empty one:
    // otherwise a whole tier would be disabled.
    if (matches.length !== 1) throw new Error(`Authentik group ${name} not found or not readable.`)
    const members = matches[0].users_obj
    if (!Array.isArray(members)) throw new Error(`Authentik returned no members for ${name}.`)
    return members.map((member) => {
      if (typeof member.uid !== 'string' || !member.uid) {
        throw new Error(`Authentik returned a member of ${name} without a uid.`)
      }
      return { active: member.is_active === true, subject: member.uid }
    })
  }

  return {
    cron: options.cron ?? '*/15 * * * *',
    fetchGroupMembers: async (groups) => {
      const entries = await Promise.all(
        groups.map(async (group) => [group, await fetchGroup(group)] as const),
      )
      return new Map(entries)
    },
    queue: options.queue ?? 'oidc-reconcile',
  }
}
