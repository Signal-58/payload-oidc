import type { Payload } from 'payload'

import {
  isBreakGlassEmail,
  roleForGroups,
  roleTableGroups,
  type ResolvedOidcOptions,
} from './options'
import { authCollectionModel, disableUser, OIDC_FIELDS, roleValue, type StoredUser } from './store'

/** KV key of the last successful reconcile run. */
export const RECONCILE_HEARTBEAT_KEY = 'payload-oidc:reconcile'

export type ReconcileHeartbeat = {
  disabled: number
  finishedAt: string
  roleChanges: number
  users: number
}

export type ReconcileResult = ReconcileHeartbeat

/**
 * Brings every linked user in line with the provider's groups:
 *
 * - A user whose subject is in no role-table group, or only as an inactive member, is disabled
 *   (again, if a whole-document write restored their role or sessions).
 * - An enabled user whose role changed gets the new role. A disabled user stays disabled until
 *   they sign in again.
 * - Users are never created, and the break-glass account and unlinked users are never touched.
 *
 * It changes nothing unless every group was read, and stops without changes if it would disable
 * more than `maxDisableShare` of the linked users (at least one is always allowed), so a renamed
 * group or a lost permission can't disable a whole tier. Each successful run records a heartbeat.
 *
 * @throws When a group can't be read or a safety stop trips: the job fails and alerts.
 */
export const reconcileUsers = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  now: Date = new Date(),
): Promise<ReconcileResult> => {
  const source = options.reconcile
  if (!source) throw new Error('payload-oidc: reconcile is not configured.')

  // Users first, then groups: every write below is conditional on the user being unchanged
  // since this read, so someone who signs in (and is synced) while the groups are fetched is left
  // for the next run instead of being judged on a stale snapshot.
  const model = authCollectionModel(payload, options.collection)
  const linked = await model.find({ [OIDC_FIELDS.subject]: { $exists: true } }).lean()

  const groups = roleTableGroups(options.roleTable)
  const members = await source.fetchGroupMembers(groups)
  const groupsBySubject = new Map<string, string[]>()
  for (const group of groups) {
    const list = members.get(group)
    if (!list) throw new Error(`payload-oidc: reconcile got no answer for group ${group}.`)
    for (const member of list) {
      if (!member.active) continue
      groupsBySubject.set(member.subject, [...(groupsBySubject.get(member.subject) ?? []), group])
    }
  }

  const unchanged = (user: StoredUser) => ({
    _id: user._id,
    [OIDC_FIELDS.subject]: user[OIDC_FIELDS.subject],
    updatedAt: user.updatedAt ?? null,
  })
  const newlyDisabled: StoredUser[] = []
  const redisabled: StoredUser[] = []
  const toChange: Array<{ role: string; user: StoredUser }> = []
  let enabled = 0
  for (const user of linked) {
    if (isBreakGlassEmail(options, user.email)) continue
    const isDisabled = Boolean(user[OIDC_FIELDS.disabledAt])
    if (!isDisabled) enabled += 1
    const role = roleForGroups(
      options.roleTable,
      groupsBySubject.get(String(user[OIDC_FIELDS.subject])),
    )
    const stored = user[options.roleField]
    const hasRole = Array.isArray(stored) ? stored.length > 0 : Boolean(stored)
    const sessions = Array.isArray(user.sessions) ? user.sessions.length : 0
    if (!role) {
      if (!isDisabled) newlyDisabled.push(user)
      // Disabled already, but a whole-document write restored the role or sessions.
      else if (hasRole || sessions > 0) redisabled.push(user)
      continue
    }
    if (isDisabled) continue
    if (JSON.stringify(stored) !== JSON.stringify(roleValue(options, role))) {
      toChange.push({ role, user })
    }
  }

  // The share counts enabled users only: disabled ones that were never removed would otherwise
  // inflate it until a whole tier fits under the limit.
  const allowed = Math.max(1, Math.floor(enabled * options.reconcileMaxDisableShare))
  if (newlyDisabled.length > allowed) {
    throw new Error(
      `payload-oidc: reconcile would disable ${newlyDisabled.length} of ${enabled} enabled users (more than ${allowed}); nothing was changed. If that is intended, raise reconcileMaxDisableShare for one run.`,
    )
  }

  let disabled = 0
  for (const user of [...newlyDisabled, ...redisabled]) {
    if (await disableUser(payload, options, user._id, now, unchanged(user))) disabled += 1
  }
  let roleChanges = 0
  for (const { role, user } of toChange) {
    // Only while still enabled and unchanged: a disable or a sign-in that landed meanwhile wins.
    const result = await model.updateOne(
      { ...unchanged(user), [OIDC_FIELDS.disabledAt]: null },
      { $set: { [options.roleField]: roleValue(options, role), updatedAt: now } },
    )
    if (result.matchedCount > 0) roleChanges += 1
  }

  const heartbeat: ReconcileHeartbeat = {
    disabled,
    finishedAt: now.toISOString(),
    roleChanges,
    users: linked.length,
  }
  await payload.kv.set(RECONCILE_HEARTBEAT_KEY, heartbeat)
  payload.logger.info({ msg: 'payload-oidc: reconcile finished', ...heartbeat })
  return heartbeat
}

/** Whether the last successful run is recent enough, for a status check such as Gatus. */
export const reconcileHealth = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  now: Date = new Date(),
): Promise<{ healthy: boolean; lastSuccessAt: string | null }> => {
  const heartbeat = await payload.kv.get<ReconcileHeartbeat>(RECONCILE_HEARTBEAT_KEY)
  const finishedAt = heartbeat?.finishedAt ? new Date(heartbeat.finishedAt) : undefined
  const healthy = Boolean(
    finishedAt &&
    now.getTime() - finishedAt.getTime() <= options.reconcileHeartbeatMaxSeconds * 1000,
  )
  return { healthy, lastSuccessAt: heartbeat?.finishedAt ?? null }
}
