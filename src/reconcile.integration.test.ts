import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import type { ReconcileMember, ReconcileSource } from './options'
import { resolveOptions } from './options'
import { RECONCILE_HEARTBEAT_KEY, reconcileUsers } from './reconcile'
import { BREAK_GLASS, databaseUri, jsonRequest, startHarness, type Harness } from './test/harness'

/*
 * Reconcile and removal against a real Payload on MongoDB, with a fake reconcile source standing
 * in for the provider's directory. See test/harness.ts for the opt-in.
 */
let now = new Date()
const clock = () => now

/** The fake directory: group → members. A group set to `null` fails to load. */
let directory: Record<string, ReconcileMember[] | null> = {}
/** Runs while the groups are being fetched, to simulate activity during a run. */
let duringFetch: () => Promise<void> = async () => {}
const source: ReconcileSource = {
  cron: '*/15 * * * *',
  fetchGroupMembers: async (groups) => {
    await duringFetch()
    return new Map(
      groups.map((group) => {
        const members = directory[group]
        if (members === null) throw new Error(`cannot read ${group}`)
        return [group, members ?? []]
      }),
    )
  },
  queue: 'oidc-reconcile',
}

const active = (...subjects: string[]) => subjects.map((subject) => ({ active: true, subject }))

describe.skipIf(!databaseUri)('payload-oidc reconcile and removal', () => {
  let h: Harness
  const run = () =>
    reconcileUsers(h.payload, resolveOptions({ ...h.pluginOptions, reconcile: source }), now)
  const bySubject = (sub: string) => h.users().findOne({ oidcSubject: sub }).lean()

  /** Signs in a user per subject, all as editors. */
  const signInEditors = async (...subjects: string[]) => {
    directory = { 'cms-test-editor': active(...subjects) }
    for (const sub of subjects) {
      await h.signIn({
        email: `${sub}@example.test`,
        email_verified: true,
        groups: ['cms-test-editor'],
        sub,
      })
    }
  }

  beforeAll(async () => {
    h = await startHarness({
      clock,
      key: 'reconcile',
      plugin: {
        reconcile: source,
        removeAccess: ({ user }) =>
          (user as { roles?: string[] } | null)?.roles?.includes('superadmin') === true,
      },
    })
  })
  afterAll(async () => {
    await h?.stop()
  })
  beforeEach(async () => {
    now = new Date()
    directory = {}
    duringFetch = async () => {}
    await h.clear()
    await h.payload.delete({
      collection: 'posts',
      overrideAccess: true,
      where: { id: { exists: true } },
    })
  })

  it('disables removed and deactivated users, follows role changes, and records a heartbeat', async () => {
    await signInEditors('a', 'b', 'c', 'd', 'e')
    directory = {
      'cms-test-admin': active('b'),
      'cms-test-editor': [...active('a', 'c', 'e'), { active: false, subject: 'd' }],
    }
    const result = await run()
    expect(result).toMatchObject({ disabled: 1, roleChanges: 1, users: 5 })
    expect(await bySubject('d')).toMatchObject({ roles: [], sessions: [] })
    expect((await bySubject('d'))?.oidcDisabledAt).toBeInstanceOf(Date)
    expect(await bySubject('b')).toMatchObject({ roles: ['admin'] })
    expect(
      (await h.payload.kv.get<{ finishedAt: string }>(RECONCILE_HEARTBEAT_KEY))?.finishedAt,
    ).toBe(now.toISOString())
    // Running again changes nothing.
    expect(await run()).toMatchObject({ disabled: 0, roleChanges: 0 })
  })

  it('re-disables a disabled user whose role or sessions came back, and never touches break-glass', async () => {
    await signInEditors('f', 'g', 'h', 'i')
    directory = { 'cms-test-editor': active('g', 'h', 'i') }
    await run()
    const f = await bySubject('f')
    await h
      .users()
      .updateOne(
        { _id: f?._id },
        { $set: { roles: ['editor'], sessions: [{ createdAt: now, expiresAt: now, id: 'back' }] } },
      )
    await run()
    expect(await bySubject('f')).toMatchObject({ roles: [], sessions: [] })

    const breakGlass = await h.createUser(BREAK_GLASS, { roles: ['superadmin'] })
    await h.users().updateOne({ _id: breakGlass.id }, { $set: { oidcSubject: 'sub-bg' } })
    await run()
    expect(await h.users().findOne({ _id: breakGlass.id }).lean()).toMatchObject({
      roles: ['superadmin'],
    })
  })

  it('changes nothing when a group fails to load or too many would be disabled', async () => {
    await signInEditors('j', 'k', 'l', 'm', 'n', 'o', 'p', 'q')
    directory = { 'cms-test-admin': null, 'cms-test-editor': [] }
    await expect(run()).rejects.toThrow(/cannot read cms-test-admin/)
    directory = { 'cms-test-editor': active('j', 'k', 'l', 'm', 'n') }
    await expect(run()).rejects.toThrow(/would disable 3 of 8 enabled users \(more than 2\)/)
    for (const sub of ['o', 'p', 'q'])
      expect(await bySubject(sub)).toMatchObject({ roles: ['editor'] })
    expect(await h.payload.kv.get(RECONCILE_HEARTBEAT_KEY)).toBeDefined()
  })

  it('counts only enabled users towards the safety stop', async () => {
    await signInEditors('e1', 'e2', 'e3', 'e4', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8')
    for (const sub of ['x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7', 'x8']) {
      await h
        .users()
        .updateOne({ oidcSubject: sub }, { $set: { oidcDisabledAt: now, roles: [], sessions: [] } })
    }
    // The editor group emptied by mistake: 4 of 4 enabled users would go.
    directory = { 'cms-test-editor': [] }
    await expect(run()).rejects.toThrow(/would disable 4 of 4 enabled users \(more than 1\)/)
    for (const sub of ['e1', 'e2', 'e3', 'e4'])
      expect(await bySubject(sub)).toMatchObject({ roles: ['editor'] })
  })

  it('leaves a user who changed during the run for the next one', async () => {
    await signInEditors('busy', 'calm', 'calm2', 'calm3')
    directory = { 'cms-test-editor': active('calm', 'calm2', 'calm3') }
    duringFetch = async () => {
      // A sign-in syncs the user while the groups are being read.
      await h.users().updateOne({ oidcSubject: 'busy' }, { $set: { updatedAt: new Date() } })
    }
    expect(await run()).toMatchObject({ disabled: 0 })
    expect(await bySubject('busy')).toMatchObject({ roles: ['editor'] })
    duringFetch = async () => {}
    expect(await run()).toMatchObject({ disabled: 1 })
  })

  it('runs on every cron tick, even with no record of the last schedule', async () => {
    const tick = async (at: string) => {
      now = new Date(at)
      await h.payload.jobs.handleSchedules({ queue: source.queue })
      await h.payload.jobs.run({ queue: source.queue })
      const heartbeat = await h.payload.kv.get<{ finishedAt: string }>(RECONCILE_HEARTBEAT_KEY)
      return heartbeat?.finishedAt
    }
    await h.payload.db.connection
      .collection('globals')
      .deleteMany({ globalType: 'payload-jobs-stats' })

    await expect(tick('2026-01-01T00:00:00.000Z')).resolves.toBe('2026-01-01T00:00:00.000Z')
    await expect(tick('2026-01-01T00:15:00.000Z')).resolves.toBe('2026-01-01T00:15:00.000Z')
    await expect(tick('2026-01-01T00:30:00.000Z')).resolves.toBe('2026-01-01T00:30:00.000Z')
  })

  it('reports reconcile health from the heartbeat', async () => {
    await h.payload.kv.set(RECONCILE_HEARTBEAT_KEY, {
      disabled: 0,
      finishedAt: new Date(now.getTime() - 10 * 60e3).toISOString(),
      roleChanges: 0,
      users: 0,
    })
    expect((await h.request('/api/users/oidc/reconcile/health')).status).toBe(200)
    await h.payload.kv.set(RECONCILE_HEARTBEAT_KEY, {
      disabled: 0,
      finishedAt: new Date(now.getTime() - 60 * 60e3).toISOString(),
      roleChanges: 0,
      users: 0,
    })
    const stale = await h.request('/api/users/oidc/reconcile/health')
    expect(stale.status).toBe(503)
    expect(Object.keys(await stale.json()).sort()).toEqual(['healthy', 'lastSuccessAt'])
  })

  it('removes only disabled users, deleting the unreferenced and anonymising the rest', async () => {
    const boss = await h.signIn({
      email: 'boss@example.test',
      email_verified: true,
      groups: ['org-admins'],
      sub: 'boss',
    })
    const editorSession = await h.signIn({
      email: 'ed@example.test',
      email_verified: true,
      groups: ['cms-test-editor'],
      sub: 'ed',
    })
    await signInEditors('lone', 'byline', 'credited', 'owner', 'drafted')
    const id = async (sub: string) => String((await bySubject(sub))?._id)
    await h.payload.create({
      collection: 'posts',
      data: { author: await id('byline') },
      overrideAccess: true,
    })
    await h.payload.create({
      collection: 'posts',
      data: { credits: [{ person: await id('credited') }] },
      overrideAccess: true,
    })
    await h.payload.create({
      collection: 'posts',
      data: { owner: { relationTo: 'users', value: await id('owner') } },
      overrideAccess: true,
    })
    const post = await h.payload.create({
      collection: 'posts',
      data: {},
      draft: false,
      overrideAccess: true,
    })
    await h.payload.update({
      collection: 'posts',
      data: { author: await id('drafted') },
      draft: true,
      id: post.id,
      overrideAccess: true,
    })

    const remove = (sub: string, cookie = boss.token) =>
      id(sub).then((userId) =>
        h.request(`/api/users/oidc/remove/${userId}`, jsonRequest('POST', undefined, cookie)),
      )
    // Active users can't be removed, and only a superadmin may remove.
    expect((await remove('lone')).status).toBe(409)
    for (const sub of ['lone', 'byline', 'credited', 'owner', 'drafted']) {
      await h.users().updateOne({ oidcSubject: sub }, { $set: { oidcDisabledAt: now, roles: [] } })
    }
    expect((await remove('lone', editorSession.token)).status).toBe(403)
    expect((await remove('lone', '')).status).toBe(401)

    const loneId = await id('lone')
    expect(await (await remove('lone')).json()).toEqual({ result: 'deleted' })
    expect(await h.users().findOne({ _id: loneId }).lean()).toBeNull()

    await h
      .users()
      .updateOne(
        { oidcSubject: 'byline' },
        { $set: { bio: 'Comedian from Chicago', loginAttempts: 2, resetPasswordToken: 'pending' } },
      )
    for (const sub of ['byline', 'credited', 'owner', 'drafted']) {
      const userId = await id(sub)
      expect(await (await remove(sub)).json(), sub).toEqual({ result: 'anonymised' })
      const anonymised = await h.users().findOne({ _id: userId }).lean()
      expect(anonymised).toMatchObject({
        email: `removed-${userId}@removed.invalid`,
        firstName: 'Removed',
        lastName: 'user',
        sessions: [],
      })
      expect(anonymised?.oidcSubject).toBeUndefined()
      for (const field of ['bio', 'loginAttempts', 'resetPasswordToken']) {
        expect(anonymised?.[field], `${sub}.${field}`).toBeUndefined()
      }
      // Payload can still save the anonymised record (its email passes Payload's check).
      await h.payload.update({ collection: 'users', data: {}, id: userId, overrideAccess: true })
    }
    // Added back at the provider, they sign in as a new user.
    const anonymisedId = await h
      .users()
      .findOne({ email: { $regex: '^removed-' } })
      .lean()
    await h.signIn({
      email: 'byline@example.test',
      email_verified: true,
      groups: ['cms-test-editor'],
      sub: 'byline',
    })
    const returned = await bySubject('byline')
    expect(returned).toMatchObject({ email: 'byline@example.test', roles: ['editor'] })
    expect(String(returned?._id)).not.toBe(String(anonymisedId?._id))
  })
})
