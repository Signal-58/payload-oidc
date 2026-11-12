import { ObjectId } from 'mongodb'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { clearLinkingSnapshot, takeLinkingSnapshot, type OidcMigrationArgs } from './migration'
import type { ReconcileMember, ReconcileSource } from './options'
import { RECONCILE_HEARTBEAT_KEY } from './reconcile'
import { RECONCILE_TASK_SLUG } from './reconcile-task'
import { OIDC_SYNC_CONTEXT } from './store'
import { databaseUri, jsonRequest, SERVER_URL, startHarness, type Harness } from './test/harness'

/*
 * What an app adopting the plugin leans on, in an app shaped like the next adopters: Payload's
 * `serverURL` unset with the plugin's `serverURL` option set instead (as such an app runs outside
 * production), a required role field, the linking-snapshot migration run in a transaction, and a
 * reconcile run that a deploy cut off. See test/harness.ts for the opt-in.
 */
let now = new Date()
const clock = () => now

/** The fake directory: group → members. */
let directory: Record<string, ReconcileMember[]> = {}
const source: ReconcileSource = {
  cron: '*/15 * * * *',
  fetchGroupMembers: async (groups) =>
    new Map(groups.map((group) => [group, directory[group] ?? []])),
  queue: 'oidc-reconcile',
}

const person = (sub: string, groups = ['cms-test-editor'], email = `${sub}@example.test`) => ({
  email,
  email_verified: true,
  groups,
  sub,
})

describe.skipIf(!databaseUri)('payload-oidc in an adopting app', () => {
  let h: Harness
  const raw = (name: string) => h.payload.db.connection.collection(name)
  const bySubject = (sub: string) => h.users().findOne({ oidcSubject: sub }).lean()

  beforeAll(async () => {
    h = await startHarness({
      clock,
      key: 'adoption',
      plugin: {
        reconcile: source,
        serverURL: SERVER_URL,
      },
      rolesRequired: true,
      withoutServerURL: true,
    })
  })
  afterAll(async () => {
    await h?.stop()
  })
  beforeEach(async () => {
    now = new Date()
    directory = {}
    await h.clear()
    await raw('payload-jobs').deleteMany({})
    await raw('globals').deleteMany({ globalType: 'payload-jobs-stats' })
    await h.payload.kv.delete(RECONCILE_HEARTBEAT_KEY)
  })

  it('signs in on the plugin’s serverURL when Payload’s is unset', async () => {
    expect(h.payload.config.serverURL).toBeFalsy()

    const result = await h.signIn(person('ada', ['cms-test-admin']))
    expect(`${result.callbackUrl.origin}${result.callbackUrl.pathname}`).toBe(
      `${SERVER_URL}/api/users/oidc/callback`,
    )
    expect(result.location).toBe('/admin')
    const auth = await h.payload.auth({
      headers: new Headers({ cookie: result.token!, origin: SERVER_URL }),
    })
    expect(auth.user).toMatchObject({ email: 'ada@example.test', roles: ['admin'] })

    // A second allowed origin still gets its own callback.
    const alt = await h.request('/api/users/oidc/authorize', {
      headers: { 'x-forwarded-host': 'alt.example.test', 'x-forwarded-proto': 'https' },
    })
    expect(new URL(alt.headers.get('location') ?? '').searchParams.get('redirect_uri')).toBe(
      'https://alt.example.test/api/users/oidc/callback',
    )
  })

  it('lets an admin save a disabled user, though the role field is required', async () => {
    const admin = await h.signIn(person('admin', ['cms-test-admin']))
    await h.signIn(person('gone'))
    expect((await h.signIn(person('gone', ['unrelated']))).location).toBe(
      '/admin/login?oidc_error=no_role',
    )
    const gone = await bySubject('gone')
    expect(gone).toMatchObject({ roles: [] })

    const edit = await h.request(
      `/api/users/${String(gone?._id)}`,
      jsonRequest('PATCH', { bio: 'Still credited' }, admin.token),
    )
    expect(edit.status).toBe(200)
    expect(await bySubject('gone')).toMatchObject({ bio: 'Still credited', roles: [] })

    // Anyone not disabled still needs a role, even in a sync write.
    const active = await bySubject('admin')
    await expect(
      h.payload.update({
        collection: 'users',
        context: { [OIDC_SYNC_CONTEXT]: true },
        data: { roles: [] } as never,
        id: String(active?._id),
        overrideAccess: true,
      }),
    ).rejects.toMatchObject({ data: { errors: [expect.objectContaining({ path: 'roles' })] } })
  })

  it('takes the linking snapshot in a migration transaction, once, and clears it', async () => {
    const users = raw('users')
    await users.dropIndex('oidcSubject_1')
    await h.createUser('old@example.test')
    await h.signIn(person('linked'))

    // As `payload migrate` runs a migration: in a transaction, with its session.
    const migrate = async (step: (args: OidcMigrationArgs) => Promise<number>) => {
      const transactionID = await h.payload.db.beginTransaction()
      const session = (h.payload.db as unknown as { sessions: Record<string, unknown> }).sessions[
        String(transactionID)
      ]
      const changed = await step({ payload: h.payload, session })
      await h.payload.db.commitTransaction(transactionID!)
      return changed
    }
    await expect(migrate(takeLinkingSnapshot)).resolves.toBe(1)
    await expect(migrate(takeLinkingSnapshot)).resolves.toBe(0)

    const index = (await users.indexes()).find(({ key }) => 'oidcSubject' in key)
    expect(index).toMatchObject({ sparse: true, unique: true })
    expect(await users.findOne({ email: 'old@example.test' })).toMatchObject({
      oidcLinkable: true,
    })
    expect((await bySubject('linked'))?.oidcLinkable).toBeUndefined()

    // The snapshot user links at their first sign-in.
    await h.signIn(person('old'))
    expect(await users.findOne({ email: 'old@example.test' })).toMatchObject({ oidcSubject: 'old' })

    await users.updateOne({ email: 'old@example.test' }, { $set: { oidcLinkable: true } })
    await expect(migrate(clearLinkingSnapshot)).resolves.toBe(1)
    const cleared = await users.findOne({ email: 'old@example.test' })
    expect(cleared?.oidcLinkable).toBeUndefined()
    expect(cleared).toMatchObject({ oidcSubject: 'old' })
  })

  it('releases a reconcile run a deploy cut off at the next schedule, and runs a new one', async () => {
    const jobs = raw('payload-jobs')
    /** One cron tick: schedule, then run; how many runs it queued and how many it skipped. */
    const tick = async () => {
      const { queued, skipped } = await h.payload.jobs.handleSchedules({ queue: source.queue })
      await h.payload.jobs.run({ queue: source.queue })
      return { queued: queued.length, skipped: skipped.length }
    }
    const queued = (await h.payload.jobs.queue({
      input: {},
      queue: source.queue,
      task: RECONCILE_TASK_SLUG,
    } as never)) as { id: number | string }
    const _id = new ObjectId(String(queued.id))
    /** Leaves the run as a process that died mid-run would: scheduled and still processing. */
    const cutOff = (minutesAgo: number) =>
      jobs.updateOne(
        { _id },
        {
          $set: {
            'meta.scheduled': true,
            processing: true,
            updatedAt: new Date(now.getTime() - minutesAgo * 60e3),
          },
        },
      )

    // Recent enough to be a live run: left alone, and it holds the schedule back.
    await cutOff(5)
    await expect(tick()).resolves.toEqual({ queued: 0, skipped: 1 })
    expect(await jobs.findOne({ _id })).toMatchObject({ processing: true })
    expect(await h.payload.kv.get(RECONCILE_HEARTBEAT_KEY)).toBeNull()

    // Past the threshold: marked failed, and the same tick queues and runs a fresh one.
    await cutOff(11)
    await expect(tick()).resolves.toEqual({ queued: 1, skipped: 0 })
    expect(await jobs.findOne({ _id })).toMatchObject({
      error: { cancelled: true },
      hasError: true,
      processing: false,
    })
    // The new run completed (and Payload deleted it, as it does completed jobs by default).
    expect(await h.payload.kv.get(RECONCILE_HEARTBEAT_KEY)).toMatchObject({
      finishedAt: now.toISOString(),
    })
  })
})
