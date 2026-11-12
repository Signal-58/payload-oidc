import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'

import { resolveOptions, type OidcPluginOptions, type ReconcileSource } from './options'
import { createReconcileTask, RECONCILE_TASK_SLUG, releaseStaleRuns } from './reconcile-task'

const source: ReconcileSource = {
  cron: '*/15 * * * *',
  fetchGroupMembers: async () => new Map(),
  queue: 'oidc-reconcile',
}

const base: OidcPluginOptions = {
  clientId: 'client',
  clientSecret: 'secret',
  issuer: 'https://idp.example/',
  reconcile: source,
  roles: { field: 'roles', table: { admin: ['g-admin'] } },
}

const now = new Date('2026-11-12T12:00:00.000Z')
const staleJob = {
  createdAt: '2026-11-12T11:30:00.000Z',
  id: 'job-1',
  updatedAt: '2026-11-12T11:30:05.000Z',
}

/** The first find returns the stale runs; the second reads back the ones cancel marked. */
const fakePayload = (stale: unknown[], released = stale) => {
  const find = vi
    .fn()
    .mockResolvedValueOnce({ docs: stale })
    .mockResolvedValueOnce({ docs: released })
  const cancel = vi.fn().mockResolvedValue(undefined)
  const logger = { error: vi.fn(), warn: vi.fn() }
  const payload = { find, jobs: { cancel }, logger } as unknown as Payload
  return { cancel, find, logger, payload }
}

const beforeScheduleOf = (options: OidcPluginOptions) => {
  const hook = createReconcileTask(resolveOptions(options), { clock: () => now }).schedule?.[0]
    ?.hooks?.beforeSchedule
  if (!hook) throw new Error('no beforeSchedule hook')
  return hook
}

const scheduleArgs = (payload: Payload, defaultResult = { shouldSchedule: true }) => {
  const defaultBeforeSchedule = vi
    .fn()
    .mockResolvedValue({ ...defaultResult, waitUntil: new Date('2026-11-12T12:15:00.000Z') })
  const args = {
    defaultBeforeSchedule,
    jobStats: {},
    queueable: {
      scheduleConfig: { cron: source.cron, queue: source.queue },
      taskConfig: { slug: RECONCILE_TASK_SLUG },
    },
    req: { payload },
  } as never
  return { args, defaultBeforeSchedule }
}

describe('releaseStaleRuns', () => {
  it('finds unfinished reconcile runs on the queue last updated before the threshold', async () => {
    const { cancel, find, payload } = fakePayload([])
    await expect(
      releaseStaleRuns(payload, { now, olderThanSeconds: 600, queue: 'oidc-reconcile' }),
    ).resolves.toEqual([])
    expect(find.mock.calls[0]?.[0]).toMatchObject({
      collection: 'payload-jobs',
      overrideAccess: true,
      pagination: false,
      where: {
        and: [
          { processing: { equals: true } },
          { completedAt: { exists: false } },
          { hasError: { not_equals: true } },
          { queue: { equals: 'oidc-reconcile' } },
          { taskSlug: { equals: RECONCILE_TASK_SLUG } },
          { updatedAt: { less_than: '2026-11-12T11:50:00.000Z' } },
        ],
      },
    })
    expect(cancel).not.toHaveBeenCalled()
  })

  it('cancels stale runs that are still processing, and logs each one it marked', async () => {
    const { cancel, logger, payload } = fakePayload([staleJob])
    await expect(
      releaseStaleRuns(payload, { now, olderThanSeconds: 600, queue: 'oidc-reconcile' }),
    ).resolves.toEqual(['job-1'])
    expect(cancel).toHaveBeenCalledExactlyOnceWith({
      overrideAccess: true,
      where: { and: [{ id: { in: ['job-1'] } }, { processing: { equals: true } }] },
    })
    expect(logger.warn).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({
        jobId: 'job-1',
        msg: expect.stringContaining('still processing after 600 seconds'),
      }),
    )
  })

  it('reports only the runs cancel changed, leaving one that finished in between', async () => {
    const { logger, payload } = fakePayload([staleJob], [])
    await expect(
      releaseStaleRuns(payload, { now, olderThanSeconds: 600, queue: 'oidc-reconcile' }),
    ).resolves.toEqual([])
    expect(logger.warn).not.toHaveBeenCalled()
  })
})

describe('the reconcile schedule', () => {
  it('releases stale runs before Payload’s rule, by default after 10 minutes', async () => {
    const { cancel, find, payload } = fakePayload([staleJob])
    const { args, defaultBeforeSchedule } = scheduleArgs(payload)
    await expect(beforeScheduleOf(base)(args)).resolves.toEqual({
      shouldSchedule: true,
      waitUntil: undefined,
    })
    expect(find.mock.calls[0]?.[0].where.and).toContainEqual({
      updatedAt: { less_than: '2026-11-12T11:50:00.000Z' },
    })
    expect(cancel.mock.invocationCallOrder[0]).toBeLessThan(
      defaultBeforeSchedule.mock.invocationCallOrder[0] ?? 0,
    )
  })

  it('takes its threshold from reconcileStaleAfterMinutes', async () => {
    const { find, payload } = fakePayload([])
    await beforeScheduleOf({ ...base, reconcileStaleAfterMinutes: 45 })(scheduleArgs(payload).args)
    expect(find.mock.calls[0]?.[0].where.and).toContainEqual({
      updatedAt: { less_than: '2026-11-12T11:15:00.000Z' },
    })
  })

  it('leaves runs alone when turned off', async () => {
    const { find, payload } = fakePayload([staleJob])
    const { args, defaultBeforeSchedule } = scheduleArgs(payload, { shouldSchedule: false })
    await expect(
      beforeScheduleOf({ ...base, reconcileStaleAfterMinutes: false })(args),
    ).resolves.toEqual({ shouldSchedule: false, waitUntil: undefined })
    expect(find).not.toHaveBeenCalled()
    expect(defaultBeforeSchedule).toHaveBeenCalledOnce()
  })

  it('runs the app’s own beforeSchedule after releasing, instead of Payload’s rule', async () => {
    const { cancel, payload } = fakePayload([staleJob])
    const own = vi.fn().mockResolvedValue({ input: {}, shouldSchedule: false })
    const { args, defaultBeforeSchedule } = scheduleArgs(payload)
    await expect(
      beforeScheduleOf({ ...base, reconcileScheduleHooks: { beforeSchedule: own } })(args),
    ).resolves.toEqual({ input: {}, shouldSchedule: false, waitUntil: undefined })
    expect(cancel.mock.invocationCallOrder[0]).toBeLessThan(own.mock.invocationCallOrder[0] ?? 0)
    expect(defaultBeforeSchedule).not.toHaveBeenCalled()
  })

  it('still makes the scheduling decision when releasing fails', async () => {
    const { find, logger, payload } = fakePayload([])
    find.mockReset().mockRejectedValue(new Error('database down'))
    const { args } = scheduleArgs(payload)
    await expect(beforeScheduleOf(base)(args)).resolves.toEqual({
      shouldSchedule: true,
      waitUntil: undefined,
    })
    expect(logger.error).toHaveBeenCalledWith(
      expect.objectContaining({ msg: 'payload-oidc: could not release stale reconcile runs' }),
    )
  })

  it('isn’t scheduled without a source or with sign-in off', () => {
    expect(
      createReconcileTask(resolveOptions({ ...base, reconcile: undefined })).schedule,
    ).toBeUndefined()
    expect(
      createReconcileTask(resolveOptions({ ...base, issuer: undefined })).schedule,
    ).toBeUndefined()
  })
})
