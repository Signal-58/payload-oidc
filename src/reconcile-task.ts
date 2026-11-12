import type { Payload, TaskConfig, Where } from 'payload'

import type { ResolvedOidcOptions } from './options'
import { reconcileUsers } from './reconcile'

export const RECONCILE_TASK_SLUG = 'payload-oidc-reconcile'

/** Payload's jobs collection. */
const JOBS_COLLECTION = 'payload-jobs'

type JobSummary = { createdAt?: string; id: number | string; updatedAt?: string }

/**
 * Marks reconcile runs on `queue` that are still processing after `olderThanSeconds` as failed,
 * and returns the IDs it marked.
 *
 * Payload's scheduler queues a run only while no scheduled run of the task is waiting or
 * processing, and its runner only picks up jobs that aren't processing. A run left processing by a
 * process that stopped mid-run (a container a deploy replaced) would therefore block the queue for
 * good: Payload never expires it. Payload's own cancel writes its final-failure shape
 * (`hasError`, `processing: false`, `error.cancelled`), so the dead run stays visible as a failed
 * job and the scheduler stops counting it.
 */
export const releaseStaleRuns = async (
  payload: Payload,
  { now, olderThanSeconds, queue }: { now: Date; olderThanSeconds: number; queue: string },
): Promise<Array<number | string>> => {
  const where: Where = {
    and: [
      { processing: { equals: true } },
      { completedAt: { exists: false } },
      { hasError: { not_equals: true } },
      { queue: { equals: queue } },
      { taskSlug: { equals: RECONCILE_TASK_SLUG } },
      { updatedAt: { less_than: new Date(now.getTime() - olderThanSeconds * 1000).toISOString() } },
    ],
  }
  const select = { createdAt: true, updatedAt: true } as const
  const { docs: stale } = (await payload.find({
    collection: JOBS_COLLECTION,
    depth: 0,
    overrideAccess: true,
    pagination: false,
    select,
    where,
  })) as unknown as { docs: JobSummary[] }
  if (stale.length === 0) return []
  const ids = stale.map((job) => job.id)

  // Only those still processing: a run that finished since the find is left alone.
  await payload.jobs.cancel({
    overrideAccess: true,
    where: { and: [{ id: { in: ids } }, { processing: { equals: true } }] },
  })

  // Cancel doesn't say which jobs it changed, so read back the ones it marked.
  const { docs: released } = (await payload.find({
    collection: JOBS_COLLECTION,
    depth: 0,
    overrideAccess: true,
    pagination: false,
    select,
    where: { and: [{ id: { in: ids } }, { 'error.cancelled': { equals: true } }] },
  })) as unknown as { docs: JobSummary[] }
  for (const job of released) {
    payload.logger.warn({
      createdAt: job.createdAt,
      jobId: job.id,
      lastUpdatedAt: job.updatedAt,
      msg: `payload-oidc: marked reconcile run ${job.id} failed: still processing after ${olderThanSeconds} seconds`,
    })
  }
  return released.map((job) => job.id)
}

/** The share of the stale threshold a run's source may take before the run gives up. */
const SOURCE_TIME_SHARE = 0.8

/**
 * The options with the reconcile source's answer limited to `limitMs`. Payload doesn't touch a
 * job while its handler runs, so a run that outlasted the stale threshold would look cut off,
 * be released, and overlap the new run. Reconcile writes nothing until every group is read, so
 * stopping at the read changes nothing.
 */
const withSourceTimeLimit = (
  options: ResolvedOidcOptions,
  limitMs: number,
): ResolvedOidcOptions => {
  const source = options.reconcile!
  return {
    ...options,
    reconcile: {
      ...source,
      fetchGroupMembers: async (groups) => {
        let timer: ReturnType<typeof setTimeout> | undefined
        const late = new Promise<never>((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new Error(
                  `payload-oidc: the reconcile source took longer than ${limitMs / 1000} seconds; the run stopped before changing anything, so it can't outlast reconcileStaleAfterMinutes and be taken for a cut-off run.`,
                ),
              ),
            limitMs,
          )
        })
        try {
          return await Promise.race([source.fetchGroupMembers(groups), late])
        } finally {
          clearTimeout(timer)
        }
      },
    },
  }
}

/**
 * The reconcile job. Payload schedules it only on its own queue, and runs schedules only for
 * queues listed in `jobs.autoRun`, so the app must add that queue there. A failed run (a group
 * that can't be read, a safety stop) fails the job and records no heartbeat.
 */
export const createReconcileTask = (
  options: ResolvedOidcOptions,
  { clock = () => new Date(), concurrencyControl = false } = {},
): TaskConfig => ({
  slug: RECONCILE_TASK_SLUG,
  label: 'Reconcile CMS users with the identity provider',
  // One run at a time where the app enables Payload's concurrency control; otherwise Payload's
  // scheduler still skips a schedule while a run is queued or running.
  ...(concurrencyControl ? { concurrency: () => RECONCILE_TASK_SLUG } : {}),
  inputSchema: [],
  outputSchema: [
    { name: 'disabled', type: 'number', required: true },
    { name: 'roleChanges', type: 'number', required: true },
    { name: 'users', type: 'number', required: true },
  ],
  retries: 0,
  ...(options.enabled && options.reconcile
    ? {
        schedule: [
          {
            cron: options.reconcile.cron,
            hooks: {
              ...options.reconcileScheduleHooks,
              beforeSchedule: async (args) => {
                // On every tick, not only at startup: with start-first deploys the run a deploy
                // cuts off usually belongs to the old process, after this one started.
                const olderThanSeconds = options.reconcileStaleAfterSeconds
                if (olderThanSeconds !== undefined) {
                  try {
                    await releaseStaleRuns(args.req.payload, {
                      now: clock(),
                      olderThanSeconds,
                      queue: args.queueable.scheduleConfig.queue,
                    })
                  } catch (error) {
                    // Still make the scheduling decision; the next tick tries again.
                    args.req.payload.logger.error({
                      err: error,
                      msg: 'payload-oidc: could not release stale reconcile runs',
                    })
                  }
                }
                return {
                  ...(await (
                    options.reconcileScheduleHooks?.beforeSchedule ?? args.defaultBeforeSchedule
                  )(args)),
                  // Payload can make a new job wait for the next cron slot. That slot's tick only
                  // runs the job, as one is still waiting, so reconcile would run on every other
                  // tick. With no wait, the tick that queues the job also runs it.
                  waitUntil: undefined,
                }
              },
            },
            queue: options.reconcile.queue,
          },
        ],
      }
    : {}),
  handler: async ({ req }) => {
    if (!options.enabled || !options.reconcile) {
      return { output: { disabled: 0, roleChanges: 0, users: 0 } }
    }
    const staleAfterSeconds = options.reconcileStaleAfterSeconds
    const { disabled, roleChanges, users } = await reconcileUsers(
      req.payload,
      // While stale runs are released, a live run must end well before it would look stale.
      staleAfterSeconds === undefined
        ? options
        : withSourceTimeLimit(options, staleAfterSeconds * 1000 * SOURCE_TIME_SHARE),
      clock(),
    )
    return { output: { disabled, roleChanges, users } }
  },
})
