import type { TaskConfig } from 'payload'

import type { ResolvedOidcOptions } from './options'
import { reconcileUsers } from './reconcile'

export const RECONCILE_TASK_SLUG = 'payload-oidc-reconcile'

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
              // Payload can make a new job wait for the next cron slot. That slot's tick only runs
              // the job, as one is still waiting, so reconcile would run on every other tick.
              // With no wait, the tick that queues the job also runs it.
              beforeSchedule: async (args) => ({
                ...(await (
                  options.reconcileScheduleHooks?.beforeSchedule ?? args.defaultBeforeSchedule
                )(args)),
                waitUntil: undefined,
              }),
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
    const { disabled, roleChanges, users } = await reconcileUsers(req.payload, options, clock())
    return { output: { disabled, roleChanges, users } }
  },
})
