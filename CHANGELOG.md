# Changelog

All notable changes to this package are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[semantic versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0]

App code the first adopter wrote for itself, moved into the plugin so the next apps don't copy it.
0.2.0 configurations keep working. One change is on by default: stale reconcile runs are released,
and a reconcile source now has a time limit (below). `reconcileStaleAfterMinutes: false` restores
0.2.0's behaviour.

### Added

- **No role on a disabled user.** The role field's validation lets an empty role (an empty list,
  or no single value) through while `oidcDisabledAt` is set, so a `required` role field no longer
  stops an admin saving a disabled user. Anything else goes to the field's own `validate`, or to
  Payload's default for its type. It applies whether or not sign-in is on.
- **`takeLinkingSnapshot` and `clearLinkingSnapshot`**, for an app's migration: build the
  collection's indexes, then mark every unlinked user `oidcLinkable` (and the reverse). Call it
  first in the migration's transaction. The null-subject check runs outside the transaction, which
  would otherwise hold the collection that the index build waits for; a write conflict with the
  build, and an index that fails to build, fail with errors that say so.
- **Stale reconcile runs are released** (on by default). Before each schedule, reconcile runs on
  the schedule's queue still processing after `reconcileStaleAfterMinutes` (default 10, at least
  1. are marked failed with Payload's cancel, so a run a deploy cut off no longer blocks the queue.
     So that a live run never looks stale, a run whose source hasn't answered within 80% of that
     threshold stops before changing anything. `reconcileStaleAfterMinutes: false` turns both off; a
     `beforeSchedule` in `reconcileScheduleHooks` runs after the release.
- README: an "Existing users" section, and the adoption checklist updated for the above.
- Tests: an end-to-end suite for an adopting app (Payload's `serverURL` unset with the plugin's
  option set, a required role field, the snapshot in a migration transaction, a cut-off reconcile
  run). The suites' linking window is now relative to the day they run, rather than ending on
  2026-12-01.

## [0.2.0]

The first public release. The plugin's code and behaviour are those of 0.1.0, which ran as a
private workspace package; only the packaging changed.

### Changed

- Published to npm, built to `dist/` as ESM JavaScript with type declarations. Relative imports
  are fully specified, so Node can load the package without a bundler (Payload's CLI and job
  runner do).
- `jose` is a dependency rather than a development dependency, because
  `@signal58/payload-oidc/testing` imports it.

### Added

- README: an "Adopting in an app" checklist, and the callback path stated with Payload's
  `routes.api` (`${serverURL}${routes.api}/<collection>/oidc/callback`), which the code already
  used.
- Tests: an end-to-end case with a non-default `routes.api`, and CI across Payload 3.91.0 and
  3.92.1.

## [0.1.0]

Private release, used as a workspace package only.

[Unreleased]: https://github.com/Signal-58/payload-oidc/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Signal-58/payload-oidc/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Signal-58/payload-oidc/releases/tag/v0.2.0
