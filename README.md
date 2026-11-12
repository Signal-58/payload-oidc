# @signal58/payload-oidc

Sign in to the Payload admin with an OpenID Connect provider, and make the provider the source of
truth for the auth collection's users and roles.

- Users are created at their first sign-in. Email, first name, last name and role are taken from
  the ID token at every sign-in and can't be edited in Payload.
- Roles come from the provider's `groups` claim through one role table, highest role first.
- A user whose groups grant no role is refused and disabled: role and sessions cleared,
  `oidcDisabledAt` set, record kept.
- Password sign-in is closed for the collection: `login`, `forgotPassword`, `resetPassword`,
  `unlock`, and setting a password through `update`, are refused through REST, the admin and the
  Local API alike. A break-glass account can be let back in with a flag.
- A reconcile job (optional) reads the provider's role-table groups every 15 minutes and disables
  users who left them, so removal doesn't wait for a sign-in. It changes nothing unless every
  group was read, stops if it would disable too many users at once, and records a heartbeat that
  an uptime check can watch.
- A superadmin (the app decides who) can remove a disabled user: deleted if nothing refers to
  them, anonymised otherwise.
- Sessions are ordinary Payload sessions: an idle timeout (`sessionHours`) that activity extends,
  up to an absolute cap from sign-in (`sessionMaxHours`). A refresh near the cap gets a token that
  ends at the cap, not `sessionHours` later.

Payload `^3.91` with the MongoDB adapter, on Node 24. MIT licence.

## Install

```bash
pnpm add @signal58/payload-oidc
```

`payload` and `@payloadcms/ui` (`^3.91`, at the same version as each other) and `react` 19 are peer
dependencies. The package is ESM only.

## Setup

```ts
import { oidcPlugin } from '@signal58/payload-oidc'

export default buildConfig({
  serverURL: process.env.SERVER_URL, // required: the redirect URI is built from it
  plugins: [
    oidcPlugin({
      collection: 'users',
      issuer: process.env.OIDC_ISSUER, // https://idp.example/application/o/my-cms/
      clientId: process.env.OIDC_CLIENT_ID,
      clientSecret: process.env.OIDC_CLIENT_SECRET,
      roles: {
        field: 'roles',
        table: {
          admin: ['cms-admins'],
          editor: ['cms-editors'],
        },
      },
      buttonLabel: 'Sign in with Example SSO',
      breakGlassEmail: process.env.BREAK_GLASS_EMAIL,
      passwordLogin: process.env.PASSWORD_LOGIN === '1',
    }),
  ],
})
```

Register `${serverURL}${routes.api}/<collection>/oidc/callback` as the client's redirect URI (with
Payload's default `routes.api`, `https://cms.example/api/users/oidc/callback`), and the same path
on each of `additionalServerURLs`, with the Authorization Code grant, a confidential client, and an
RS256 signing key. Request scopes `openid email profile` (the default); the provider must send
`email_verified: true` and a `groups` claim.

With the issuer, client ID or client secret unset, the plugin is off: it still adds its fields and
endpoints (which answer 404), so the schema doesn't change, but sign-in works exactly as before.
That is the rollback. Discovery happens at the first sign-in, never at startup or during a build.

Run `payload generate:importmap` after adding the plugin: the sign-in button is a server
component, `@signal58/payload-oidc/rsc#OidcLoginButton`, added to `admin.components.beforeLogin`.

## What it adds

Endpoint paths are relative to the collection's REST route, `${routes.api}/<collection>`.

| Addition                      | Purpose                                                                                                   |
| ----------------------------- | --------------------------------------------------------------------------------------------------------- |
| `oidcSubject` field           | The provider's `sub`, unique. Unset (never `null`) when unlinked, because the index is sparse.            |
| `oidcDisabledAt` field        | Set when the user is disabled.                                                                            |
| `oidcLinkable` field          | Marks pre-existing users that may be linked by email once, before `linkByEmailUntil`.                     |
| `GET /oidc/authorize`         | Starts sign-in. `?redirect=` is kept only if it is a path under the admin route.                          |
| `GET /oidc/callback`          | Finishes sign-in and sets the Payload session cookie.                                                     |
| `beforeOperation` hook        | Closes password operations and creation outside sync; refuses `refresh` after the cap.                    |
| `refresh` hook                | Signs a refreshed token that ends at the absolute cap.                                                    |
| `beforeChange` hook           | Drops an `oidcSubject` of `null` or `''`, which would collide in the sparse index.                        |
| `beforeLogin` component       | The sign-in button and error message; hides the password form while it's closed.                          |
| `POST /oidc/remove/:id`       | Removes a disabled user (`removeAccess`, default nobody); a "Remove user" button in the sidebar calls it. |
| `unlock` access denied        | Payload then hides "Force Unlock"; the operation is refused anyway.                                       |
| Sidebar `oidcRemove` ui field | "Remove user" on a disabled user; hides "Change Password" while password sign-in is closed.               |
| `loggingLevels.OidcRefusal`   | `info`: refused password operations and ended sessions are expected, not errors.                          |
| `GET /oidc/reconcile/health`  | 200 while the last successful reconcile is recent, 503 once it isn't; for an uptime check.                |
| `payload-oidc-reconcile` task | Registered always; scheduled on `reconcile.queue` only when a source is configured.                       |

The managed fields (`email`, first and last name, the role field) get `update` access that only
the plugin's sync passes (`req.context.oidcSync`). **If your app replaces field or collection
access after plugins run, keep those rules**: no updates to the managed fields outside sync, no
`create` outside sync, no `delete` except through your own removal path, and no `unlock` (or the
admin shows a "Force Unlock" the server refuses).

## Sign-in

1. `authorize` creates `state`, `nonce` and a PKCE verifier and seals them, with the return path,
   in a short-lived, HTTP-only, `SameSite=Lax` cookie scoped to the callback path (AES-256-GCM,
   key derived from the Payload secret).
2. `callback` exchanges the code and validates the ID token with `openid-client`, including its
   signature against the provider's JWKS (non-repudiation checks are on: by default the library
   relies on TLS for tokens from the token endpoint).
3. The role comes from the role table. No role: refused, and disabled if the user exists.
4. The user is found by `oidcSubject`. If there is none and linking is still open, a user with
   `oidcLinkable` and the same email is linked in one atomic update that also clears its sessions
   and replaces its password with one nobody knows. Otherwise a new user is created, unless the
   email already belongs to someone (refused, never taken over).
5. Email, names and role are written and `oidcDisabledAt` cleared. For an existing user that is
   one database update of just those paths (never a whole-document write, which could restore
   sessions a disable just cleared), so **no collection hooks or validation run** for it; a new
   user is created through Payload with `req.context.oidcSync` set, so hooks do run.
   The break-glass email is never linked or synced: a provider account with it is refused.
6. A session is pushed with one conditional update (only while the user isn't disabled and is
   still linked to that subject), the JWT signed over `getFieldsToSign` with that `sid`, and the
   cookie set.

Failures redirect to the login page with `?oidc_error=<code>`: `email_not_verified`, `no_role`,
`account_conflict`, `disabled`, `expired`, `provider`, `unavailable`, `failed`. Provider detail is
only logged.

**The plugin trusts `email_verified`.** Linking by email (before the cut-off) gives a provider
account the existing CMS record with that email. That is only safe if users can't change their
own email at the provider, or the provider marks a changed email unverified.

## Reconcile

```ts
import { authentikSource, oidcPlugin } from '@signal58/payload-oidc'

oidcPlugin({
  // …
  reconcile: authentikSource({
    url: process.env.OIDC_RECONCILE_URL,
    token: process.env.OIDC_RECONCILE_TOKEN,
  }),
})

// and, because Payload runs schedules only for listed queues:
jobs: {
  autoRun: [{ cron: '*/15 * * * *', queue: 'oidc-reconcile' }]
}
```

`authentikSource` reads each role-table group (`GET /api/v3/core/groups/?name=…&include_users=true`)
with a token that only needs object-level `view_group` on those groups; a member's `uid` is the
OIDC `sub` when the provider's subject mode is the hashed user ID. Any other directory can be a
source: implement `ReconcileSource.fetchGroupMembers`.

Each run:

- disables linked users whose subject is in no role-table group or only as an inactive member
  (again, if something restored their role or sessions);
- updates enabled users whose role changed; a disabled user stays disabled until they sign in;
- never creates users, and never touches the break-glass account or unlinked users;
- changes nothing if any group can't be read, and stops without changes if it would disable more
  than `reconcileMaxDisableShare` of the linked users (default 25%; one is always allowed);
- records a heartbeat in Payload's KV store; `GET /oidc/reconcile/health` answers 503 once it is
  older than `reconcileHeartbeatMaxMinutes` (default 45).

## Removing users

`POST ${routes.api}/<collection>/oidc/remove/:id`, or the sidebar's "Remove user" on a disabled
user. Only disabled users: an active one would be created again at their next sign-in, and the
break-glass account never. The plugin scans the config for relationship and upload fields (in arrays, groups,
blocks and tabs, polymorphic included, and in versions) that can point at the collection. If none
refers to the user they are deleted; otherwise their names become "Removed user", their email
`removed-<id>@removed.invalid`, and every other profile field (photo, links, anything the app
added; `keepOnRemove` keeps named ones), their subject, password, sessions and reset or lockout
state go, so bylines still resolve but nothing else identifies them.
Payload's own bookkeeping (preferences, locks) isn't counted; rich-text links aren't seen.

## Break-glass

With `passwordLogin: true`, the `breakGlassEmail` account may use its password (sign-in, forgotten
and reset password, and changing its own password), and, until `linkByEmailUntil`, so may
pre-existing users that haven't linked yet. Nobody may set another user's password. Anyone else
gets the status and body an unknown address gets (a 401, or a forgotten-password success that
sends nothing). Timing and lockout still differ (only allowed users' passwords are checked and
their failures counted), so keep the flag's windows short. Sync never disables the break-glass
account. On an empty database, the break-glass account can register itself through Payload's
first-register screen while the flag is on; it can't set the plugin's fields there.

## Options

| Option                               | Default                         | Notes                                                             |
| ------------------------------------ | ------------------------------- | ----------------------------------------------------------------- |
| `collection`                         | `'users'`                       | An auth collection.                                               |
| `issuer`, `clientId`, `clientSecret` | —                               | All three, or the plugin is off.                                  |
| `roles.field`                        | —                               | The role field.                                                   |
| `roles.table`                        | —                               | Role → groups, highest role first.                                |
| `roles.hasMany`                      | `true`                          | `false` stores a single value.                                    |
| `fields`                             | `firstName`, `lastName`         | Names of the name fields.                                         |
| `lastNamePlaceholder`                | `'-'`                           | Used when the provider sends no `family_name`.                    |
| `sessionHours`                       | `8`                             | Becomes the collection's `tokenExpiration`.                       |
| `sessionMaxHours`                    | `12`                            | Refresh is refused after this, from sign-in.                      |
| `passwordLogin`                      | `false`                         | Needs `breakGlassEmail`.                                          |
| `breakGlassEmail`                    | —                               |                                                                   |
| `linkByEmailUntil`                   | —                               | ISO date; without it nobody is linked by email.                   |
| `scopes`                             | `['openid','email','profile']`  |                                                                   |
| `additionalServerURLs`               | —                               | Other public origins, used when a request arrives on one of them. |
| `reconcile`                          | —                               | A `ReconcileSource`, such as `authentikSource(...)`.              |
| `reconcileMaxDisableShare`           | `0.25`                          |                                                                   |
| `reconcileHeartbeatMaxMinutes`       | `45`                            |                                                                   |
| `removeAccess`                       | nobody                          | `(req) => boolean`.                                               |
| `serverURL`                          | Payload's `serverURL`           | The public origin the callback is registered under.               |
| `buttonLabel`                        | `'Sign in with single sign-on'` |                                                                   |
| `allowInsecureIssuer`                | `false`                         | Allows an `http:` issuer, never when `NODE_ENV=production`.       |

## Adopting in an app

The plugin owns sign-in, the managed fields and the password refusals. These are the app's:

1. **Provider.** One confidential client per environment, each with its own secret: Authorization
   Code with PKCE, RS256, and the callback above registered for every origin the environment
   serves. The ID token must carry `email_verified: true` and a `groups` claim limited to the role
   table's groups. With Authentik, use the "verified email" scope mapping (it sends `false`
   otherwise) and pin the subject mode to the hashed user ID, which is what reconcile compares.
2. **Dependency.** Pin an exact version. Check that `pnpm why @payloadcms/ui` shows one version: a
   second copy breaks the admin components' React context.
3. **`serverURL` in every environment**, Payload's or the plugin's option, because the redirect URI
   is built from it. A second public origin (a LAN host, say) goes in `additionalServerURLs`, with
   its own callback registered.
4. **Access your app sets after plugins run.** If a later step replaces collection or field access,
   keep the plugin's rules there: `create` only for sync writes (`req.context[OIDC_SYNC_CONTEXT]`),
   `delete` denied (removal goes through `removeAccess` and the plugin's endpoint), `unlock`
   denied, and the email, name and role fields updatable only by sync (`syncWriteOnly`). A patch
   to the role field must keep that rule rather than overwrite it.
5. **Endpoint allowlists.** If the app limits which REST endpoints a collection exposes, add the
   plugin's four to the auth collection only.
6. **Role guards.** A hook that limits role changes (for example, one that protects the last top
   admin) must let sync writes through in both directions: the provider is right, and the
   break-glass account remains. Sign-in updates existing users directly in MongoDB without hooks;
   creating a user goes through Payload, so hooks run then.
7. **Empty roles.** A disabled user has no role. If the role field is `required`, its validation
   must allow an empty list while `oidcDisabledAt` is set; the plugin doesn't do this yet.
8. **Existing users.** Write a migration that builds the collection's indexes (the sparse unique
   `oidcSubject` index, before writing in a transaction) and sets `oidcLinkable: true` on the
   users who may link by email, skipping any already linked. Set `linkByEmailUntil` to the end of
   the linking window. Users created later are never linkable.
9. **Jobs.** With `reconcile`, add its queue (`oidc-reconcile` for `authentikSource`) to
   `jobs.autoRun` every 15 minutes. A run cut off by a deploy stays locked and blocks the queue,
   so release stale runs before each schedule; the plugin doesn't do this yet.
10. **Generated files.** Run `payload generate:importmap` and `payload generate:types`, and commit
    both.
11. **Break-glass.** A dedicated account that is never linked, with its password stored safely.
    Turn `passwordLogin` on only for the linking window and emergencies.
12. **Tests and scripts.** Tests that expect a password sign-in to work, or a wrong password's
    401, now meet the refusal. Scripts that grant roles directly drift from the provider: retire
    them or limit them to the break-glass account. Add an integration test that signs in through
    `@signal58/payload-oidc/testing` (`startFakeProvider`).
13. **Monitoring.** Point an uptime check at `${routes.api}/<collection>/oidc/reconcile/health`.
14. **Rollout.** Deploy with `passwordLogin` on and `linkByEmailUntil` set; existing users link at
    their first single sign-on. After the window, unset `passwordLogin`, then check that login,
    forgotten and reset password are refused for everyone.

## Known limits

- MongoDB only: session pushes and disables are conditional, atomic updates.
- Payload's own `refresh` writes the whole user document. If a disable lands in the same moment,
  that write can restore the role and sessions; the next disable (sign-in or reconcile) repeats it.
- The auth collection must keep its REST endpoints (`endpoints: false` is refused).
- Tested with email login. `loginWithUsername` collections are handled (the user is looked up the
  way Payload will, per operation) but not yet covered by the end-to-end suites.
- A Payload write can't clear a linked `oidcSubject` (a `null` or `''` is dropped); code that
  unlinks a user must `$unset` it directly.
- Signing out of the CMS doesn't sign out of the provider.
- "Change Password" is hidden with CSS (Payload has no option for it), and only while password
  sign-in is closed: with `passwordLogin` on it shows on every account, though the server lets only
  the break-glass account change its own password.

## Development

```bash
pnpm install
pnpm check               # typecheck and lint
pnpm test                # unit tests
pnpm test:integration    # end to end: a real Payload on MongoDB and a fake OIDC provider
pnpm build               # dist/: ESM and declarations
node scripts/check-dist.mjs  # the built entry points load in plain Node
pnpm check:package       # publint and arethetypeswrong
```

The integration suite needs a MongoDB replica set (`PAYLOAD_OIDC_DATABASE_URI`, or a local one on
`127.0.0.1:27017` by default, named by `PAYLOAD_OIDC_REPLICA_SET` if set) and owns its database: it
refuses one that holds anything else.

## Releases and security

Versions follow semver, recorded in [CHANGELOG.md](CHANGELOG.md). A `v*` tag publishes to npm from
GitHub Actions, with provenance. Report vulnerabilities privately, as [SECURITY.md](SECURITY.md)
describes.
