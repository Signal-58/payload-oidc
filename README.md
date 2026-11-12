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

Payload `^3.91` with the MongoDB adapter. MIT licence.

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

Register `${serverURL}/api/<collection>/oidc/callback` as the client's only redirect URI, with the
Authorization Code grant, a confidential client, and an RS256 signing key. Request scopes
`openid email profile` (the default); the provider must send `email_verified: true` and a
`groups` claim.

With the issuer, client ID or client secret unset, the plugin is off: it still adds its fields and
endpoints (which answer 404), so the schema doesn't change, but sign-in works exactly as before.
That is the rollback. Discovery happens at the first sign-in, never at startup or during a build.

Run `payload generate:importmap` after adding the plugin: the sign-in button is a server
component, `@signal58/payload-oidc/rsc#OidcLoginButton`, added to `admin.components.beforeLogin`.

## What it adds

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

`POST /api/<collection>/oidc/remove/:id`, or the sidebar's "Remove user" on a disabled user. Only
disabled users: an active one would be created again at their next sign-in, and the break-glass
account never. The plugin scans the config for relationship and upload fields (in arrays, groups,
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

## Tests

```bash
pnpm test                # unit tests
pnpm test:integration    # end to end: a real Payload on MongoDB and a fake OIDC provider
```

The integration suite needs a MongoDB replica set (`PAYLOAD_OIDC_DATABASE_URI`, or a local one on
`127.0.0.1:27017` by default, named by `PAYLOAD_OIDC_REPLICA_SET` if set) and owns its database: it
refuses one that holds anything else.
