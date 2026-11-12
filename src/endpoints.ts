import { generatePayloadCookie, parseCookies } from 'payload/shared'
import type { Endpoint, PayloadRequest } from 'payload'

import type { ResolvedOidcOptions } from './options'
import { reconcileHealth } from './reconcile'
import { removeUser } from './remove'
import { authCollectionConfig } from './store'
import { randomSignInSecrets, type ProviderClient } from './provider'
import { completeSignIn, type SignInRefusal } from './sign-in'
import {
  openTransaction,
  safeReturnPath,
  sealTransaction,
  TRANSACTION_MAX_AGE_SECONDS,
} from './transaction'

/** Query parameter on the login page that carries a refusal code. */
export const SIGN_IN_ERROR_PARAM = 'oidc_error'

const noStore = { 'Cache-Control': 'private, no-store' }

const notConfigured = () =>
  Response.json(
    { error: { code: 'not_found', message: 'Single sign-on is not configured.' } },
    { headers: noStore, status: 404 },
  )

const firstHeader = (req: PayloadRequest, name: string): string | undefined =>
  req.headers.get(name)?.split(',')[0]?.trim() || undefined

/**
 * The public origin this sign-in runs on: the request's own origin when it is one of the allowed
 * ones, so the transaction cookie and the callback stay on one host, otherwise the configured
 * `serverURL`. Headers can only choose among allowed origins, never add one.
 */
const serverUrl = (req: PayloadRequest, options: ResolvedOidcOptions): string => {
  const configured = options.serverURL ?? req.payload.config.serverURL
  if (!configured) {
    throw new Error('payload-oidc needs its serverURL option or serverURL in the Payload config.')
  }
  const fallback = new URL(configured).origin
  if (options.additionalServerURLs.length === 0) return fallback
  const url = new URL(req.url ?? fallback, fallback)
  const host = firstHeader(req, 'x-forwarded-host') ?? firstHeader(req, 'host') ?? url.host
  const protocol = firstHeader(req, 'x-forwarded-proto') ?? url.protocol.replace(/:$/, '')
  const candidate = `${protocol}://${host}`.toLowerCase()
  return (
    [fallback, ...options.additionalServerURLs].find((origin) => origin === candidate) ?? fallback
  )
}

const callbackPath = (req: PayloadRequest, options: ResolvedOidcOptions) =>
  `${req.payload.config.routes.api}/${options.collection}/oidc/callback`

/** The redirect URI registered with the provider. */
export const redirectUri = (req: PayloadRequest, options: ResolvedOidcOptions) =>
  `${serverUrl(req, options)}${callbackPath(req, options)}`

const transactionCookieName = (req: PayloadRequest) => `${req.payload.config.cookiePrefix}-oidc`

const transactionCookie = (
  req: PayloadRequest,
  options: ResolvedOidcOptions,
  value: string,
  maxAge: number,
) =>
  [
    `${transactionCookieName(req)}=${value}`,
    `Path=${callbackPath(req, options)}`,
    `Max-Age=${maxAge}`,
    'HttpOnly',
    // Lax, not Strict: the provider's redirect back is a cross-site navigation, and Strict would
    // drop the cookie on exactly that request.
    'SameSite=Lax',
    ...(serverUrl(req, options).startsWith('https:') ? ['Secure'] : []),
  ].join('; ')

const loginPath = (req: PayloadRequest) => {
  const { admin, routes } = req.payload.config
  return `${routes.admin.replace(/\/+$/, '')}${admin.routes.login}`
}

const redirect = (location: string, cookies: string[] = []) => {
  const headers = new Headers({ ...noStore, Location: location })
  for (const cookie of cookies) headers.append('Set-Cookie', cookie)
  return new Response(null, { headers, status: 302 })
}

const toLogin = (req: PayloadRequest, reason: SignInRefusal, cookies: string[] = []) =>
  redirect(`${loginPath(req)}?${SIGN_IN_ERROR_PARAM}=${reason}`, cookies)

export const createEndpoints = (
  options: ResolvedOidcOptions,
  client: ProviderClient,
  clock: () => Date = () => new Date(),
): Endpoint[] => [
  {
    handler: async (req) => {
      if (!options.enabled) return notConfigured()
      const requested = new URL(req.url ?? '', 'http://payload-oidc.invalid').searchParams.get(
        'redirect',
      )
      const returnTo = safeReturnPath(requested, req.payload.config.routes.admin)
      const secrets = await randomSignInSecrets()
      let callback: string
      try {
        callback = redirectUri(req, options)
      } catch (error) {
        req.payload.logger.error({ err: error, msg: 'payload-oidc: no public origin configured' })
        return toLogin(req, 'failed')
      }
      let location: URL
      try {
        location = await client.authorizationUrl({
          codeChallenge: secrets.codeChallenge,
          nonce: secrets.nonce,
          redirectUri: callback,
          state: secrets.state,
        })
      } catch (error) {
        req.payload.logger.error({ err: error, msg: 'payload-oidc: provider discovery failed' })
        return toLogin(req, 'unavailable')
      }
      const sealed = sealTransaction(req.payload.secret, {
        createdAt: clock().getTime(),
        nonce: secrets.nonce,
        returnTo,
        state: secrets.state,
        verifier: secrets.verifier,
      })
      return redirect(location.href, [
        transactionCookie(req, options, sealed, TRANSACTION_MAX_AGE_SECONDS),
      ])
    },
    method: 'get',
    path: '/oidc/authorize',
  },
  {
    handler: async (req) => {
      if (!options.enabled) return notConfigured()
      const clear = transactionCookie(req, options, '', 0)
      const now = clock()
      const transaction = openTransaction(
        req.payload.secret,
        parseCookies(req.headers).get(transactionCookieName(req)),
        now,
      )
      if (!transaction) return toLogin(req, 'expired', [clear])

      // The registered redirect URI with the provider's parameters: behind a proxy, req.url
      // carries the internal origin, which the token endpoint would reject.
      const callbackUrl = new URL(redirectUri(req, options))
      callbackUrl.search = new URL(req.url ?? '', 'http://payload-oidc.invalid').search

      let identity
      try {
        identity = await client.exchange({
          callbackUrl,
          nonce: transaction.nonce,
          state: transaction.state,
          verifier: transaction.verifier,
        })
      } catch (error) {
        req.payload.logger.warn({ err: error, msg: 'payload-oidc: sign-in failed at the provider' })
        return toLogin(req, 'provider', [clear])
      }

      let outcome
      try {
        outcome = await completeSignIn(req.payload, options, identity, now)
      } catch (error) {
        req.payload.logger.error({ err: error, msg: 'payload-oidc: sign-in failed in the CMS' })
        return toLogin(req, 'failed', [clear])
      }
      if (outcome.kind === 'refused') {
        req.payload.logger.info({ msg: 'payload-oidc: sign-in refused', reason: outcome.reason })
        return toLogin(req, outcome.reason, [clear])
      }
      const authConfig = authCollectionConfig(req.payload, options.collection).auth
      const sessionCookie = generatePayloadCookie({
        collectionAuthConfig: authConfig,
        cookiePrefix: req.payload.config.cookiePrefix,
        token: outcome.token,
      }) as string
      return redirect(transaction.returnTo, [clear, sessionCookie])
    },
    method: 'get',
    path: '/oidc/callback',
  },
  {
    // Removes a disabled user: deleted if nothing refers to them, otherwise anonymised. POST
    // only, and the app decides who may (`removeAccess`, default nobody).
    handler: async (req) => {
      if (!options.enabled) return notConfigured()
      if (!req.user || !(await options.removeAccess(req))) {
        return Response.json(
          { error: { code: 'forbidden', message: 'You may not remove users.' } },
          { headers: noStore, status: req.user ? 403 : 401 },
        )
      }
      const id = req.routeParams?.id
      if (typeof id !== 'string' && typeof id !== 'number') return notConfigured()
      const outcome = await removeUser(req.payload, options, id)
      if (outcome.kind === 'refused') {
        const messages = {
          break_glass: 'The break-glass account is never removed.',
          not_disabled:
            'Only a disabled user can be removed: remove them at the identity provider first.',
          not_found: 'No such user.',
        } as const
        return Response.json(
          { error: { code: outcome.reason, message: messages[outcome.reason] } },
          { headers: noStore, status: outcome.reason === 'not_found' ? 404 : 409 },
        )
      }
      req.payload.logger.info({
        by: req.user.id,
        id,
        msg: `payload-oidc: user ${outcome.kind}`,
      })
      return Response.json({ result: outcome.kind }, { headers: noStore })
    },
    method: 'post',
    path: '/oidc/remove/:id',
  },
  {
    // For an uptime check (Gatus): 200 while the last successful reconcile is recent, 503 once it
    // isn't, so a failing reconcile (an expired token, a renamed group) alerts instead of silently
    // stopping removals. It says nothing about users.
    handler: async (req) => {
      if (!options.enabled || !options.reconcile) return notConfigured()
      const health = await reconcileHealth(req.payload, options, clock())
      return Response.json(health, { headers: noStore, status: health.healthy ? 200 : 503 })
    },
    method: 'get',
    path: '/oidc/reconcile/health',
  },
]
