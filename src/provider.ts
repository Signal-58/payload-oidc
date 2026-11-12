import * as oidc from 'openid-client'

import type { ResolvedOidcOptions } from './options'

/** The verified claims the plugin uses from a sign-in. */
export type VerifiedIdentity = {
  email: string
  emailVerified: boolean
  familyName?: string
  givenName?: string
  groups: unknown
  name?: string
  subject: string
}

export type ProviderClient = {
  /** Builds the provider's authorization URL, discovering the provider on first use. */
  authorizationUrl: (input: {
    codeChallenge: string
    nonce: string
    redirectUri: string
    state: string
  }) => Promise<URL>
  /**
   * Exchanges the callback's code and validates the ID token: signature against the provider's
   * JWKS, issuer, audience, expiry, `nonce`, plus `state` and the PKCE verifier.
   */
  exchange: (input: {
    callbackUrl: URL
    nonce: string
    state: string
    verifier: string
  }) => Promise<VerifiedIdentity>
}

const text = (value: unknown): string | undefined =>
  typeof value === 'string' && value.trim() ? value.trim() : undefined

/**
 * Creates the provider client. Discovery runs the first time sign-in needs it, never at startup
 * or during a build, and a failed discovery isn't cached, so the next sign-in tries again.
 */
export const createProviderClient = (
  options: ResolvedOidcOptions,
  discover: typeof oidc.discovery = oidc.discovery,
): ProviderClient => {
  let configuration: Promise<oidc.Configuration> | undefined

  // openid-client skips the ID token's signature when the token comes straight from the token
  // endpoint (OIDC Core 3.1.3.7 lets a client rely on TLS); non-repudiation checks verify it
  // against the provider's JWKS as well.
  const execute = [
    oidc.enableNonRepudiationChecks,
    ...(options.allowInsecureIssuer ? [oidc.allowInsecureRequests] : []),
  ]
  const load = (): Promise<oidc.Configuration> => {
    configuration ??= discover(
      new URL(options.issuer),
      options.clientId,
      options.clientSecret,
      undefined,
      { execute },
    ).catch((error: unknown) => {
      configuration = undefined
      throw error
    })
    return configuration
  }

  return {
    authorizationUrl: async ({ codeChallenge, nonce, redirectUri, state }) =>
      oidc.buildAuthorizationUrl(await load(), {
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        nonce,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: options.scopes.join(' '),
        state,
      }),
    exchange: async ({ callbackUrl, nonce, state, verifier }) => {
      const tokens = await oidc.authorizationCodeGrant(await load(), callbackUrl, {
        expectedNonce: nonce,
        expectedState: state,
        idTokenExpected: true,
        pkceCodeVerifier: verifier,
      })
      const claims = tokens.claims()
      if (!claims) throw new Error('payload-oidc: the provider returned no ID token.')
      const email = text(claims.email)?.toLowerCase()
      if (!email) throw new Error('payload-oidc: the ID token has no email.')
      return {
        email,
        emailVerified: claims.email_verified === true,
        familyName: text(claims.family_name),
        givenName: text(claims.given_name),
        groups: claims.groups,
        name: text(claims.name),
        subject: claims.sub,
      }
    },
  }
}

/** Fresh `state`, `nonce` and PKCE verifier for one sign-in. */
export const randomSignInSecrets = async () => {
  const verifier = oidc.randomPKCECodeVerifier()
  return {
    codeChallenge: await oidc.calculatePKCECodeChallenge(verifier),
    nonce: oidc.randomNonce(),
    state: oidc.randomState(),
    verifier,
  }
}
