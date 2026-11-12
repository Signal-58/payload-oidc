import crypto from 'node:crypto'
import http from 'node:http'
import type { AddressInfo } from 'node:net'

import { exportJWK, generateKeyPair, SignJWT } from 'jose'

/** The claims the fake provider puts in the next ID token. */
export type FakeUser = {
  email: string
  email_verified?: boolean
  family_name?: string
  given_name?: string
  groups?: string[]
  name?: string
  sub: string
}

type PendingCode = {
  challenge: string
  clientId: string
  nonce: string
  redirectUri: string
  user: FakeUser
}

/**
 * A minimal OpenID Connect provider on 127.0.0.1 for tests: discovery, JWKS, an authorization
 * endpoint that signs in `nextUser` at once, and a token endpoint that checks the client secret,
 * the code, the redirect URI and the PKCE verifier, then issues an RS256 ID token.
 */
export const startFakeProvider = async (client: { id: string; secret: string }) => {
  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const jwk = { ...(await exportJWK(publicKey)), alg: 'RS256', kid: 'test-key', use: 'sig' }
  const codes = new Map<string, PendingCode>()
  const state = {
    /** Signs the ID token with a key the JWKS doesn't publish. */
    forgeSignature: false,
    issuer: '',
    nextUser: undefined as FakeUser | undefined,
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', state.issuer)
    const json = (status: number, body: unknown) => {
      res.writeHead(status, { 'content-type': 'application/json' }).end(JSON.stringify(body))
    }
    if (url.pathname === '/.well-known/openid-configuration') {
      return json(200, {
        authorization_endpoint: `${state.issuer}/authorize`,
        code_challenge_methods_supported: ['S256'],
        id_token_signing_alg_values_supported: ['RS256'],
        issuer: state.issuer,
        jwks_uri: `${state.issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        token_endpoint: `${state.issuer}/token`,
        token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      })
    }
    if (url.pathname === '/jwks') return json(200, { keys: [jwk] })
    if (url.pathname === '/authorize') {
      const params = url.searchParams
      if (!state.nextUser || params.get('client_id') !== client.id) return json(400, {})
      const code = crypto.randomBytes(16).toString('hex')
      codes.set(code, {
        challenge: params.get('code_challenge') ?? '',
        clientId: client.id,
        nonce: params.get('nonce') ?? '',
        redirectUri: params.get('redirect_uri') ?? '',
        user: state.nextUser,
      })
      const back = new URL(params.get('redirect_uri') ?? '')
      back.searchParams.set('code', code)
      back.searchParams.set('state', params.get('state') ?? '')
      back.searchParams.set('iss', state.issuer)
      res.writeHead(302, { location: back.href }).end()
      return
    }
    if (url.pathname === '/token' && req.method === 'POST') {
      const body = new URLSearchParams(
        await new Promise<string>((resolve) => {
          let data = ''
          req.on('data', (chunk) => (data += chunk))
          req.on('end', () => resolve(data))
        }),
      )
      const basic = Buffer.from(
        `${encodeURIComponent(client.id)}:${encodeURIComponent(client.secret)}`,
      ).toString('base64')
      const posted =
        body.get('client_id') === client.id && body.get('client_secret') === client.secret
      if (req.headers.authorization !== `Basic ${basic}` && !posted) {
        return json(401, { error: 'invalid_client' })
      }
      const pending = codes.get(body.get('code') ?? '')
      codes.delete(body.get('code') ?? '')
      const verifier = body.get('code_verifier') ?? ''
      const challenge = crypto.createHash('sha256').update(verifier).digest('base64url')
      if (
        !pending ||
        pending.redirectUri !== body.get('redirect_uri') ||
        pending.challenge !== challenge
      ) {
        return json(400, { error: 'invalid_grant' })
      }
      const signingKey = state.forgeSignature
        ? (await generateKeyPair('RS256')).privateKey
        : privateKey
      const idToken = await new SignJWT({ ...pending.user, nonce: pending.nonce })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
        .setIssuer(state.issuer)
        .setAudience(client.id)
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(signingKey)
      return json(200, {
        access_token: 'unused',
        expires_in: 300,
        id_token: idToken,
        token_type: 'Bearer',
      })
    }
    json(404, {})
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  state.issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`
  return {
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    state,
  }
}
