import type { Payload } from 'payload'

import { SIGN_IN_ERROR_PARAM } from '../endpoints'
import { PUBLIC_STATE_KEY, type OidcPublicState } from '../plugin'
import type { SignInRefusal } from '../sign-in'

const MESSAGES: Record<SignInRefusal, string> = {
  account_conflict:
    'An account with this email already exists and can’t be linked. Ask an administrator.',
  disabled: 'This account is disabled. Ask an administrator.',
  email_not_verified: 'Your email address isn’t verified with the identity provider.',
  expired: 'The sign-in took too long or was started in another window. Try again.',
  failed: 'The CMS couldn’t complete the sign-in. Try again, or ask an administrator.',
  no_role: 'Your account has no access to this CMS. Ask an administrator.',
  provider: 'The identity provider didn’t complete the sign-in. Try again.',
  unavailable: 'The identity provider can’t be reached right now. Try again shortly.',
}

const firstValue = (value: unknown): string | undefined =>
  typeof value === 'string' ? value : Array.isArray(value) ? firstValue(value[0]) : undefined

/**
 * The single sign-on button above the login form. While password sign-in is off it also hides
 * the password form; the server refuses password operations regardless (`beforeOperation`).
 */
export const OidcLoginButton = ({
  payload,
  searchParams,
}: {
  payload: Payload
  searchParams?: Record<string, string | string[] | undefined>
}) => {
  const state = payload.config.custom?.[PUBLIC_STATE_KEY] as OidcPublicState | undefined
  if (!state?.enabled) return null

  const error = firstValue(searchParams?.[SIGN_IN_ERROR_PARAM]) as SignInRefusal | undefined
  const message = error && Object.hasOwn(MESSAGES, error) ? MESSAGES[error] : undefined
  const redirect = firstValue(searchParams?.redirect)
  const href = redirect
    ? `${state.authorizePath}?redirect=${encodeURIComponent(redirect)}`
    : state.authorizePath

  return (
    <div className="payload-oidc" style={{ marginBottom: 'var(--base)' }}>
      {message ? (
        <p className="payload-oidc__error" role="alert" style={{ color: 'var(--theme-error-500)' }}>
          {message}
        </p>
      ) : null}
      <a
        className="btn btn--style-primary btn--size-large"
        href={href}
        style={{ display: 'block', textAlign: 'center', width: '100%' }}
      >
        {state.buttonLabel}
      </a>
      {state.passwordLogin ? null : <style>{'.login__form { display: none; }'}</style>}
    </div>
  )
}
