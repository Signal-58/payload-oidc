'use client'

import { Button, toast, useConfig, useDocumentInfo, useFormFields } from '@payloadcms/ui'
import { useState } from 'react'

/**
 * Payload shows "Change Password" to anyone who may update the user, and has no option to hide
 * it; the server refuses the change regardless (`beforeOperation`).
 */
const HIDE_PASSWORD_CHANGE = '#change-password { display: none; }'

/**
 * "Remove user" in the sidebar of a disabled user. The endpoint decides who may (the app's
 * `removeAccess`) and whether the user is deleted or anonymised. With `hidePasswordChange`
 * (single sign-on on, password sign-in off) it also hides "Change Password" on every user.
 */
export const RemoveUserButton = ({
  hidePasswordChange = false,
}: {
  hidePasswordChange?: boolean
}) => {
  const { collectionSlug, id } = useDocumentInfo()
  const disabledAt = useFormFields(([fields]) => fields.oidcDisabledAt?.value)
  const {
    config: { routes },
  } = useConfig()
  const [busy, setBusy] = useState(false)
  const hide = hidePasswordChange ? <style>{HIDE_PASSWORD_CHANGE}</style> : null
  if (!id || !collectionSlug || !disabledAt) return hide

  const remove = async () => {
    const confirmed = window.confirm(
      'Remove this disabled user? If nothing refers to them they are deleted; otherwise their name and email are replaced so bylines still resolve. This can’t be undone.',
    )
    if (!confirmed) return
    setBusy(true)
    try {
      const response = await fetch(
        // Relative, like Payload's own admin calls: the session cookie belongs to this host.
        `${routes.api}/${collectionSlug}/oidc/remove/${encodeURIComponent(String(id))}`,
        { credentials: 'include', method: 'POST' },
      )
      const body = (await response.json().catch(() => ({}))) as {
        error?: { message?: string }
        result?: 'anonymised' | 'deleted'
      }
      if (!response.ok) {
        toast.error(body.error?.message ?? 'The user could not be removed.')
        return
      }
      toast.success(body.result === 'deleted' ? 'User deleted.' : 'User anonymised.')
      window.location.assign(`${routes.admin}/collections/${collectionSlug}`)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="field-type payload-oidc-remove" style={{ marginBottom: 'var(--base)' }}>
      {hide}
      <Button buttonStyle="secondary" disabled={busy} onClick={remove} size="medium">
        Remove user
      </Button>
    </div>
  )
}
