import crypto from 'node:crypto'

import { getFieldsToSign, jwtSign, type Payload } from 'payload'

import {
  canLinkByEmail,
  isBreakGlassEmail,
  roleForGroups,
  type ResolvedOidcOptions,
} from './options'
import type { VerifiedIdentity } from './provider'
import {
  authCollectionConfig,
  disableUser,
  isDuplicateKeyError,
  linkByEmail,
  markVerified,
  OIDC_FIELDS,
  OIDC_SYNC_CONTEXT,
  pushSession,
  roleValue,
  writeManagedFields,
} from './store'

/**
 * Why a sign-in was refused. The login page shows a short message per code; provider detail is
 * only logged.
 */
export type SignInRefusal =
  | 'account_conflict'
  | 'failed'
  | 'disabled'
  | 'email_not_verified'
  | 'no_role'
  | 'provider'
  | 'expired'
  | 'unavailable'

export type SignInOutcome =
  | { kind: 'refused'; reason: SignInRefusal }
  | { expiresAt: Date; kind: 'success'; token: string; userId: string | number }

type UserDocument = { email?: string; id: string | number; [key: string]: unknown }

const syncContext = { [OIDC_SYNC_CONTEXT]: true }

const findOne = async (
  payload: Payload,
  collection: string,
  where: Record<string, unknown>,
): Promise<UserDocument | undefined> => {
  const { docs } = await payload.find({
    collection: collection as never,
    depth: 0,
    limit: 1,
    overrideAccess: true,
    pagination: false,
    where: where as never,
  })
  return docs[0] as UserDocument | undefined
}

/** First and last name from the claims; `lastName` is required, so it falls back to a placeholder. */
export const namesFromIdentity = (options: ResolvedOidcOptions, identity: VerifiedIdentity) => {
  const firstName =
    identity.givenName ?? identity.name?.split(/\s+/)[0] ?? identity.email.split('@')[0]
  return { firstName, lastName: identity.familyName ?? options.lastNamePlaceholder }
}

/**
 * Finishes a sign-in after the ID token has been validated: decides the role, finds, links or
 * creates the user, writes the provider-owned fields, and issues a Payload session.
 */
export const completeSignIn = async (
  payload: Payload,
  options: ResolvedOidcOptions,
  identity: VerifiedIdentity,
  now: Date,
): Promise<SignInOutcome> => {
  const refuse = (reason: SignInRefusal): SignInOutcome => ({ kind: 'refused', reason })
  if (!identity.emailVerified) return refuse('email_not_verified')
  // The break-glass account signs in with its password only. A provider account with its email
  // must never link to it (which would rotate its password away) or sync it.
  if (isBreakGlassEmail(options, identity.email)) return refuse('account_conflict')

  const collection = options.collection
  const bySubject = { [OIDC_FIELDS.subject]: { equals: identity.subject } }
  const role = roleForGroups(options.roleTable, identity.groups)
  let user = await findOne(payload, collection, bySubject)

  if (!role) {
    if (user && !isBreakGlassEmail(options, user.email)) {
      await disableUser(payload, options, user.id, now)
    }
    return refuse('no_role')
  }

  if (
    !user &&
    canLinkByEmail(options, now) &&
    (await linkByEmail(payload, options, identity.email, identity.subject))
  ) {
    user = await findOne(payload, collection, bySubject)
  }

  const names = namesFromIdentity(options, identity)
  const managed = {
    email: identity.email,
    [options.firstNameField]: names.firstName,
    [options.lastNameField]: names.lastName,
    [options.roleField]: roleValue(options, role),
  }

  if (!user) {
    // Someone else's email (a user who isn't linkable, or is linked to another subject): never
    // take the account over and never create a duplicate.
    if (await findOne(payload, collection, { email: { equals: identity.email } })) {
      return refuse('account_conflict')
    }
    try {
      const created = (await payload.create({
        collection: collection as never,
        context: syncContext,
        data: {
          ...managed,
          [OIDC_FIELDS.subject]: identity.subject,
          // Required by local auth; nobody knows it, and password sign-in is closed anyway.
          password: crypto.randomBytes(48).toString('base64url'),
        } as never,
        depth: 0,
        disableVerificationEmail: true,
        overrideAccess: true,
      })) as unknown as UserDocument
      await markVerified(payload, options, created.id)
      user = created
    } catch (error) {
      if (!isDuplicateKeyError(error, [OIDC_FIELDS.subject, 'email'])) throw error
      // A second first sign-in for the same subject won the race (it may not have committed
      // yet), or the email was just taken.
      for (let attempt = 0; !user && attempt < 5; attempt += 1) {
        if (attempt > 0) await new Promise((resolve) => setTimeout(resolve, 100))
        user = await findOne(payload, collection, bySubject)
      }
      if (!user) return refuse('account_conflict')
    }
  } else {
    try {
      if (!(await writeManagedFields(payload, options, user.id, identity.subject, managed, now))) {
        return refuse('disabled')
      }
    } catch (error) {
      // The provider's email now belongs to another CMS user.
      if (isDuplicateKeyError(error)) return refuse('account_conflict')
      throw error
    }
    user = (await findOne(payload, collection, bySubject)) ?? user
  }

  const sid = await pushSession(payload, options, user.id, identity.subject, now)
  if (!sid) return refuse('disabled')

  const collectionConfig = authCollectionConfig(payload, collection)
  const { exp, token } = await jwtSign({
    fieldsToSign: getFieldsToSign({
      collectionConfig,
      email: identity.email,
      sid,
      user: { ...user, collection } as never,
    }),
    secret: payload.secret,
    tokenExpiration: options.sessionSeconds,
  })
  return { expiresAt: new Date(exp * 1000), kind: 'success', token, userId: user.id }
}
