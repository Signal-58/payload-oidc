import type { Payload } from 'payload'
import { describe, expect, it, vi } from 'vitest'

import { clearLinkingSnapshot, takeLinkingSnapshot } from './migration'

const fakePayload = ({
  fields = [{ name: 'email' }, { name: 'oidcSubject' }],
  nullSubjects = 0,
  slug = 'users',
} = {}) => {
  const users = {
    countDocuments: vi.fn().mockResolvedValue(nullSubjects),
    updateMany: vi.fn().mockResolvedValue({ modifiedCount: 3 }),
  }
  const collection = vi.fn(() => users)
  const createIndexes = vi.fn().mockResolvedValue(undefined)
  const info = vi.fn()
  const payload = {
    collections: { [slug]: { config: { fields } } },
    db: {
      collections: { [slug]: { collection: { name: `${slug}_live` }, createIndexes } },
      connection: { db: { collection } },
    },
    logger: { info },
  } as unknown as Payload
  return { collection, createIndexes, info, payload, users }
}

const session = { id: 'migration-session' }

describe('takeLinkingSnapshot', () => {
  it('builds the indexes, then marks every never-linked user linkable in the session', async () => {
    const { collection, createIndexes, info, payload, users } = fakePayload()

    await expect(takeLinkingSnapshot({ payload, session })).resolves.toBe(3)

    // The physical collection name, which may differ from the slug.
    expect(collection).toHaveBeenCalledWith('users_live')
    // Outside the transaction: it would otherwise hold the collection the index build needs.
    expect(users.countDocuments).toHaveBeenCalledWith({ oidcSubject: { $type: 'null' } }, {})
    // The index build must finish before the transactional write (catalog-change race).
    expect(createIndexes).toHaveBeenCalledOnce()
    expect(createIndexes.mock.invocationCallOrder[0]).toBeLessThan(
      users.updateMany.mock.invocationCallOrder[0] ?? 0,
    )
    expect(users.updateMany).toHaveBeenCalledExactlyOnceWith(
      { oidcLinkable: { $exists: false }, oidcSubject: { $exists: false } },
      { $set: { oidcLinkable: true } },
      { session },
    )
    expect(info).toHaveBeenCalledWith('payload-oidc: marked 3 users of "users" linkable.')
  })

  it('works on another auth collection', async () => {
    const { collection, payload } = fakePayload({ slug: 'staff' })
    await takeLinkingSnapshot({ payload }, { collection: 'staff' })
    expect(collection).toHaveBeenCalledWith('staff_live')
  })

  it('stops before any change if a user stores oidcSubject as null', async () => {
    const { createIndexes, payload, users } = fakePayload({ nullSubjects: 1 })
    await expect(takeLinkingSnapshot({ payload, session })).rejects.toThrow(
      /stores oidcSubject as null/,
    )
    expect(createIndexes).not.toHaveBeenCalled()
    expect(users.updateMany).not.toHaveBeenCalled()
  })

  it('says which collection’s index build failed', async () => {
    const { createIndexes, payload, users } = fakePayload()
    createIndexes.mockRejectedValue(new Error('E11000 duplicate key error'))
    await expect(takeLinkingSnapshot({ payload, session })).rejects.toThrow(
      'payload-oidc: building the indexes of "users" failed: Error: E11000 duplicate key error',
    )
    expect(users.updateMany).not.toHaveBeenCalled()
  })

  it('explains a write conflict with the index build, and passes other errors on', async () => {
    const conflict = fakePayload()
    conflict.users.updateMany.mockRejectedValue(
      Object.assign(new Error('catalog changes'), { code: 112 }),
    )
    await expect(takeLinkingSnapshot({ payload: conflict.payload, session })).rejects.toThrow(
      /conflicted with the index build on "users"\. Call takeLinkingSnapshot before any other operation/,
    )
    const other = fakePayload()
    const failure = new Error('network')
    other.users.updateMany.mockRejectedValue(failure)
    await expect(takeLinkingSnapshot({ payload: other.payload, session })).rejects.toBe(failure)
  })

  it('refuses a collection without the plugin’s fields, or without the MongoDB adapter', async () => {
    const withoutPlugin = fakePayload({ fields: [{ name: 'email' }] })
    await expect(takeLinkingSnapshot({ payload: withoutPlugin.payload })).rejects.toThrow(
      /no oidcSubject field/,
    )
    expect(withoutPlugin.users.updateMany).not.toHaveBeenCalled()
    await expect(
      takeLinkingSnapshot({ payload: fakePayload().payload }, { collection: 'nope' }),
    ).rejects.toThrow(/needs the MongoDB adapter \(no model for "nope"\)/)
  })
})

describe('clearLinkingSnapshot', () => {
  it('clears only the linkable marks, in the session', async () => {
    const { payload, users } = fakePayload()
    await expect(clearLinkingSnapshot({ payload, session })).resolves.toBe(3)
    expect(users.updateMany).toHaveBeenCalledExactlyOnceWith(
      { oidcLinkable: { $exists: true } },
      { $unset: { oidcLinkable: '' } },
      { session },
    )
  })
})
