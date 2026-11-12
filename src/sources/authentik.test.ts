import { describe, expect, it, vi } from 'vitest'

import { authentikSource } from './authentik'

const group = (name: string, members: Array<{ is_active?: boolean; uid?: string }>) => ({
  name,
  users_obj: members,
})

const fakeFetch = (responses: Record<string, { body?: unknown; status?: number }>) =>
  vi.fn(async (url: string | URL | Request) => {
    const name = new URL(String(url)).searchParams.get('name') ?? ''
    const response = responses[name] ?? { body: { results: [] } }
    return new Response(JSON.stringify(response.body ?? {}), { status: response.status ?? 200 })
  })

describe('authentikSource', () => {
  it('is off without a URL or token', () => {
    expect(authentikSource({ token: 't' })).toBeUndefined()
    expect(authentikSource({ url: 'https://auth.example' })).toBeUndefined()
  })

  it('reads each group with its members, by exact name, with the token', async () => {
    const fetch = fakeFetch({
      'cms-a': {
        body: {
          results: [
            group('cms-a', [
              { is_active: true, uid: 'u1' },
              { is_active: false, uid: 'u2' },
            ]),
          ],
        },
      },
      'cms-b': { body: { results: [group('cms-b-other', []), group('cms-b', [])] } },
    })
    const source = authentikSource({ fetch, token: 'secret', url: 'https://auth.example/' })!
    expect(source).toMatchObject({ cron: '*/15 * * * *', queue: 'oidc-reconcile' })
    const members = await source.fetchGroupMembers(['cms-a', 'cms-b'])
    expect(members.get('cms-a')).toEqual([
      { active: true, subject: 'u1' },
      { active: false, subject: 'u2' },
    ])
    expect(members.get('cms-b')).toEqual([])
    const [url, init] = fetch.mock.calls[0] as unknown as [string, RequestInit]
    expect(url).toBe(
      'https://auth.example/api/v3/core/groups/?include_users=true&name=cms-a&page_size=2',
    )
    expect((init.headers as Record<string, string>).Authorization).toBe('Bearer secret')
  })

  it('refuses an http URL outside local development, and times requests out', async () => {
    expect(() => authentikSource({ token: 't', url: 'http://auth.example' })).toThrow(/https/)
    expect(
      authentikSource({ allowInsecure: true, token: 't', url: 'http://127.0.0.1:9000' }),
    ).toBeDefined()
    vi.stubEnv('NODE_ENV', 'production')
    try {
      expect(() =>
        authentikSource({ allowInsecure: true, token: 't', url: 'http://127.0.0.1:9000' }),
      ).toThrow(/https/)
    } finally {
      vi.unstubAllEnvs()
    }
    const fetch = fakeFetch({ 'cms-a': { body: { results: [group('cms-a', [])] } } })
    await authentikSource({
      fetch,
      timeoutMs: 1234,
      token: 't',
      url: 'https://auth.example',
    })!.fetchGroupMembers(['cms-a'])
    expect((fetch.mock.calls[0] as unknown as [string, RequestInit])[1].signal).toBeInstanceOf(
      AbortSignal,
    )
  })

  it('fails, rather than reporting an empty group, when a group is missing or unreadable', async () => {
    const read = (responses: Parameters<typeof fakeFetch>[0]) =>
      authentikSource({
        fetch: fakeFetch(responses),
        token: 't',
        url: 'https://auth.example',
      })!.fetchGroupMembers(['cms-a'])
    await expect(read({})).rejects.toThrow(/not found or not readable/)
    await expect(read({ 'cms-a': { status: 403 } })).rejects.toThrow(/answered 403/)
    await expect(read({ 'cms-a': { body: { results: [{ name: 'cms-a' }] } } })).rejects.toThrow(
      /no members/,
    )
    await expect(
      read({ 'cms-a': { body: { results: [group('cms-a', [{ is_active: true }])] } } }),
    ).rejects.toThrow(/without a uid/)
  })
})
