import { describe, expect, test } from 'bun:test'
import { signJwtHS256 } from './jwt'
import { MemoryKv } from './kv'
import { MemorySessionStore } from './memory-store'
import { JwtSessionStrategy } from './token-jwt'
import type { AuthUser } from './types'

const SECRET = 'test-secret-at-least-16-chars'

const user: AuthUser = {
  id: 'usr_abc',
  status: 'active',
  tokenVersion: 3,
  phone: null,
  email: null,
  hasPassword: false,
  createdAt: new Date(),
}

function makeStrategy() {
  return new JwtSessionStrategy({
    secret: SECRET,
    accessTtlSec: 60,
    refreshTtlSec: 120,
    sessions: new MemorySessionStore(),
    kv: new MemoryKv(),
    claimsFromUser: () => ({ role: 'admin' }),
  })
}

describe('JwtSessionStrategy', () => {
  test('m612 形 payload 兼容:同 secret 下现网旧 token 可验证,role 从 claims 带回', async () => {
    const iat = Math.floor(Date.now() / 1000)
    // 模拟 m612 现网 JwtService.signAccess 的 payload 形态
    const legacy = await signJwtHS256(
      { sub: 'usr_legacy', jti: 'jti_01ABC', iat, exp: iat + 1800, scope: 'user', ver: 5, role: 'admin' },
      SECRET,
    )
    const v = await makeStrategy().verifyAccess(legacy)
    expect(v.userId).toBe('usr_legacy')
    expect(v.tokenVersion).toBe(5)
    expect(v.jti).toBe('jti_01ABC')
    expect(v.claims?.role).toBe('admin')
  })

  test('签发的 access 含标准骨架与业务 claims', async () => {
    const s = makeStrategy()
    const pair = await s.issue(user, {})
    const v = await s.verifyAccess(pair.access)
    expect(v.userId).toBe('usr_abc')
    expect(v.tokenVersion).toBe(3)
    expect(v.claims?.role).toBe('admin')
    expect(pair.refresh).toBeTruthy()
    expect(pair.expiresInSec).toBe(60)
  })

  test('过期 → token_expired;错 secret → token_invalid;refresh 当 access 用 → token_invalid', async () => {
    const s = makeStrategy()
    const iat = Math.floor(Date.now() / 1000)
    const expired = await signJwtHS256(
      { sub: 'u', jti: 'j', iat: iat - 100, exp: iat - 10, scope: 'user' },
      SECRET,
    )
    expect(s.verifyAccess(expired)).rejects.toMatchObject({ kind: 'token_expired' })
    const wrongKey = await signJwtHS256({ sub: 'u', scope: 'user', exp: iat + 60 }, 'another-secret-16chars!')
    expect(s.verifyAccess(wrongKey)).rejects.toMatchObject({ kind: 'token_invalid' })
    const pair = await s.issue(user, {})
    if (!pair.refresh) throw new Error('no refresh')
    expect(s.verifyAccess(pair.refresh)).rejects.toMatchObject({ kind: 'token_invalid' })
  })

  test('revoke access 拉黑 jti,即刻失效', async () => {
    const s = makeStrategy()
    const pair = await s.issue(user, {})
    await s.revoke({ access: pair.access })
    expect(s.verifyAccess(pair.access)).rejects.toMatchObject({ kind: 'token_revoked' })
  })

  test('refresh:ver 不匹配(全端登出后)→ token_revoked', async () => {
    const s = makeStrategy()
    const pair = await s.issue(user, {})
    if (!pair.refresh) throw new Error('no refresh')
    expect(s.refresh(pair.refresh, {}, async () => ({ ...user, tokenVersion: 4 }))).rejects.toMatchObject({
      kind: 'token_revoked',
    })
  })

  test('secret 短于 16 字符构造即抛(fail fast)', () => {
    expect(() => new JwtSessionStrategy({ secret: 'short', sessions: new MemorySessionStore() })).toThrow()
  })
})
