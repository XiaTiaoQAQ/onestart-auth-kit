import { beforeEach, describe, expect, test } from 'bun:test'
import { PasswordProvider } from '../providers/password'
import { SmsProvider, StubSmsChannel } from '../providers/sms'
import { AuthKit } from './engine'
import { AuthError } from './errors'
import { MemoryKv } from './kv'
import { InMemoryAuthStore, MemoryCodeStore, MemorySessionStore } from './memory-store'
import { JwtSessionStrategy } from './token-jwt'
import { OpaqueTokenStrategy } from './token-opaque'
import type { AuthProvider, IdentityClaim, RequestContext, TokenStrategy } from './types'

/** 测试用 federated provider:credential 即 claim,直接透传,fail=true 时抛 credential_invalid */
function fakeFederated(platform: string, appId = 'app1'): AuthProvider {
  return {
    platform,
    appId,
    identityKind: 'federated',
    async verify(credential: unknown): Promise<IdentityClaim> {
      const c = credential as Partial<IdentityClaim> & { fail?: boolean }
      if (c.fail) throw new AuthError('credential_invalid')
      return {
        platform,
        appId,
        openId: c.openId ?? 'o1',
        unionId: c.unionId ?? null,
        ...(c.phone ? { phone: c.phone } : {}),
        ...(c.email ? { email: c.email } : {}),
      }
    },
  }
}

/** 测试用 guarded provider(账密形):按 account 计失败锁定 */
function fakeGuarded(): AuthProvider {
  return {
    platform: 'password',
    appId: '',
    identityKind: 'local',
    lockKeyOf: (c: unknown) => (c as { account?: string })?.account ?? null,
    async verify(credential: unknown): Promise<IdentityClaim> {
      const c = credential as { account: string; ok?: boolean }
      if (!c.ok) throw new AuthError('credential_invalid')
      return {
        platform: 'password',
        appId: '',
        openId: c.account,
        phone: `+86138000000${c.account.slice(-2)}`,
      }
    },
  }
}

type StrategyName = 'opaque' | 'jwt'

function makeStrategy(name: StrategyName, sessions: MemorySessionStore): TokenStrategy {
  if (name === 'opaque') return new OpaqueTokenStrategy({ sessions, ttlSec: 3600 })
  return new JwtSessionStrategy({
    secret: 'test-secret-at-least-16-chars',
    accessTtlSec: 3600,
    refreshTtlSec: 7200,
    sessions,
    kv: new MemoryKv(),
    claimsFromUser: () => ({ role: 'user' }),
  })
}

for (const strategyName of ['opaque', 'jwt'] as StrategyName[]) {
  describe(`AuthKit engine [${strategyName}]`, () => {
    let store: InMemoryAuthStore
    let sessions: MemorySessionStore
    let kit: AuthKit
    let createdUsers: string[]

    beforeEach(() => {
      store = new InMemoryAuthStore()
      sessions = new MemorySessionStore()
      createdUsers = []
      kit = new AuthKit({
        store,
        tokens: makeStrategy(strategyName, sessions),
        providers: [fakeFederated('wechat_mini'), fakeFederated('wechat_open', 'app2'), fakeGuarded()],
        kv: new MemoryKv(),
        policy: { loginLock: { maxFails: 3, lockSec: 60 } },
        hooks: {
          onUserCreated: async (u) => {
            createdUsers.push(u.id)
          },
        },
      })
    })

    test('federated 首登建号,二登复用', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1' })
      expect(r1.isNewUser).toBe(true)
      expect(createdUsers).toEqual([r1.user.id])
      const r2 = await kit.login('wechat_mini', { openId: 'wx1' })
      expect(r2.isNewUser).toBe(false)
      expect(r2.user.id).toBe(r1.user.id)
      expect(createdUsers).toHaveLength(1)
    })

    test('unionid 家族合并:wechat_open 同 unionId 不建新号,绑到既有用户', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1', unionId: 'u-1' })
      const r2 = await kit.login('wechat_open', { openId: 'open1', unionId: 'u-1' })
      expect(r2.user.id).toBe(r1.user.id)
      expect(r2.isNewUser).toBe(false)
      const identities = await store.listIdentities(r1.user.id)
      expect(identities.map((i) => i.platform).sort()).toEqual(['wechat_mini', 'wechat_open'])
    })

    test('unionid 机会性回填:首登无 unionId,次登带上后写回身份行', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1' })
      await kit.login('wechat_mini', { openId: 'wx1', unionId: 'u-9' })
      const [identity] = await store.listIdentities(r1.user.id)
      expect(identity?.unionId).toBe('u-9')
    })

    test('可信邮箱找回:apple 形 claim 命中既有邮箱用户并绑身份', async () => {
      const { user } = await store.createUserWithIdentity({ email: 'a@b.com' }, null)
      const r = await kit.login('wechat_mini', { openId: 'wxN', email: 'a@b.com' })
      expect(r.user.id).toBe(user.id)
      expect(r.isNewUser).toBe(false)
      expect((await store.listIdentities(user.id)).some((i) => i.openId === 'wxN')).toBe(true)
    })

    test('autoRegister=false 时未注册登录抛 user_not_found', async () => {
      const strict = new AuthKit({
        store,
        tokens: makeStrategy(strategyName, sessions),
        providers: [fakeFederated('wechat_mini')],
        policy: { autoRegister: false },
      })
      expect(strict.login('wechat_mini', { openId: 'nobody' })).rejects.toMatchObject({
        kind: 'user_not_found',
      })
    })

    test('封禁用户登录与 verify 均被拒', async () => {
      const r = await kit.login('wechat_mini', { openId: 'wx1' })
      await store.setStatus(r.user.id, 'blocked')
      expect(kit.login('wechat_mini', { openId: 'wx1' })).rejects.toMatchObject({ kind: 'user_blocked' })
      expect(kit.verify(r.tokens.access)).rejects.toMatchObject({ kind: 'user_blocked' })
    })

    test('verify:合法 token 返回用户,垃圾 token 抛 token_invalid', async () => {
      const r = await kit.login('wechat_mini', { openId: 'wx1' })
      const v = await kit.verify(r.tokens.access)
      expect(v.user.id).toBe(r.user.id)
      expect(kit.verify('garbage')).rejects.toMatchObject({ kind: 'token_invalid' })
    })

    test('单端登出后 access 失效', async () => {
      const r = await kit.login('wechat_mini', { openId: 'wx1' })
      await kit.logout({
        access: r.tokens.access,
        ...(r.tokens.refresh ? { refresh: r.tokens.refresh } : {}),
      })
      expect(kit.verify(r.tokens.access)).rejects.toMatchObject({ kind: 'token_revoked' })
    })

    test('全端登出:tokenVersion 递增,旧 access 全部失效', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1' })
      const r2 = await kit.login('wechat_mini', { openId: 'wx1' })
      await kit.logout({ userId: r1.user.id, allDevices: true })
      for (const t of [r1.tokens.access, r2.tokens.access]) {
        expect(kit.verify(t)).rejects.toMatchObject({ kind: 'token_revoked' })
      }
    })

    test('登录失败锁定:连续失败 → account_locked,正确密码也被拒', async () => {
      const cred = { account: 'alice' }
      await expect(kit.login('password', cred)).rejects.toMatchObject({
        kind: 'credential_invalid',
        detail: { attemptsLeft: 2 },
      })
      await expect(kit.login('password', cred)).rejects.toMatchObject({ detail: { attemptsLeft: 1 } })
      await expect(kit.login('password', cred)).rejects.toMatchObject({ kind: 'account_locked' })
      await expect(kit.login('password', { account: 'alice', ok: true })).rejects.toMatchObject({
        kind: 'account_locked',
      })
      // 其他账号不受影响
      const other = await kit.login('password', { account: 'bob99', ok: true })
      expect(other.user.id).toBeTruthy()
    })

    test('bind:身份被他人占用抛 identity_taken 且带 ownerId', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1' })
      const r2 = await kit.login('wechat_mini', { openId: 'wx2' })
      expect(kit.bind(r2.user.id, 'wechat_mini', { openId: 'wx1' })).rejects.toMatchObject({
        kind: 'identity_taken',
        detail: { ownerId: r1.user.id },
      })
      // 本人重复绑定幂等
      const idem = await kit.bind(r1.user.id, 'wechat_mini', { openId: 'wx1' })
      expect(idem?.userId).toBe(r1.user.id)
    })

    test('bindContact:被占抛 contact_taken(含 ownerId),本人幂等', async () => {
      const r1 = await kit.login('wechat_mini', { openId: 'wx1' })
      const r2 = await kit.login('wechat_mini', { openId: 'wx2' })
      await kit.bindContact(r1.user.id, 'phone', '13800138000')
      await expect(kit.bindContact(r2.user.id, 'phone', '+8613800138000')).rejects.toMatchObject({
        kind: 'contact_taken',
        detail: { ownerId: r1.user.id },
      })
      await kit.bindContact(r1.user.id, 'phone', '13800138000') // 幂等
    })

    test('unbind:唯一登录手段受 last_identity 保护', async () => {
      const r = await kit.login('wechat_mini', { openId: 'wx1' })
      expect(kit.unbind(r.user.id, 'wechat_mini', 'wx1', 'app1')).rejects.toMatchObject({
        kind: 'last_identity',
      })
      await kit.bindContact(r.user.id, 'phone', '13800138000')
      await kit.unbind(r.user.id, 'wechat_mini', 'wx1', 'app1') // 有手机号兜底后可解绑
      expect(await store.listIdentities(r.user.id)).toHaveLength(0)
    })

    test('mergeUsers:身份改挂、空壳软删、旧凭证失效、换发新凭证', async () => {
      const shell = await kit.login('wechat_mini', { openId: 'wx-shell' })
      const owner = await kit.login('wechat_open', { openId: 'open-owner' })
      const { tokens } = await kit.mergeUsers(shell.user.id, owner.user.id)
      // 空壳的微信身份现在解析到 owner
      const again = await kit.login('wechat_mini', { openId: 'wx-shell' })
      expect(again.user.id).toBe(owner.user.id)
      // 空壳旧 token 失效,新 token 归 owner
      expect(kit.verify(shell.tokens.access)).rejects.toBeInstanceOf(AuthError)
      expect((await kit.verify(tokens.access)).user.id).toBe(owner.user.id)
    })
  })
}

describe('AuthKit refresh(仅 JwtSession)', () => {
  test('旋转刷新:旧 refresh 作废,新对可用', async () => {
    const store = new InMemoryAuthStore()
    const sessions = new MemorySessionStore()
    const kit = new AuthKit({
      store,
      tokens: makeStrategy('jwt', sessions),
      providers: [fakeFederated('wechat_mini')],
    })
    const r = await kit.login('wechat_mini', { openId: 'wx1' })
    const refresh1 = r.tokens.refresh
    if (!refresh1) throw new Error('expected refresh token')
    const pair2 = await kit.refresh(refresh1)
    expect((await kit.verify(pair2.access)).user.id).toBe(r.user.id)
    // 旧 refresh 已被旋转吊销
    expect(kit.refresh(refresh1)).rejects.toMatchObject({ kind: 'token_revoked' })
    // 新 refresh 可继续
    if (!pair2.refresh) throw new Error('expected refresh token')
    const pair3 = await kit.refresh(pair2.refresh)
    expect((await kit.verify(pair3.access)).user.id).toBe(r.user.id)
  })

  test('Opaque 策略 refresh 抛 token_invalid(不支持)', async () => {
    const kit = new AuthKit({
      store: new InMemoryAuthStore(),
      tokens: new OpaqueTokenStrategy({ sessions: new MemorySessionStore() }),
      providers: [fakeFederated('wechat_mini')],
    })
    expect(kit.refresh('whatever')).rejects.toMatchObject({ kind: 'token_invalid' })
  })

  test('claims 透传:JWT verify 带回 claimsFromUser 写入的 role', async () => {
    const kit = new AuthKit({
      store: new InMemoryAuthStore(),
      tokens: makeStrategy('jwt', new MemorySessionStore()),
      providers: [fakeFederated('wechat_mini')],
    })
    const r = await kit.login('wechat_mini', { openId: 'wx1' })
    const v = await kit.verify(r.tokens.access)
    expect(v.claims?.role).toBe('user')
  })
})

describe('验证码全流程(SmsProvider + 引擎限流)', () => {
  function makeSmsKit(resendIntervalSec = 0) {
    const store = new InMemoryAuthStore()
    const channel = new StubSmsChannel()
    const codes = new MemoryCodeStore()
    const kit = new AuthKit({
      store,
      tokens: new OpaqueTokenStrategy({ sessions: new MemorySessionStore() }),
      providers: [new SmsProvider({ channel, codes }), new PasswordProvider({ store })],
      policy: { codeRate: { resendIntervalSec, perTargetDaily: 10, perIpHourly: 20 } },
    })
    return { kit, channel, store }
  }

  test('发码 → 短信登录自动建号 → 二次登录复用', async () => {
    const { kit, channel } = makeSmsKit()
    await kit.sendCode('sms', '13800138000', 'login')
    const code = channel.lastCode
    if (!code) throw new Error('no code sent')
    const r1 = await kit.login('sms', { phone: '13800138000', code })
    expect(r1.isNewUser).toBe(true)
    expect(r1.user.phone).toBe('+8613800138000')
    await kit.sendCode('sms', '+8613800138000', 'login')
    const r2 = await kit.login('sms', { phone: '13800138000', code: channel.lastCode ?? '' })
    expect(r2.user.id).toBe(r1.user.id)
    expect(r2.isNewUser).toBe(false)
  })

  test('错码 / 重复消费均拒;冷却期内重发限流', async () => {
    const { kit, channel } = makeSmsKit(60)
    await kit.sendCode('sms', '13800138000', 'login')
    expect(kit.login('sms', { phone: '13800138000', code: '000000' })).rejects.toMatchObject({
      kind: 'code_invalid',
    })
    const code = channel.lastCode ?? ''
    await kit.login('sms', { phone: '13800138000', code })
    expect(kit.login('sms', { phone: '13800138000', code })).rejects.toMatchObject({ kind: 'code_invalid' })
    expect(kit.sendCode('sms', '13800138000', 'login')).rejects.toMatchObject({ kind: 'code_rate_limited' })
  })

  test('register 场景已注册 → contact_taken;reset 场景未注册 → user_not_found', async () => {
    const { kit, channel } = makeSmsKit()
    await kit.sendCode('sms', '13800138000', 'login')
    await kit.login('sms', { phone: '13800138000', code: channel.lastCode ?? '' })
    expect(kit.sendCode('sms', '13800138000', 'register')).rejects.toMatchObject({ kind: 'contact_taken' })
    expect(kit.sendCode('sms', '13900139000', 'reset')).rejects.toMatchObject({ kind: 'user_not_found' })
  })

  test('设密码 → 账密登录 → 验证码重置密码后旧密码失效', async () => {
    const { kit, channel } = makeSmsKit()
    await kit.sendCode('sms', '13800138000', 'login')
    const r = await kit.login('sms', { phone: '13800138000', code: channel.lastCode ?? '' })
    await kit.setPassword(r.user.id, 'secret123')
    const byPwd = await kit.login('password', { account: '13800138000', password: 'secret123' })
    expect(byPwd.user.id).toBe(r.user.id)

    await kit.sendCode('sms', '13800138000', 'reset')
    await kit.resetPasswordByCode({
      kind: 'phone',
      target: '+8613800138000',
      code: channel.lastCode ?? '',
      newPassword: 'newpass456',
    })
    expect(kit.login('password', { account: '13800138000', password: 'secret123' })).rejects.toMatchObject({
      kind: 'credential_invalid',
    })
    const byNew = await kit.login('password', { account: '13800138000', password: 'newpass456' })
    expect(byNew.user.id).toBe(r.user.id)
  })
})
