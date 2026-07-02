// AuthKit 引擎:不变的登录管线(验证凭证 → 解析身份 → 签发凭证)+ 凭证生命周期 + 绑定/合并原语。
// 变化的部分全部在注入的 provider / store / tokens / kv 里。
import { AuthError, isAuthError } from './errors'
import { MemoryKv } from './kv'
import { tryNormalizeEmail, tryNormalizePhone } from './normalize'
import type {
  AuthKitOptions,
  AuthKitPolicy,
  AuthProvider,
  AuthStore,
  AuthUser,
  CodeScene,
  Identity,
  IdentityClaim,
  LoggerLike,
  LoginResult,
  NewIdentity,
  PlatformId,
  RedisLike,
  RequestContext,
  TokenPair,
  TokenStrategy,
  VerifyResult,
} from './types'
import { isCodeSender } from './types'

/** password provider 实现此接口后,引擎的 setPassword / resetPasswordByCode 可用 */
export interface PasswordManager {
  hashPassword(plain: string): Promise<string>
}

function hasPasswordManager(p: unknown): p is PasswordManager {
  return typeof (p as PasswordManager)?.hashPassword === 'function'
}

const DEFAULT_POLICY = {
  loginLock: { maxFails: 5, lockSec: 600 },
  codeRate: { resendIntervalSec: 60, perTargetDaily: 10, perIpHourly: 20 },
  unionFamilies: [['wechat_mini', 'wechat_open'], ['qq']] as PlatformId[][],
  autoRegister: true,
}

export class AuthKit {
  private readonly store: AuthStore
  private readonly tokens: TokenStrategy
  private readonly providers = new Map<PlatformId, AuthProvider>()
  private readonly kv: RedisLike
  private readonly hooks: AuthKitOptions['hooks']
  private readonly policy: Required<Pick<AuthKitPolicy, 'unionFamilies' | 'autoRegister'>> &
    Pick<AuthKitPolicy, 'loginLock' | 'codeRate'>
  private readonly logger: LoggerLike | null

  constructor(opts: AuthKitOptions) {
    this.store = opts.store
    this.tokens = opts.tokens
    for (const p of opts.providers) this.providers.set(p.platform, p)
    this.kv = opts.kv ?? new MemoryKv()
    this.hooks = opts.hooks ?? {}
    this.policy = {
      loginLock: opts.policy?.loginLock === undefined ? DEFAULT_POLICY.loginLock : opts.policy.loginLock,
      codeRate: opts.policy?.codeRate ?? DEFAULT_POLICY.codeRate,
      unionFamilies: opts.policy?.unionFamilies ?? DEFAULT_POLICY.unionFamilies,
      autoRegister: opts.policy?.autoRegister ?? DEFAULT_POLICY.autoRegister,
    }
    this.logger = opts.logger ?? null
  }

  // ---------- 登录管线 ----------

  async login(platform: PlatformId, credential: unknown, ctx: RequestContext = {}): Promise<LoginResult> {
    const provider = this.providerOf(platform)
    const lockKey = provider.lockKeyOf?.(credential) ?? null
    if (lockKey) await this.assertNotLocked(platform, lockKey, ctx)

    let claim: IdentityClaim
    try {
      claim = await provider.verify(credential, ctx)
    } catch (err) {
      if (lockKey && (isAuthError(err, 'credential_invalid') || isAuthError(err, 'code_invalid'))) {
        await this.recordFail(platform, lockKey, ctx, err)
      }
      throw err
    }
    if (lockKey) await this.clearFails(platform, lockKey, ctx)

    const { user, isNewUser } = await this.resolveUser(provider, claim)
    this.assertLoginable(user)
    const tokens = await this.tokens.issue(user, ctx)
    await this.store.markLogin(user.id, new Date())
    if (isNewUser) await this.fire('onUserCreated', () => this.hooks?.onUserCreated?.(user, claim))
    await this.fire('onLogin', () => this.hooks?.onLogin?.(user, platform, ctx))
    return { user, tokens, isNewUser, claim }
  }

  /**
   * 身份解析:provider 直通 → openid 直中(顺带回填 unionId)→ unionid 家族合并
   * → 可信联系方式找回(顺带绑定 federated 身份)→ 自动建号。
   */
  private async resolveUser(
    provider: AuthProvider,
    claim: IdentityClaim,
  ): Promise<{ user: AuthUser; isNewUser: boolean }> {
    if (claim.userId) {
      const user = await this.store.findUserById(claim.userId)
      if (!user) throw new AuthError('user_not_found')
      return { user, isNewUser: false }
    }

    const federated = provider.identityKind === 'federated'
    if (federated) {
      const direct = await this.store.findIdentity(claim.platform, claim.appId, claim.openId)
      if (direct) {
        const user = await this.store.findUserById(direct.userId)
        if (user) {
          if (claim.unionId && !direct.unionId) await this.store.setIdentityUnionId(direct.id, claim.unionId)
          return { user, isNewUser: false }
        }
        await this.store.unbindIdentity(direct.id) // 指向已删用户的 stale 绑定
      }
      if (claim.unionId) {
        const family = this.policy.unionFamilies.find((f) => f.includes(claim.platform)) ?? [claim.platform]
        const sibling = await this.store.findIdentityByUnionId(family, claim.unionId)
        if (sibling) {
          const user = await this.store.findUserById(sibling.userId)
          if (user) {
            await this.store.bindIdentity(user.id, this.identityOf(claim))
            return { user, isNewUser: false }
          }
        }
      }
    }

    const contact: { kind: 'phone' | 'email'; value: string } | null = claim.phone
      ? { kind: 'phone', value: claim.phone }
      : claim.email
        ? { kind: 'email', value: claim.email }
        : null
    if (contact) {
      const owner = await this.store.findUserByContact(contact.kind, contact.value)
      if (owner) {
        if (federated) await this.store.bindIdentity(owner.id, this.identityOf(claim))
        return { user: owner, isNewUser: false }
      }
    }

    if (!this.policy.autoRegister) throw new AuthError('user_not_found')
    const { user, created } = await this.store.createUserWithIdentity(
      { phone: claim.phone ?? null, email: claim.email ?? null },
      federated ? this.identityOf(claim) : null,
    )
    return { user, isNewUser: created }
  }

  private identityOf(claim: IdentityClaim): NewIdentity {
    return {
      platform: claim.platform,
      appId: claim.appId,
      openId: claim.openId,
      unionId: claim.unionId ?? null,
      ...(claim.profile ? { profile: claim.profile } : {}),
    }
  }

  // ---------- 凭证生命周期 ----------

  async verify(accessToken: string): Promise<VerifyResult> {
    const v = await this.tokens.verifyAccess(accessToken)
    const user = await this.store.findUserById(v.userId)
    if (!user) throw new AuthError('token_invalid')
    if (v.tokenVersion !== undefined && v.tokenVersion !== user.tokenVersion)
      throw new AuthError('token_revoked')
    this.assertLoginable(user)
    return { user, ...(v.claims ? { claims: v.claims } : {}), ...(v.jti ? { jti: v.jti } : {}) }
  }

  async refresh(refreshToken: string, ctx: RequestContext = {}): Promise<TokenPair> {
    if (!this.tokens.refresh) throw new AuthError('token_invalid', { reason: 'refresh_unsupported' })
    return this.tokens.refresh(refreshToken, ctx, async (userId) => {
      const user = await this.store.findUserById(userId)
      if (!user) throw new AuthError('token_invalid')
      this.assertLoginable(user)
      return user
    })
  }

  async logout(input: {
    access?: string
    refresh?: string
    userId?: string
    allDevices?: boolean
  }): Promise<void> {
    if (input.allDevices) {
      let userId = input.userId
      if (!userId && input.access) userId = (await this.tokens.verifyAccess(input.access)).userId
      if (!userId) throw new AuthError('token_invalid', { reason: 'no_user_for_logout_all' })
      await this.store.bumpTokenVersion(userId)
      await this.tokens.revokeAllForUser(userId)
    }
    const single: { access?: string; refresh?: string } = {}
    if (input.access) single.access = input.access
    if (input.refresh) single.refresh = input.refresh
    if (single.access || single.refresh) await this.tokens.revoke(single)
  }

  // ---------- 绑定 / 解绑 / 合并 ----------

  /** federated 平台返回新建的 Identity;local 平台(sms/email)绑定联系方式并返回 null */
  async bind(
    userId: string,
    platform: PlatformId,
    credential: unknown,
    ctx: RequestContext = {},
  ): Promise<Identity | null> {
    const provider = this.providerOf(platform)
    const claim = await provider.verify(credential, ctx)
    if (provider.identityKind === 'local') {
      const kind = claim.phone ? 'phone' : 'email'
      const value = claim.phone ?? claim.email
      if (!value) throw new AuthError('credential_invalid', { reason: 'no_contact_in_claim' })
      await this.bindContact(userId, kind, value)
      return null
    }
    const existing = await this.store.findIdentity(claim.platform, claim.appId, claim.openId)
    if (existing) {
      if (existing.userId === userId) return existing
      throw new AuthError('identity_taken', { ownerId: existing.userId })
    }
    return this.store.bindIdentity(userId, this.identityOf(claim))
  }

  async bindContact(userId: string, kind: 'phone' | 'email', value: string): Promise<void> {
    const normalized = kind === 'phone' ? tryNormalizePhone(value) : tryNormalizeEmail(value)
    if (!normalized) throw new AuthError('credential_invalid', { reason: `invalid_${kind}` })
    const owner = await this.store.findUserByContact(kind, normalized)
    if (owner) {
      if (owner.id === userId) return
      throw new AuthError('contact_taken', { ownerId: owner.id, [kind]: normalized })
    }
    await this.store.updateContact(userId, kind, normalized)
  }

  async unbind(userId: string, platform: PlatformId, openId: string, appId = ''): Promise<void> {
    const identity = await this.store.findIdentity(platform, appId, openId)
    if (!identity || identity.userId !== userId) throw new AuthError('identity_not_found')
    const user = await this.store.findUserById(userId)
    if (!user) throw new AuthError('user_not_found')
    const rest = (await this.store.listIdentities(userId)).filter((i) => i.id !== identity.id)
    if (rest.length === 0 && !user.phone && !user.email && !user.hasPassword) {
      throw new AuthError('last_identity')
    }
    await this.store.unbindIdentity(identity.id)
  }

  /**
   * 账号合并原语:from 的身份全部改挂到 to,from 软删且全端失效,换发 to 的新凭证。
   * 是否允许合并(如"空壳号才能被吞并")由业务在调用前判断。
   */
  async mergeUsers(
    fromUserId: string,
    toUserId: string,
    ctx: RequestContext = {},
  ): Promise<{ tokens: TokenPair }> {
    const [from, to] = await Promise.all([
      this.store.findUserById(fromUserId),
      this.store.findUserById(toUserId),
    ])
    if (!from || !to) throw new AuthError('user_not_found')
    this.assertLoginable(to)
    await this.store.reassignIdentities(fromUserId, toUserId)
    await this.store.softDeleteUser(fromUserId)
    await this.store.bumpTokenVersion(fromUserId)
    await this.tokens.revokeAllForUser(fromUserId)
    await this.store.markLogin(to.id, new Date())
    const tokens = await this.tokens.issue(to, ctx)
    return { tokens }
  }

  // ---------- 验证码 ----------

  async sendCode(
    platform: PlatformId,
    target: string,
    scene: CodeScene,
    ctx: RequestContext = {},
  ): Promise<{ resendAfterSec: number }> {
    const provider = this.providerOf(platform)
    if (!isCodeSender(provider))
      throw new AuthError('provider_not_configured', { platform, reason: 'not_code_sender' })

    const kind = platform === 'email' ? 'email' : 'phone'
    const normalized = kind === 'phone' ? tryNormalizePhone(target) : tryNormalizeEmail(target)
    if (!normalized) throw new AuthError('credential_invalid', { reason: `invalid_${kind}` })

    if (scene === 'register' || scene === 'reset') {
      const owner = await this.store.findUserByContact(kind, normalized)
      if (scene === 'register' && owner) throw new AuthError('contact_taken', { [kind]: normalized })
      if (scene === 'reset' && !owner) throw new AuthError('user_not_found')
    }

    const rate = this.policy.codeRate
    if (rate) {
      // 冷却按 (scene, target) 维度(对齐 m612/rensheji 现网行为);日限/IP 限按 target 全局
      const resendKey = `authkit:rl:resend:${scene}:${normalized}`
      const resendTtl = await this.kv.ttl(resendKey)
      if (resendTtl > 0) throw new AuthError('code_rate_limited', { retryAfterSec: resendTtl })
      const day = new Date().toISOString().slice(0, 10)
      const dayKey = `authkit:rl:day:${normalized}:${day}`
      const dayCount = await this.kv.incr(dayKey)
      if (dayCount === 1) await this.kv.expire(dayKey, 86400)
      if (dayCount > rate.perTargetDaily) throw new AuthError('code_rate_limited', { retryAfterSec: 86400 })
      if (ctx.ip) {
        const ipKey = `authkit:rl:ip:${ctx.ip}:${new Date().getUTCHours()}`
        const ipCount = await this.kv.incr(ipKey)
        if (ipCount === 1) await this.kv.expire(ipKey, 3600)
        if (ipCount > rate.perIpHourly) throw new AuthError('code_rate_limited', { retryAfterSec: 3600 })
      }
      await provider.sendCode(normalized, scene, ctx)
      await this.kv.set(resendKey, '1', 'EX', rate.resendIntervalSec)
      return { resendAfterSec: rate.resendIntervalSec }
    }
    await provider.sendCode(normalized, scene, ctx)
    return { resendAfterSec: 0 }
  }

  // ---------- 密码管理 ----------

  async setPassword(userId: string, newPassword: string): Promise<void> {
    const user = await this.store.findUserById(userId)
    if (!user) throw new AuthError('user_not_found')
    await this.store.setPasswordHash(userId, await this.hashPassword(newPassword))
  }

  async resetPasswordByCode(input: {
    kind: 'phone' | 'email'
    target: string
    code: string
    newPassword: string
  }): Promise<void> {
    const platform = input.kind === 'phone' ? 'sms' : 'email'
    const provider = this.providerOf(platform)
    const claim = await provider.verify(
      input.kind === 'phone'
        ? { phone: input.target, code: input.code, scene: 'reset' }
        : { email: input.target, code: input.code, scene: 'reset' },
      {},
    )
    const value = claim.phone ?? claim.email
    if (!value) throw new AuthError('credential_invalid')
    const user = await this.store.findUserByContact(input.kind, value)
    if (!user) throw new AuthError('user_not_found')
    await this.store.setPasswordHash(user.id, await this.hashPassword(input.newPassword))
    await this.store.bumpTokenVersion(user.id)
    await this.tokens.revokeAllForUser(user.id)
  }

  private async hashPassword(plain: string): Promise<string> {
    const pw = this.providers.get('password')
    if (!pw || !hasPasswordManager(pw)) {
      throw new AuthError('provider_not_configured', { platform: 'password' })
    }
    return pw.hashPassword(plain)
  }

  // ---------- 内部 ----------

  private providerOf(platform: PlatformId): AuthProvider {
    const p = this.providers.get(platform)
    if (!p) throw new AuthError('provider_not_configured', { platform })
    return p
  }

  private assertLoginable(user: AuthUser): void {
    if (user.status === 'blocked') throw new AuthError('user_blocked')
    if (user.status === 'locked') throw new AuthError('account_locked')
  }

  private lockKeys(
    platform: PlatformId,
    lockKey: string,
    ctx: RequestContext,
  ): { fail: string; lock: string } {
    const dim = `${platform}:${lockKey}:${ctx.ip ?? 'noip'}`
    return { fail: `authkit:lk:fail:${dim}`, lock: `authkit:lk:lock:${dim}` }
  }

  private async assertNotLocked(platform: PlatformId, lockKey: string, ctx: RequestContext): Promise<void> {
    if (!this.policy.loginLock) return
    const ttl = await this.kv.ttl(this.lockKeys(platform, lockKey, ctx).lock)
    if (ttl > 0) throw new AuthError('account_locked', { retryAfterSec: ttl })
  }

  private async recordFail(
    platform: PlatformId,
    lockKey: string,
    ctx: RequestContext,
    err: AuthError,
  ): Promise<void> {
    const lock = this.policy.loginLock
    if (!lock) return
    const keys = this.lockKeys(platform, lockKey, ctx)
    const fails = await this.kv.incr(keys.fail)
    if (fails === 1) await this.kv.expire(keys.fail, lock.lockSec)
    if (fails >= lock.maxFails) {
      await this.kv.set(keys.lock, '1', 'EX', lock.lockSec)
      throw new AuthError('account_locked', { retryAfterSec: lock.lockSec })
    }
    err.detail.attemptsLeft = lock.maxFails - fails
  }

  private async clearFails(platform: PlatformId, lockKey: string, ctx: RequestContext): Promise<void> {
    if (!this.policy.loginLock) return
    await this.kv.del(this.lockKeys(platform, lockKey, ctx).fail)
  }

  private async fire(name: string, fn: () => Promise<void> | undefined): Promise<void> {
    try {
      await fn()
    } catch (err) {
      this.logger?.warn({ err, hook: name }, 'authkit hook failed')
    }
  }
}
