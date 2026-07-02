// JWT + 会话策略(m612 模式):access 短期 JWT,refresh 长期 JWT + jti 落 SessionStore 旋转刷新,
// jti 黑名单进 RedisLike,tokenVersion 全端登出由引擎在 verify 时比对。
// payload 骨架对齐 m612 现网:{ sub, jti, iat, exp, scope: 'user'|'refresh', ver, ...claims } ——
// 同 secret 下,接入前已发放的 token 可无缝验证。
import { AuthError } from './errors'
import { signJwtHS256, verifyJwtHS256 } from './jwt'
import { MemoryKv } from './kv'
import type {
  AuthUser,
  RedisLike,
  RequestContext,
  SessionStore,
  TokenPair,
  TokenStrategy,
  VerifiedAccess,
} from './types'

export interface JwtSessionOptions {
  /** HS256 密钥,至少 16 字符 */
  secret: string
  /** access 有效期,缺省 30 分钟 */
  accessTtlSec?: number
  /** refresh 有效期,缺省 30 天 */
  refreshTtlSec?: number
  sessions: SessionStore
  /** jti 黑名单存储;缺省 MemoryKv(仅单进程) */
  kv?: RedisLike
  /** 黑名单键前缀;m612 接入传 'jwt:black:' 对齐存量键 */
  blacklistPrefix?: string
  /** 返回值并入 access payload(如 m612 的 role),verifyAccess 经 claims 原样带回 */
  claimsFromUser?: (user: AuthUser) => Record<string, unknown>
}

const RESERVED = new Set(['sub', 'jti', 'iat', 'exp', 'scope', 'ver'])

export class JwtSessionStrategy implements TokenStrategy {
  private readonly secret: string
  private readonly accessTtlSec: number
  private readonly refreshTtlSec: number
  private readonly sessions: SessionStore
  private readonly kv: RedisLike
  private readonly blackPrefix: string
  private readonly claimsFromUser: ((user: AuthUser) => Record<string, unknown>) | null

  constructor(opts: JwtSessionOptions) {
    if (!opts.secret || opts.secret.length < 16)
      throw new Error('JwtSessionStrategy: secret must be at least 16 chars')
    this.secret = opts.secret
    this.accessTtlSec = opts.accessTtlSec ?? 30 * 60
    this.refreshTtlSec = opts.refreshTtlSec ?? 30 * 86400
    this.sessions = opts.sessions
    this.kv = opts.kv ?? new MemoryKv()
    this.blackPrefix = opts.blacklistPrefix ?? 'authkit:black:'
    this.claimsFromUser = opts.claimsFromUser ?? null
  }

  async issue(user: AuthUser, ctx: RequestContext): Promise<TokenPair> {
    const iat = Math.floor(Date.now() / 1000)
    const extra = this.claimsFromUser?.(user) ?? {}
    const access = await signJwtHS256(
      {
        ...extra,
        sub: user.id,
        jti: `jti_${crypto.randomUUID()}`,
        iat,
        exp: iat + this.accessTtlSec,
        scope: 'user',
        ver: user.tokenVersion,
      },
      this.secret,
    )
    const refreshJti = `rti_${crypto.randomUUID()}`
    const refresh = await signJwtHS256(
      {
        sub: user.id,
        jti: refreshJti,
        iat,
        exp: iat + this.refreshTtlSec,
        scope: 'refresh',
        ver: user.tokenVersion,
      },
      this.secret,
    )
    await this.sessions.insert({
      userId: user.id,
      key: refreshJti,
      client: ctx.client ?? '',
      ...(ctx.ip ? { ip: ctx.ip } : {}),
      ...(ctx.userAgent ? { userAgent: ctx.userAgent } : {}),
      expiresAt: new Date((iat + this.refreshTtlSec) * 1000),
    })
    return { access, refresh, expiresInSec: this.accessTtlSec }
  }

  async verifyAccess(token: string): Promise<VerifiedAccess> {
    const p = await verifyJwtHS256(token, this.secret)
    if (p.scope !== 'user' || typeof p.sub !== 'string') throw new AuthError('token_invalid')
    const jti = typeof p.jti === 'string' ? p.jti : undefined
    if (jti && (await this.kv.get(this.blackPrefix + jti))) throw new AuthError('token_revoked')
    const claims: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(p)) if (!RESERVED.has(k)) claims[k] = v
    return {
      userId: p.sub,
      ...(jti ? { jti } : {}),
      ...(typeof p.ver === 'number' ? { tokenVersion: p.ver } : {}),
      ...(Object.keys(claims).length ? { claims } : {}),
    }
  }

  async refresh(
    refreshToken: string,
    ctx: RequestContext,
    resolveUser: (userId: string) => Promise<AuthUser>,
  ): Promise<TokenPair> {
    const p = await verifyJwtHS256(refreshToken, this.secret)
    if (p.scope !== 'refresh' || typeof p.sub !== 'string' || typeof p.jti !== 'string') {
      throw new AuthError('token_invalid')
    }
    const session = await this.sessions.find(p.jti)
    if (!session || session.revokedAt || session.expiresAt.getTime() <= Date.now()) {
      throw new AuthError('token_revoked')
    }
    const user = await resolveUser(p.sub)
    if (typeof p.ver === 'number' && p.ver !== user.tokenVersion) throw new AuthError('token_revoked')
    await this.sessions.revoke(p.jti)
    return this.issue(user, ctx)
  }

  async revoke(input: { access?: string; refresh?: string }): Promise<void> {
    if (input.access) {
      try {
        const p = await verifyJwtHS256(input.access, this.secret)
        if (typeof p.jti === 'string') {
          const ttl = Math.max(1, Number(p.exp ?? 0) - Math.floor(Date.now() / 1000))
          await this.kv.set(this.blackPrefix + p.jti, '1', 'EX', ttl)
        }
      } catch {
        // 已过期/非法的 access 无需拉黑
      }
    }
    if (input.refresh) {
      try {
        const p = await verifyJwtHS256(input.refresh, this.secret)
        if (typeof p.jti === 'string') await this.sessions.revoke(p.jti)
      } catch {
        // 同上
      }
    }
  }

  async revokeAllForUser(userId: string): Promise<void> {
    // access 侧的全端失效由引擎 bumpTokenVersion 完成;这里吊销全部 refresh 会话。
    await this.sessions.revokeAllForUser(userId)
  }
}
