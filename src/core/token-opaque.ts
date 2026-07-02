// 不透明 token 策略(rensheji 模式):token 本身即会话键,查库校验。
// 即时吊销、零额外依赖;每次鉴权一次存储查询,量级上来换 JwtSessionStrategy,业务代码不动。
import { AuthError } from './errors'
import type {
  AuthUser,
  RequestContext,
  SessionStore,
  TokenPair,
  TokenStrategy,
  VerifiedAccess,
} from './types'

export function randomHex(bytes: number): string {
  const buf = new Uint8Array(bytes)
  crypto.getRandomValues(buf)
  return Array.from(buf, (b) => b.toString(16).padStart(2, '0')).join('')
}

export interface OpaqueTokenOptions {
  sessions: SessionStore
  /** access token 有效期,缺省 7 天 */
  ttlSec?: number
}

export class OpaqueTokenStrategy implements TokenStrategy {
  private readonly sessions: SessionStore
  private readonly ttlSec: number

  constructor(opts: OpaqueTokenOptions) {
    this.sessions = opts.sessions
    this.ttlSec = opts.ttlSec ?? 7 * 86400
  }

  async issue(user: AuthUser, ctx: RequestContext): Promise<TokenPair> {
    const token = randomHex(32)
    await this.sessions.insert({
      userId: user.id,
      key: token,
      client: ctx.client ?? '',
      ...(ctx.ip ? { ip: ctx.ip } : {}),
      ...(ctx.userAgent ? { userAgent: ctx.userAgent } : {}),
      expiresAt: new Date(Date.now() + this.ttlSec * 1000),
    })
    return { access: token, expiresInSec: this.ttlSec }
  }

  async verifyAccess(token: string): Promise<VerifiedAccess> {
    const row = await this.sessions.find(token)
    if (!row) throw new AuthError('token_invalid')
    if (row.revokedAt) throw new AuthError('token_revoked')
    if (row.expiresAt.getTime() <= Date.now()) throw new AuthError('token_expired')
    return { userId: row.userId }
  }

  async revoke(input: { access?: string; refresh?: string }): Promise<void> {
    if (input.access) await this.sessions.revoke(input.access)
    if (input.refresh) await this.sessions.revoke(input.refresh)
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.sessions.revokeAllForUser(userId)
  }
}
