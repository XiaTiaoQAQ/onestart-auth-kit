import { AuthError } from '../../core/errors'
import { tryNormalizeEmail } from '../../core/normalize'
// Apple 登录 provider(federated):对 Apple JWKS 验 identityToken 的 JWS(ES256/RS256),
// 校验 iss/aud/exp。依赖 jose(optional peer,仅本入口)。email 仅首次授权返回,进 claim。
import type { AuthProvider, IdentityClaim, RequestContext } from '../../core/types'

export interface AppleCredential {
  identityToken: string
}

export interface AppleOptions {
  /** app 的 bundle id(原生)或 Services ID(web),即 JWT 的 aud */
  clientId: string
  /** 多客户端(iOS + web)时传全部合法 aud */
  extraClientIds?: string[]
}

const APPLE_ISSUER = 'https://appleid.apple.com'
const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys'

/** jose 的最小结构面(optional peer,不引入其类型依赖,避免 d.ts 传染) */
interface JoseModule {
  createRemoteJWKSet(url: URL): unknown
  jwtVerify(
    token: string,
    jwks: unknown,
    opts: { issuer: string; audience: string[] },
  ): Promise<{ payload: Record<string, unknown> }>
}

export class AppleProvider implements AuthProvider<AppleCredential> {
  readonly platform = 'apple'
  readonly identityKind = 'federated' as const
  readonly appId: string
  private readonly audiences: string[]
  private jwks: unknown = null

  constructor(opts: AppleOptions) {
    if (!opts.clientId) throw new Error('AppleProvider: missing clientId')
    this.appId = opts.clientId
    this.audiences = [opts.clientId, ...(opts.extraClientIds ?? [])]
  }

  async verify(credential: AppleCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const token = credential?.identityToken
    if (!token) throw new AuthError('credential_invalid', { reason: 'missing_identity_token' })
    const jose = await this.importJose()
    this.jwks ??= jose.createRemoteJWKSet(new URL(APPLE_JWKS_URL))
    let payload: { sub?: string; email?: string; email_verified?: boolean | string }
    try {
      const r = await jose.jwtVerify(token, this.jwks, { issuer: APPLE_ISSUER, audience: this.audiences })
      payload = r.payload as typeof payload
    } catch {
      throw new AuthError('credential_invalid', { reason: 'apple_jws_verify_failed' })
    }
    if (!payload.sub) throw new AuthError('credential_invalid', { reason: 'apple_no_sub' })
    const emailVerified = payload.email_verified === true || payload.email_verified === 'true'
    const email = emailVerified && payload.email ? tryNormalizeEmail(payload.email) : null
    return {
      platform: this.platform,
      appId: this.appId,
      openId: payload.sub,
      unionId: null,
      ...(email ? { email } : {}),
    }
  }

  private async importJose(): Promise<JoseModule> {
    try {
      const name = 'jose'
      return (await import(name)) as JoseModule
    } catch {
      throw new AuthError('provider_not_configured', { platform: this.platform, reason: 'install jose' })
    }
  }
}
