// 支付宝小程序 provider(federated):alipay.system.oauth.token,RSA2(SHA256withRSA)签名。
// 零依赖:node:crypto。支付宝无 unionid,跨端归一靠手机号绑定(DESIGN §8)。
import { createSign } from 'node:crypto'
import { AuthError } from '../../core/errors'
import type { AuthProvider, IdentityClaim, RequestContext } from '../../core/types'

export interface AlipayMiniCredential {
  code: string
}

export interface AlipayMiniOptions {
  appid: string
  /** 应用私钥:PKCS8 PEM 或裸 base64(自动包 PEM 头) */
  privateKey: string
  gateway?: string
}

function toPem(key: string): string {
  if (key.includes('BEGIN')) return key
  const body = key.replace(/\s+/g, '').replace(/(.{64})/g, '$1\n')
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----`
}

/** 支付宝网关要求 GMT+8 的 yyyy-MM-dd HH:mm:ss */
function alipayTimestamp(): string {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 19).replace('T', ' ')
}

export class AlipayMiniProvider implements AuthProvider<AlipayMiniCredential> {
  readonly platform = 'alipay_mini'
  readonly identityKind = 'federated' as const
  readonly appId: string
  private readonly privateKeyPem: string
  private readonly gateway: string

  constructor(opts: AlipayMiniOptions) {
    if (!opts.appid || !opts.privateKey) throw new Error('AlipayMiniProvider: missing appid/privateKey')
    this.appId = opts.appid
    this.privateKeyPem = toPem(opts.privateKey)
    this.gateway = opts.gateway ?? 'https://openapi.alipay.com/gateway.do'
  }

  async verify(credential: AlipayMiniCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const code = credential?.code
    if (!code) throw new AuthError('credential_invalid', { reason: 'missing_code' })

    const params: Record<string, string> = {
      app_id: this.appId,
      method: 'alipay.system.oauth.token',
      format: 'JSON',
      charset: 'utf-8',
      sign_type: 'RSA2',
      timestamp: alipayTimestamp(),
      version: '1.0',
      grant_type: 'authorization_code',
      code,
    }
    params.sign = this.sign(params)

    const res = await fetch(this.gateway, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params).toString(),
    })
    if (!res.ok) throw new AuthError('provider_upstream', { platform: this.platform, status: res.status })
    const payload = (await res.json().catch(() => ({}))) as {
      alipay_system_oauth_token_response?: { user_id?: string; open_id?: string; code?: string; msg?: string }
      error_response?: { code?: string; msg?: string; sub_msg?: string }
    }
    const err = payload.error_response
    if (err) {
      throw new AuthError('provider_upstream', {
        platform: this.platform,
        code: err.code,
        msg: err.sub_msg ?? err.msg,
      })
    }
    const body = payload.alipay_system_oauth_token_response
    const openId = body?.open_id ?? body?.user_id
    if (!openId) {
      throw new AuthError('provider_upstream', { platform: this.platform, code: body?.code, msg: body?.msg })
    }
    return { platform: this.platform, appId: this.appId, openId, unionId: null }
  }

  /** RSA2:参数按键名字典序 key=value 用 & 连接(不做 URL 编码),SHA256withRSA 签名后 base64 */
  private sign(params: Record<string, string>): string {
    const content = Object.keys(params)
      .filter((k) => k !== 'sign' && params[k] !== '')
      .sort()
      .map((k) => `${k}=${params[k]}`)
      .join('&')
    return createSign('RSA-SHA256').update(content, 'utf8').sign(this.privateKeyPem, 'base64')
  }
}
