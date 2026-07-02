import { AuthError } from '../../core/errors'
import { MemoryKv } from '../../core/kv'
// 微信小程序 provider(federated):code2session 登录 + getPhoneNumber 手机号快速验证。
// access_token 经 RedisLike 缓存(微信 7200s,留 120s 余量)—— 收编自 m612 的 WechatMiniProgramClient。
import type { AuthProvider, IdentityClaim, RedisLike, RequestContext } from '../../core/types'

const WX_API_BASE = 'https://api.weixin.qq.com'

interface WxErrorish {
  errcode?: number
  errmsg?: string
}

export interface WechatMiniCredential {
  code: string
}

export interface WechatMiniOptions {
  appid: string
  secret: string
  /** access_token 缓存;缺省 MemoryKv(仅单进程) */
  kv?: RedisLike
}

export class WechatMiniProvider implements AuthProvider<WechatMiniCredential> {
  readonly platform = 'wechat_mini'
  readonly identityKind = 'federated' as const
  readonly appId: string
  private readonly secret: string
  private readonly kv: RedisLike

  constructor(opts: WechatMiniOptions) {
    if (!opts.appid || !opts.secret) throw new Error('WechatMiniProvider: missing appid/secret')
    this.appId = opts.appid
    this.secret = opts.secret
    this.kv = opts.kv ?? new MemoryKv()
  }

  async verify(credential: WechatMiniCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const code = credential?.code
    if (!code) throw new AuthError('credential_invalid', { reason: 'missing_code' })
    const qs = new URLSearchParams({
      appid: this.appId,
      secret: this.secret,
      js_code: code,
      grant_type: 'authorization_code',
    })
    const data = await this.getJson<WxErrorish & { openid?: string; unionid?: string }>(
      `${WX_API_BASE}/sns/jscode2session?${qs}`,
    )
    if (data.errcode || !data.openid) {
      throw new AuthError('provider_upstream', {
        platform: this.platform,
        errcode: data.errcode,
        errmsg: data.errmsg,
      })
    }
    return { platform: this.platform, appId: this.appId, openId: data.openid, unionId: data.unionid ?? null }
  }

  /**
   * getPhoneNumber 按钮回调的动态 code 换手机号(新版,免 session_key 解密)。
   * 返回 E.164;配合 kit.bindContact / kit.mergeUsers 完成绑定与合并(DESIGN §5.3)。
   */
  async getPhoneNumber(code: string): Promise<string> {
    if (!code) throw new AuthError('credential_invalid', { reason: 'missing_code' })
    const token = await this.getAccessToken()
    const data = await this.postJson<
      WxErrorish & { phone_info?: { purePhoneNumber?: string; countryCode?: string } }
    >(`${WX_API_BASE}/wxa/business/getuserphonenumber?access_token=${encodeURIComponent(token)}`, { code })
    const info = data.phone_info
    if (data.errcode || !info?.purePhoneNumber) {
      throw new AuthError('provider_upstream', {
        platform: this.platform,
        errcode: data.errcode,
        errmsg: data.errmsg,
      })
    }
    return `+${info.countryCode || '86'}${info.purePhoneNumber}`
  }

  private async getAccessToken(): Promise<string> {
    const key = `authkit:wx:token:${this.appId}`
    const cached = await this.kv.get(key)
    if (cached) return cached
    const qs = new URLSearchParams({
      grant_type: 'client_credential',
      appid: this.appId,
      secret: this.secret,
    })
    const data = await this.getJson<WxErrorish & { access_token?: string; expires_in?: number }>(
      `${WX_API_BASE}/cgi-bin/token?${qs}`,
    )
    if (data.errcode || !data.access_token) {
      throw new AuthError('provider_upstream', {
        platform: this.platform,
        errcode: data.errcode,
        errmsg: data.errmsg,
      })
    }
    await this.kv.set(key, data.access_token, 'EX', Math.max(60, (data.expires_in ?? 7200) - 120))
    return data.access_token
  }

  private async getJson<T>(url: string): Promise<T> {
    const res = await fetch(url)
    if (!res.ok) throw new AuthError('provider_upstream', { platform: this.platform, status: res.status })
    return (await res.json()) as T
  }

  private async postJson<T>(url: string, body: unknown): Promise<T> {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    })
    if (!res.ok) throw new AuthError('provider_upstream', { platform: this.platform, status: res.status })
    return (await res.json()) as T
  }
}
