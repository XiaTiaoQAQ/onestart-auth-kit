import { AuthError } from '../../core/errors'
// 抖音小程序 provider(federated):v2 jscode2session(POST)。收编自 rensheji 的 platform-login.ts。
import type { AuthProvider, IdentityClaim, RequestContext } from '../../core/types'

export interface DouyinMiniCredential {
  code: string
}

export interface DouyinMiniOptions {
  appid: string
  secret: string
}

export class DouyinMiniProvider implements AuthProvider<DouyinMiniCredential> {
  readonly platform = 'douyin_mini'
  readonly identityKind = 'federated' as const
  readonly appId: string
  private readonly secret: string

  constructor(opts: DouyinMiniOptions) {
    if (!opts.appid || !opts.secret) throw new Error('DouyinMiniProvider: missing appid/secret')
    this.appId = opts.appid
    this.secret = opts.secret
  }

  async verify(credential: DouyinMiniCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const code = credential?.code
    if (!code) throw new AuthError('credential_invalid', { reason: 'missing_code' })
    const res = await fetch('https://developer.toutiao.com/api/apps/v2/jscode2session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ appid: this.appId, secret: this.secret, code }),
    })
    if (!res.ok) throw new AuthError('provider_upstream', { platform: this.platform, status: res.status })
    const payload = (await res.json().catch(() => ({}))) as {
      err_no?: number
      err_tips?: string
      data?: { openid?: string }
    }
    if (payload.err_no || !payload.data?.openid) {
      throw new AuthError('provider_upstream', {
        platform: this.platform,
        errNo: payload.err_no,
        errTips: payload.err_tips,
      })
    }
    // 抖音无 unionid 概念
    return { platform: this.platform, appId: this.appId, openId: payload.data.openid, unionId: null }
  }
}
