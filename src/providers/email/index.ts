import { AuthError } from '../../core/errors'
import { tryNormalizeEmail } from '../../core/normalize'
// 邮箱验证码 provider(local):与 sms 同构,发送走 EmailChannel,验码走 CodeStore。
import type {
  AuthProvider,
  CodeScene,
  CodeSender,
  CodeStore,
  IdentityClaim,
  RequestContext,
} from '../../core/types'

export interface EmailChannel {
  send(email: string, code: string, opts: { scene: CodeScene; locale?: string }): Promise<void>
}

/** 开发替身:验证码只进日志,绝不可用于生产。 */
export class StubEmailChannel implements EmailChannel {
  lastCode: string | null = null
  async send(email: string, code: string, opts: { scene: CodeScene }): Promise<void> {
    this.lastCode = code
    console.log(`[authkit:email:stub] email=${email} scene=${opts.scene} code=${code}(未真实发送)`)
  }
}

export interface EmailCredential {
  email: string
  code: string
  scene?: CodeScene
}

export interface EmailProviderOptions {
  channel: EmailChannel
  codes: CodeStore
  codeTtlSec?: number
  codeLength?: number
}

export class EmailProvider implements AuthProvider<EmailCredential>, CodeSender {
  readonly platform = 'email'
  readonly appId = ''
  readonly identityKind = 'local' as const
  private readonly channel: EmailChannel
  private readonly codes: CodeStore
  private readonly ttlSec: number
  private readonly codeLength: number

  constructor(opts: EmailProviderOptions) {
    this.channel = opts.channel
    this.codes = opts.codes
    this.ttlSec = opts.codeTtlSec ?? 600
    this.codeLength = opts.codeLength ?? 6
  }

  async sendCode(target: string, scene: CodeScene, ctx: RequestContext): Promise<void> {
    // 先发后存:发送失败则不落库、不覆盖旧码
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    const code = String((buf[0] ?? 0) % 10 ** this.codeLength).padStart(this.codeLength, '0')
    await this.channel.send(target, code, { scene, ...(ctx.locale ? { locale: ctx.locale } : {}) })
    await this.codes.save(target, scene, code, this.ttlSec)
  }

  async verify(credential: EmailCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const { code } = credential ?? {}
    const scene = credential?.scene ?? 'login'
    const email = credential?.email ? tryNormalizeEmail(credential.email) : null
    if (!email || !code) throw new AuthError('credential_invalid')
    const ok = await this.codes.consume(email, scene, code)
    if (!ok) throw new AuthError('code_invalid')
    return { platform: this.platform, appId: '', openId: email, email }
  }
}
