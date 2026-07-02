import { AuthError } from '../../core/errors'
import { tryNormalizePhone } from '../../core/normalize'
// 短信验证码 provider(local):发码走 SmsChannel,验码走 CodeStore 原子消费。
// 发送限流(冷却/日限/IP 限)由引擎统一执行,这里只负责生成、存码、发送。
import type {
  AuthProvider,
  CodeScene,
  CodeSender,
  CodeStore,
  IdentityClaim,
  RequestContext,
} from '../../core/types'

export interface SmsChannel {
  /** 真实发送;失败抛错。phone 为 E.164。 */
  send(phone: string, code: string, opts: { scene: CodeScene; locale?: string }): Promise<void>
}

export { AliyunSmsChannel, type AliyunSmsOptions } from './aliyun'

/** 开发替身:验证码只进日志,绝不可用于生产。 */
export class StubSmsChannel implements SmsChannel {
  lastCode: string | null = null
  async send(phone: string, code: string, opts: { scene: CodeScene }): Promise<void> {
    this.lastCode = code
    console.log(`[authkit:sms:stub] phone=${phone} scene=${opts.scene} code=${code}(未真实发送)`)
  }
}

export interface SmsCredential {
  phone: string
  code: string
  /** 缺省 'login';绑定/找回场景由调用方显式指定 */
  scene?: CodeScene
}

export interface SmsProviderOptions {
  channel: SmsChannel
  codes: CodeStore
  /** 验证码有效期,缺省 300s */
  codeTtlSec?: number
  /** 验证码位数,缺省 6 */
  codeLength?: number
}

export class SmsProvider implements AuthProvider<SmsCredential>, CodeSender {
  readonly platform = 'sms'
  readonly appId = ''
  readonly identityKind = 'local' as const
  private readonly channel: SmsChannel
  private readonly codes: CodeStore
  private readonly ttlSec: number
  private readonly codeLength: number

  constructor(opts: SmsProviderOptions) {
    this.channel = opts.channel
    this.codes = opts.codes
    this.ttlSec = opts.codeTtlSec ?? 300
    this.codeLength = opts.codeLength ?? 6
  }

  async sendCode(target: string, scene: CodeScene, ctx: RequestContext): Promise<void> {
    // 先发后存:发送失败则不落库、不覆盖旧码(引擎的冷却也只在成功后设置)
    const code = this.generateCode()
    await this.channel.send(target, code, { scene, ...(ctx.locale ? { locale: ctx.locale } : {}) })
    await this.codes.save(target, scene, code, this.ttlSec)
  }

  async verify(credential: SmsCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const { code } = credential ?? {}
    const scene = credential?.scene ?? 'login'
    const phone = credential?.phone ? tryNormalizePhone(credential.phone) : null
    if (!phone || !code) throw new AuthError('credential_invalid')
    const ok = await this.codes.consume(phone, scene, code)
    if (!ok) throw new AuthError('code_invalid')
    return { platform: this.platform, appId: '', openId: phone, phone }
  }

  private generateCode(): string {
    const buf = new Uint32Array(1)
    crypto.getRandomValues(buf)
    const n = (buf[0] ?? 0) % 10 ** this.codeLength
    return String(n).padStart(this.codeLength, '0')
  }
}
