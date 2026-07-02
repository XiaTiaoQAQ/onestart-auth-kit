// 阿里云 Dysmsapi 短信渠道(收编自 m612-pet-api / rensheji 两处同源实现)。
// 零依赖:node:crypto HMAC-SHA1 + fetch;RPC 风格签名。模板须含 ${code} 变量。
import { createHmac, randomUUID } from 'node:crypto'
import type { CodeScene } from '../../core/types'
import type { SmsChannel } from './index'

function percentEncode(s: string): string {
  return encodeURIComponent(s).replace(/\+/g, '%20').replace(/\*/g, '%2A').replace(/%7E/g, '~')
}

/** 规范化请求串 → StringToSign(method&%2F&<encoded canonical query>) */
export function aliyunRpcStringToSign(method: string, params: Record<string, string>): string {
  const canonical = Object.keys(params)
    .sort()
    .map((k) => `${percentEncode(k)}=${percentEncode(params[k] ?? '')}`)
    .join('&')
  return `${method}&${percentEncode('/')}&${percentEncode(canonical)}`
}

/** RPC v1 签名:base64(HMAC-SHA1(secret + '&', StringToSign)) */
export function aliyunRpcSignature(
  method: string,
  params: Record<string, string>,
  accessKeySecret: string,
): string {
  return createHmac('sha1', `${accessKeySecret}&`)
    .update(aliyunRpcStringToSign(method, params))
    .digest('base64')
}

export interface AliyunSmsOptions {
  accessKeyId: string
  accessKeySecret: string
  signName: string
  templateCode: string
  /** 英文模板(i18n);ctx.locale 非 zh 开头时使用 */
  templateCodeEn?: string
  endpoint?: string
}

export class AliyunSmsChannel implements SmsChannel {
  constructor(private readonly cfg: AliyunSmsOptions) {
    for (const k of ['accessKeyId', 'accessKeySecret', 'signName', 'templateCode'] as const) {
      if (!cfg[k]) throw new Error(`AliyunSmsChannel: missing ${k}`)
    }
  }

  async send(phone: string, code: string, opts: { scene: CodeScene; locale?: string }): Promise<void> {
    const template =
      opts.locale && !opts.locale.startsWith('zh') && this.cfg.templateCodeEn
        ? this.cfg.templateCodeEn
        : this.cfg.templateCode
    const params: Record<string, string> = {
      AccessKeyId: this.cfg.accessKeyId,
      Action: 'SendSms',
      Format: 'JSON',
      RegionId: 'cn-hangzhou',
      SignatureMethod: 'HMAC-SHA1',
      SignatureNonce: randomUUID(),
      SignatureVersion: '1.0',
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      Version: '2017-05-25',
      // 阿里云国内短信收裸 11 位号;E.164 的 +86 前缀在此剥离
      PhoneNumbers: phone.replace(/^\+86/, ''),
      SignName: this.cfg.signName,
      TemplateCode: template,
      TemplateParam: JSON.stringify({ code }),
    }
    const signature = aliyunRpcSignature('POST', params, this.cfg.accessKeySecret)
    const body = new URLSearchParams({ ...params, Signature: signature }).toString()

    const res = await fetch(`https://${this.cfg.endpoint ?? 'dysmsapi.aliyuncs.com'}/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    const text = await res.text()
    let payload: { Code?: string; Message?: string } = {}
    try {
      payload = JSON.parse(text) as typeof payload
    } catch {
      // 非 JSON(网关错误页等)落到下方失败分支
    }
    if (!res.ok || payload.Code !== 'OK') {
      throw new Error(`ALIYUN_SMS_${payload.Code ?? res.status}: ${payload.Message ?? text.slice(0, 200)}`)
    }
  }
}
