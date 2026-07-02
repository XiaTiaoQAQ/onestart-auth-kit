import { describe, expect, test } from 'bun:test'
import { AliyunSmsChannel, aliyunRpcSignature, aliyunRpcStringToSign } from './aliyun'

describe('阿里云 RPC 签名(与 m612/rensheji 现网实现同源)', () => {
  test('StringToSign:字典序 + 参数级 RFC3986 编码 + 规范串整体二次编码', () => {
    const sts = aliyunRpcStringToSign('POST', { B: '2', A: '1 *~' })
    expect(sts).toBe('POST&%2F&A%3D1%2520%252A~%26B%3D2')
  })

  test('签名对固定输入稳定(HMAC-SHA1 + secret&)', () => {
    const sig = aliyunRpcSignature('POST', { Action: 'SendSms', PhoneNumbers: '13800138000' }, 'testsecret')
    expect(sig).toBe(
      aliyunRpcSignature('POST', { PhoneNumbers: '13800138000', Action: 'SendSms' }, 'testsecret'),
    )
    expect(sig).toHaveLength(28) // base64(SHA1) 定长
  })

  test('配置缺失构造即抛(fail fast)', () => {
    expect(
      () => new AliyunSmsChannel({ accessKeyId: '', accessKeySecret: 'x', signName: 's', templateCode: 't' }),
    ).toThrow(/accessKeyId/)
  })
})
