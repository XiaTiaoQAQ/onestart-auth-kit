// 零依赖 JWT HS256(WebCrypto),Bun/Node 通用。仅覆盖本 SDK 所需:HS256 签发与验签。
import { AuthError } from './errors'

const enc = new TextEncoder()

function b64url(bytes: Uint8Array): string {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function b64urlDecode(s: string): Uint8Array<ArrayBuffer> {
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'))
  const buf = new Uint8Array(new ArrayBuffer(bin.length))
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i)
  return buf
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
    'verify',
  ])
}

export async function signJwtHS256(payload: Record<string, unknown>, secret: string): Promise<string> {
  const header = b64url(enc.encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
  const body = b64url(enc.encode(JSON.stringify(payload)))
  const key = await hmacKey(secret)
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(`${header}.${body}`))
  return `${header}.${body}.${b64url(new Uint8Array(sig))}`
}

/** 验签 + 解析;签名/结构错误抛 token_invalid,过期抛 token_expired。 */
export async function verifyJwtHS256(token: string, secret: string): Promise<Record<string, unknown>> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new AuthError('token_invalid')
  const [header, body, sig] = parts as [string, string, string]
  let ok = false
  try {
    const key = await hmacKey(secret)
    ok = await crypto.subtle.verify('HMAC', key, b64urlDecode(sig), enc.encode(`${header}.${body}`))
  } catch {
    throw new AuthError('token_invalid')
  }
  if (!ok) throw new AuthError('token_invalid')
  let payload: Record<string, unknown>
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecode(body)))
  } catch {
    throw new AuthError('token_invalid')
  }
  const exp = Number(payload.exp)
  if (Number.isFinite(exp) && exp * 1000 <= Date.now()) throw new AuthError('token_expired')
  return payload
}
