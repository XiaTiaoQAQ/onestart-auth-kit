// 全流程冒烟:发码 → 短信登录建号 → me → 设密码 → 账密登录 → 登出 → 旧 token 失效。
// 直接内存内起 Hono app,走真实 HTTP 语义(app.request)。
import { buildApp } from './index'

const { app, kit, smsChannel } = buildApp()

async function json(res: Response): Promise<Record<string, unknown>> {
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${await res.text()}`)
  return (await res.json()) as Record<string, unknown>
}

// 1. 发码
await json(
  await app.request('/api/auth/code/send', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ platform: 'sms', target: '13800138000', scene: 'login' }),
  }),
)
const code = smsChannel.lastCode
if (!code) throw new Error('smoke: no code')

// 2. 短信登录(自动建号)
const login = await json(
  await app.request('/api/auth/login/sms', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ phone: '13800138000', code }),
  }),
)
const data = login.data as { tokens: { access: string }; isNewUser: boolean }
if (!data.isNewUser) throw new Error('smoke: expected new user')
const access = data.tokens.access

// 3. 受保护端点
const me = await json(await app.request('/api/me', { headers: { authorization: `Bearer ${access}` } }))
const userId = (me.data as { id: string }).id

// 4. 设密码(演示直接调 kit)+ 账密登录
await kit.setPassword(userId, 'demo-pass-123')
const pwLogin = await json(
  await app.request('/api/auth/login/password', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ account: '13800138000', password: 'demo-pass-123' }),
  }),
)
if ((pwLogin.data as { user: { id: string } }).user.id !== userId) throw new Error('smoke: pw login mismatch')

// 5. 登出 → 旧 token 失效
await json(
  await app.request('/api/auth/logout', {
    method: 'POST',
    headers: { authorization: `Bearer ${access}`, 'content-type': 'application/json' },
    body: JSON.stringify({}),
  }),
)
const dead = await app.request('/api/me', { headers: { authorization: `Bearer ${access}` } })
if (dead.status !== 401) throw new Error(`smoke: expected 401 after logout, got ${dead.status}`)

console.log('SMOKE_OK: send-code → sms login → me → set/verify password → logout → token dead')
