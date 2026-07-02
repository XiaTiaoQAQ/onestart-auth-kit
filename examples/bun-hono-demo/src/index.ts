import {
  AuthKit,
  InMemoryAuthStore,
  MemoryCodeStore,
  MemorySessionStore,
  OpaqueTokenStrategy,
} from '@1start/auth-kit'
import { authMiddleware, createAuthRoutes } from '@1start/auth-kit/hono'
import { PasswordProvider } from '@1start/auth-kit/providers/password'
import { SmsProvider, StubSmsChannel } from '@1start/auth-kit/providers/sms'
// 端到端样例:默认组件组装(DESIGN §6.1)。内存 store 起步,换 PostgresAuthStore 即上生产形态。
// 起服:bun run dev;全流程冒烟:bun run smoke(见 smoke.ts)。
import { Hono } from 'hono'

export function buildApp() {
  const store = new InMemoryAuthStore()
  const sessions = new MemorySessionStore()
  const smsChannel = new StubSmsChannel()

  const kit = new AuthKit({
    store,
    tokens: new OpaqueTokenStrategy({ sessions, ttlSec: 7 * 86400 }),
    providers: [
      new SmsProvider({ channel: smsChannel, codes: new MemoryCodeStore() }),
      new PasswordProvider({ store }),
    ],
    hooks: {
      onUserCreated: async (user) => console.log(`[demo] user created: ${user.id}`),
    },
  })

  const app = new Hono()
  app.route('/api/auth', createAuthRoutes(kit))
  app.get('/api/me', authMiddleware(kit), (c) => {
    const { user } = c.get('auth')
    return c.json({ data: { id: user.id, phone: user.phone, email: user.email } })
  })
  return { app, kit, smsChannel }
}

if (import.meta.main) {
  const { app } = buildApp()
  console.log('demo listening on http://localhost:3210')
  Bun.serve({ port: 3210, fetch: app.fetch })
}
