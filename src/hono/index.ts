// 可选薄层:Hono 中间件 + 标准路由工厂。业务可完全不用它,直接调 AuthKit。
import type { Context, MiddlewareHandler } from 'hono'
import { Hono } from 'hono'
import type { AuthKit } from '../core/engine'
import { AuthError, type AuthErrorKind } from '../core/errors'
import type { CodeScene, RequestContext, VerifyResult } from '../core/types'

/** AuthError → HTTP 状态码。业务想要别的映射,替换此表或自行 catch。 */
export const AUTH_HTTP_STATUS: Record<AuthErrorKind, number> = {
  credential_invalid: 401,
  code_invalid: 401,
  code_rate_limited: 429,
  provider_not_configured: 501,
  provider_upstream: 502,
  account_locked: 423,
  user_blocked: 403,
  token_invalid: 401,
  token_expired: 401,
  token_revoked: 401,
  identity_taken: 409,
  contact_taken: 409,
  identity_not_found: 404,
  last_identity: 409,
  user_not_found: 404,
  password_required: 400,
}

export function ctxFrom(c: Context): RequestContext {
  const ip = c.req.header('x-forwarded-for')?.split(',')[0]?.trim() ?? c.req.header('x-real-ip') ?? undefined
  const userAgent = c.req.header('user-agent')
  const locale = c.req.header('accept-language')?.split(',')[0]?.trim()
  return {
    ...(ip ? { ip } : {}),
    ...(userAgent ? { userAgent } : {}),
    ...(locale ? { locale } : {}),
  }
}

export function extractBearer(c: Context): string | null {
  const h = c.req.header('authorization')
  if (!h) return null
  const m = /^Bearer\s+(.+)$/i.exec(h)
  return m?.[1] ?? null
}

declare module 'hono' {
  interface ContextVariableMap {
    auth: VerifyResult
  }
}

/**
 * Bearer 鉴权中间件:校验通过后 c.set('auth', { user, claims, jti })。
 * AuthError 统一按 AUTH_HTTP_STATUS 返回 { error: kind, detail }。
 */
export function authMiddleware(kit: AuthKit): MiddlewareHandler {
  return async (c, next) => {
    const token = extractBearer(c)
    if (!token) return c.json({ error: 'token_invalid' as const }, 401)
    try {
      c.set('auth', await kit.verify(token))
    } catch (err) {
      if (err instanceof AuthError) {
        return c.json({ error: err.kind, detail: err.detail }, AUTH_HTTP_STATUS[err.kind] as 401)
      }
      throw err
    }
    await next()
  }
}

/**
 * 标准路由(可选):POST /login/:platform、/code/send、/refresh、/logout、/bind/:platform、/password/reset。
 * 响应形态 { data } / { error, detail },业务要自有契约就别挂这个,自己写路由调 kit。
 */
export function createAuthRoutes(kit: AuthKit): Hono {
  const r = new Hono()

  r.onError((err, c) => {
    if (err instanceof AuthError) {
      return c.json({ error: err.kind, detail: err.detail }, AUTH_HTTP_STATUS[err.kind] as 401)
    }
    throw err
  })

  r.post('/login/:platform', async (c) => {
    const body = await c.req.json<Record<string, unknown>>().catch(() => ({}))
    const result = await kit.login(c.req.param('platform'), body, ctxFrom(c))
    return c.json({
      data: {
        user: { id: result.user.id, phone: result.user.phone, email: result.user.email },
        tokens: result.tokens,
        isNewUser: result.isNewUser,
      },
    })
  })

  r.post('/code/send', async (c) => {
    const body = await c.req
      .json<{ platform?: string; target?: string; scene?: CodeScene }>()
      .catch(() => ({}) as never)
    const { resendAfterSec } = await kit.sendCode(
      body.platform ?? 'sms',
      body.target ?? '',
      body.scene ?? 'login',
      ctxFrom(c),
    )
    return c.json({ data: { resendAfterSec } })
  })

  r.post('/refresh', async (c) => {
    const body = await c.req.json<{ refresh?: string }>().catch(() => ({}) as never)
    if (!body.refresh) return c.json({ error: 'token_invalid' as const }, 401)
    return c.json({ data: { tokens: await kit.refresh(body.refresh, ctxFrom(c)) } })
  })

  r.post('/logout', authMiddleware(kit), async (c) => {
    const body = await c.req.json<{ refresh?: string; allDevices?: boolean }>().catch(() => ({}) as never)
    const access = extractBearer(c)
    await kit.logout({
      ...(access ? { access } : {}),
      ...(body.refresh ? { refresh: body.refresh } : {}),
      ...(body.allDevices ? { allDevices: true, userId: c.get('auth').user.id } : {}),
    })
    return c.json({ data: { ok: true } })
  })

  r.post('/bind/:platform', authMiddleware(kit), async (c) => {
    const body = await c.req.json<Record<string, unknown>>().catch(() => ({}))
    const identity = await kit.bind(c.get('auth').user.id, c.req.param('platform'), body, ctxFrom(c))
    return c.json({ data: { bound: true, identity } })
  })

  r.post('/password/reset', async (c) => {
    const body = await c.req
      .json<{ kind?: 'phone' | 'email'; target?: string; code?: string; newPassword?: string }>()
      .catch(() => ({}) as never)
    if (!body.target || !body.code || !body.newPassword) {
      return c.json({ error: 'credential_invalid' as const }, 400)
    }
    await kit.resetPasswordByCode({
      kind: body.kind ?? 'phone',
      target: body.target,
      code: body.code,
      newPassword: body.newPassword,
    })
    return c.json({ data: { ok: true } })
  })

  return r
}
