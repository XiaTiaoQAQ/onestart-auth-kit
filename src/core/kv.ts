import type { RedisLike } from './types'

/**
 * 带 TTL 的内存 KV,RedisLike 的单进程默认实现。
 * 仅适用于单进程部署 —— 黑名单/锁定不跨进程,多实例必须注入真 Redis。
 */
export class MemoryKv implements RedisLike {
  private readonly data = new Map<string, { value: string; expiresAt: number | null }>()

  private live(key: string): { value: string; expiresAt: number | null } | null {
    const e = this.data.get(key)
    if (!e) return null
    if (e.expiresAt !== null && e.expiresAt <= Date.now()) {
      this.data.delete(key)
      return null
    }
    return e
  }

  async get(key: string): Promise<string | null> {
    return this.live(key)?.value ?? null
  }

  /** 兼容 ioredis 风格:set(key, value, 'EX', seconds) */
  async set(key: string, value: string, ...args: unknown[]): Promise<'OK'> {
    let expiresAt: number | null = null
    const exIdx = args.findIndex((a) => String(a).toUpperCase() === 'EX')
    if (exIdx >= 0) expiresAt = Date.now() + Number(args[exIdx + 1]) * 1000
    this.data.set(key, { value, expiresAt })
    return 'OK'
  }

  async del(key: string): Promise<number> {
    return this.data.delete(key) ? 1 : 0
  }

  async incr(key: string): Promise<number> {
    const cur = this.live(key)
    const next = (cur ? Number(cur.value) : 0) + 1
    this.data.set(key, { value: String(next), expiresAt: cur?.expiresAt ?? null })
    return next
  }

  async expire(key: string, ttlSec: number): Promise<number> {
    const e = this.live(key)
    if (!e) return 0
    e.expiresAt = Date.now() + ttlSec * 1000
    return 1
  }

  async ttl(key: string): Promise<number> {
    const e = this.live(key)
    if (!e) return -2
    if (e.expiresAt === null) return -1
    return Math.ceil((e.expiresAt - Date.now()) / 1000)
  }
}
