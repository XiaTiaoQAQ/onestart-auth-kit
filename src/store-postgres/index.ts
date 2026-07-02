// AuthStore 默认实现:SqlExecutor 注入解耦驱动(与 onestart-ai-kit PostgresSink 同模式)。
//   - postgres 库:new PostgresAuthStore((t, p) => sql.unsafe(t, p))
//   - pg 库:     new PostgresAuthStore((t, p) => pool.query(t, p).then(r => r.rows))
// 原子性:createUserWithIdentity 缺省用单条 CTE 语句(天然原子);注入 withTransaction 后
// 改走显式事务,并支持 onCreateInTx 在同事务内初始化业务扩展表。
import type {
  AuthStore,
  AuthUser,
  CodeScene,
  CodeStore,
  Identity,
  NewIdentity,
  PlatformId,
  SessionStore,
  UserStatus,
} from '../core/types'
import { assertPrefix, getSchemaSql } from './schema'

export type SqlExecutor = (text: string, params: unknown[]) => Promise<unknown>

export interface PostgresAuthStoreOptions {
  /** 表前缀,缺省 auth_ */
  prefix?: string
  /** 首次访问前幂等建表;生产建议 false 并用 getSchemaSql() 走迁移。缺省 true */
  ensureSchema?: boolean
  /**
   * 事务执行器(池化驱动的多语句事务必须由驱动侧提供):
   *   postgres 库:(fn) => sql.begin((tx) => fn((t, p) => tx.unsafe(t, p)))
   * 提供后 createUserWithIdentity 走显式事务,onCreateInTx 才可用。
   */
  withTransaction?: <T>(fn: (sql: SqlExecutor) => Promise<T>) => Promise<T>
  /** 建号同事务回调:初始化业务扩展表(user_profile 等)。需要 withTransaction */
  onCreateInTx?: (sql: SqlExecutor, userId: string) => Promise<void>
}

interface UserRow {
  id: string | number
  status: UserStatus
  token_version: number
  phone: string | null
  email: string | null
  password_hash: string | null
  created_at: string | Date
}

interface IdentityRow {
  id: string | number
  user_id: string | number
  platform: string
  app_id: string
  open_id: string
  union_id: string | null
  created_at: string | Date
}

function isUniqueViolation(err: unknown): boolean {
  // postgres.js / pg 把 SQLSTATE 放 code,Bun SQL 放 errno
  const e = err as { code?: string; errno?: string | number }
  return e?.code === '23505' || String(e?.errno) === '23505'
}

function asRows<T>(result: unknown): T[] {
  if (Array.isArray(result)) return result as T[]
  const rows = (result as { rows?: unknown })?.rows
  if (Array.isArray(rows)) return rows as T[]
  return []
}

function toDate(v: string | Date): Date {
  return v instanceof Date ? v : new Date(v)
}

export class PostgresAuthStore implements AuthStore {
  readonly sessions: SessionStore
  readonly codes: CodeStore
  private readonly p: string
  private readonly ensure: boolean
  private ensured: Promise<void> | null = null
  private readonly withTx: PostgresAuthStoreOptions['withTransaction'] | null
  private readonly onCreateInTx: PostgresAuthStoreOptions['onCreateInTx'] | null

  constructor(
    private readonly sql: SqlExecutor,
    opts: PostgresAuthStoreOptions = {},
  ) {
    this.p = opts.prefix ?? 'auth_'
    assertPrefix(this.p)
    this.ensure = opts.ensureSchema ?? true
    this.withTx = opts.withTransaction ?? null
    this.onCreateInTx = opts.onCreateInTx ?? null
    if (this.onCreateInTx && !this.withTx) {
      throw new Error('PostgresAuthStore: onCreateInTx requires withTransaction')
    }
    this.sessions = new PostgresSessionStore(this)
    this.codes = new PostgresCodeStore(this)
  }

  /** 建表失败(DB 未就绪/闪断)不缓存 rejected promise,否则 store 余生不可用 */
  async ready(): Promise<void> {
    if (!this.ensure) return
    this.ensured ??= this.runSchema().catch((err) => {
      this.ensured = null
      throw err
    })
    await this.ensured
  }

  private async runSchema(): Promise<void> {
    for (const stmt of getSchemaSql({ prefix: this.p })
      .split(';')
      .map((s) => s.trim())
      .filter(Boolean)) {
      await this.sql(stmt, [])
    }
  }

  async query<T>(text: string, params: unknown[]): Promise<T[]> {
    await this.ready()
    return asRows<T>(await this.sql(text, params))
  }

  get prefix(): string {
    return this.p
  }

  private toUser(r: UserRow): AuthUser {
    return {
      id: String(r.id),
      status: r.status,
      tokenVersion: Number(r.token_version),
      phone: r.phone,
      email: r.email,
      hasPassword: r.password_hash !== null,
      createdAt: toDate(r.created_at),
    }
  }

  private toIdentity(r: IdentityRow): Identity {
    return {
      id: String(r.id),
      userId: String(r.user_id),
      platform: r.platform,
      appId: r.app_id,
      openId: r.open_id,
      unionId: r.union_id,
      createdAt: toDate(r.created_at),
    }
  }

  private static readonly USER_COLS = 'id, status, token_version, phone, email, password_hash, created_at'
  private static readonly IDENTITY_COLS = 'id, user_id, platform, app_id, open_id, union_id, created_at'

  async findUserById(id: string): Promise<AuthUser | null> {
    const rows = await this.query<UserRow>(
      `SELECT ${PostgresAuthStore.USER_COLS} FROM ${this.p}users WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
      [id],
    )
    return rows[0] ? this.toUser(rows[0]) : null
  }

  async findUserByContact(kind: 'phone' | 'email', value: string): Promise<AuthUser | null> {
    if (kind !== 'phone' && kind !== 'email') throw new Error(`bad contact kind: ${kind}`)
    const rows = await this.query<UserRow>(
      `SELECT ${PostgresAuthStore.USER_COLS} FROM ${this.p}users WHERE ${kind} = $1 AND deleted_at IS NULL LIMIT 1`,
      [value],
    )
    return rows[0] ? this.toUser(rows[0]) : null
  }

  async findIdentity(platform: PlatformId, appId: string, openId: string): Promise<Identity | null> {
    const rows = await this.query<IdentityRow>(
      `SELECT ${PostgresAuthStore.IDENTITY_COLS} FROM ${this.p}identities
       WHERE platform = $1 AND app_id = $2 AND open_id = $3 AND deleted_at IS NULL LIMIT 1`,
      [platform, appId, openId],
    )
    return rows[0] ? this.toIdentity(rows[0]) : null
  }

  async findIdentityByUnionId(platforms: PlatformId[], unionId: string): Promise<Identity | null> {
    if (platforms.length === 0) return null
    // 动态占位符而非 = ANY($1):数组参数的序列化各驱动不一致(Bun SQL 不支持)
    const ph = platforms.map((_, i) => `$${i + 2}`).join(', ')
    const rows = await this.query<IdentityRow>(
      `SELECT ${PostgresAuthStore.IDENTITY_COLS} FROM ${this.p}identities
       WHERE union_id = $1 AND platform IN (${ph}) AND deleted_at IS NULL
       ORDER BY id LIMIT 1`,
      [unionId, ...platforms],
    )
    return rows[0] ? this.toIdentity(rows[0]) : null
  }

  async listIdentities(userId: string): Promise<Identity[]> {
    const rows = await this.query<IdentityRow>(
      `SELECT ${PostgresAuthStore.IDENTITY_COLS} FROM ${this.p}identities
       WHERE user_id = $1 AND deleted_at IS NULL ORDER BY id`,
      [userId],
    )
    return rows.map((r) => this.toIdentity(r))
  }

  async createUserWithIdentity(
    user: { phone?: string | null; email?: string | null; passwordHash?: string | null },
    identity: NewIdentity | null,
  ): Promise<{ user: AuthUser; created: boolean }> {
    await this.ready()
    try {
      if (this.withTx) {
        const created = await this.withTx(async (tx) => {
          const rows = asRows<UserRow>(
            await tx(
              `INSERT INTO ${this.p}users (phone, email, password_hash) VALUES ($1, $2, $3)
               RETURNING ${PostgresAuthStore.USER_COLS}`,
              [user.phone ?? null, user.email ?? null, user.passwordHash ?? null],
            ),
          )
          const u = rows[0]
          if (!u) throw new Error('insert user returned no row')
          if (identity) {
            await tx(
              `INSERT INTO ${this.p}identities (user_id, platform, app_id, open_id, union_id, profile)
               VALUES ($1, $2, $3, $4, $5, $6)`,
              [
                u.id,
                identity.platform,
                identity.appId,
                identity.openId,
                identity.unionId ?? null,
                identity.profile ? JSON.stringify(identity.profile) : null,
              ],
            )
          }
          await this.onCreateInTx?.(tx, String(u.id))
          return u
        })
        return { user: this.toUser(created), created: true }
      }
      // 无事务执行器:单条 CTE 语句,INSERT 用户 + 身份天然原子
      const rows = asRows<UserRow>(
        await this.sql(
          `WITH new_user AS (
             INSERT INTO ${this.p}users (phone, email, password_hash) VALUES ($1, $2, $3)
             RETURNING ${PostgresAuthStore.USER_COLS}
           ), new_identity AS (
             INSERT INTO ${this.p}identities (user_id, platform, app_id, open_id, union_id, profile)
             SELECT id, $4, $5, $6, $7, $8 FROM new_user WHERE $4::text IS NOT NULL
           )
           SELECT * FROM new_user`,
          [
            user.phone ?? null,
            user.email ?? null,
            user.passwordHash ?? null,
            identity?.platform ?? null,
            identity?.appId ?? '',
            identity?.openId ?? '',
            identity?.unionId ?? null,
            identity?.profile ? JSON.stringify(identity.profile) : null,
          ],
        ),
      )
      const u = rows[0]
      if (!u) throw new Error('insert user returned no row')
      return { user: this.toUser(u), created: true }
    } catch (err) {
      if (!isUniqueViolation(err)) throw err
      // 并发兜底契约:唯一冲突 → 重读既有身份/联系方式,返回既有用户
      if (identity) {
        const existing = await this.findIdentity(identity.platform, identity.appId, identity.openId)
        if (existing) {
          const owner = await this.findUserById(existing.userId)
          if (owner) return { user: owner, created: false }
        }
      }
      for (const kind of ['phone', 'email'] as const) {
        const value = user[kind]
        if (value) {
          const owner = await this.findUserByContact(kind, value)
          if (owner) return { user: owner, created: false }
        }
      }
      throw err
    }
  }

  async bindIdentity(userId: string, identity: NewIdentity): Promise<Identity> {
    const rows = await this.query<IdentityRow>(
      `INSERT INTO ${this.p}identities (user_id, platform, app_id, open_id, union_id, profile)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING ${PostgresAuthStore.IDENTITY_COLS}`,
      [
        userId,
        identity.platform,
        identity.appId,
        identity.openId,
        identity.unionId ?? null,
        identity.profile ? JSON.stringify(identity.profile) : null,
      ],
    )
    const row = rows[0]
    if (!row) throw new Error('insert identity returned no row')
    return this.toIdentity(row)
  }

  async unbindIdentity(identityId: string): Promise<void> {
    await this.query(
      `UPDATE ${this.p}identities SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`,
      [identityId],
    )
  }

  async setIdentityUnionId(identityId: string, unionId: string): Promise<void> {
    await this.query(`UPDATE ${this.p}identities SET union_id = $2 WHERE id = $1 AND union_id IS NULL`, [
      identityId,
      unionId,
    ])
  }

  async reassignIdentities(fromUserId: string, toUserId: string): Promise<void> {
    await this.query(
      `UPDATE ${this.p}identities SET user_id = $2 WHERE user_id = $1 AND deleted_at IS NULL`,
      [fromUserId, toUserId],
    )
  }

  async updateContact(userId: string, kind: 'phone' | 'email', value: string | null): Promise<void> {
    if (kind !== 'phone' && kind !== 'email') throw new Error(`bad contact kind: ${kind}`)
    await this.query(`UPDATE ${this.p}users SET ${kind} = $2, updated_at = now() WHERE id = $1`, [
      userId,
      value,
    ])
  }

  async getPasswordHash(userId: string): Promise<string | null> {
    const rows = await this.query<{ password_hash: string | null }>(
      `SELECT password_hash FROM ${this.p}users WHERE id = $1 AND deleted_at IS NULL LIMIT 1`,
      [userId],
    )
    return rows[0]?.password_hash ?? null
  }

  async setPasswordHash(userId: string, hash: string | null): Promise<void> {
    await this.query(`UPDATE ${this.p}users SET password_hash = $2, updated_at = now() WHERE id = $1`, [
      userId,
      hash,
    ])
  }

  async setStatus(userId: string, status: UserStatus): Promise<void> {
    await this.query(`UPDATE ${this.p}users SET status = $2, updated_at = now() WHERE id = $1`, [
      userId,
      status,
    ])
  }

  async bumpTokenVersion(userId: string): Promise<number> {
    const rows = await this.query<{ token_version: number }>(
      `UPDATE ${this.p}users SET token_version = token_version + 1, updated_at = now()
       WHERE id = $1 RETURNING token_version`,
      [userId],
    )
    return Number(rows[0]?.token_version ?? 0)
  }

  async markLogin(userId: string, at: Date): Promise<void> {
    await this.query(`UPDATE ${this.p}users SET last_login_at = $2 WHERE id = $1`, [userId, at])
  }

  async softDeleteUser(userId: string): Promise<void> {
    await this.query(`UPDATE ${this.p}users SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, [
      userId,
    ])
  }
}

class PostgresSessionStore implements SessionStore {
  constructor(private readonly store: PostgresAuthStore) {}

  async insert(s: {
    userId: string
    key: string
    client: string
    ip?: string
    userAgent?: string
    expiresAt: Date
  }): Promise<void> {
    await this.store.query(
      `INSERT INTO ${this.store.prefix}sessions (user_id, key, client, ip, user_agent, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [s.userId, s.key, s.client, s.ip ?? null, s.userAgent ?? null, s.expiresAt],
    )
  }

  async find(key: string): Promise<{ userId: string; expiresAt: Date; revokedAt: Date | null } | null> {
    const rows = await this.store.query<{
      user_id: string | number
      expires_at: string | Date
      revoked_at: string | Date | null
    }>(`SELECT user_id, expires_at, revoked_at FROM ${this.store.prefix}sessions WHERE key = $1 LIMIT 1`, [
      key,
    ])
    const r = rows[0]
    if (!r) return null
    return {
      userId: String(r.user_id),
      expiresAt: r.expires_at instanceof Date ? r.expires_at : new Date(r.expires_at),
      revokedAt: r.revoked_at ? (r.revoked_at instanceof Date ? r.revoked_at : new Date(r.revoked_at)) : null,
    }
  }

  async revoke(key: string): Promise<void> {
    await this.store.query(
      `UPDATE ${this.store.prefix}sessions SET revoked_at = now() WHERE key = $1 AND revoked_at IS NULL`,
      [key],
    )
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.store.query(
      `UPDATE ${this.store.prefix}sessions SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
      [userId],
    )
  }
}

class PostgresCodeStore implements CodeStore {
  constructor(private readonly store: PostgresAuthStore) {}

  async save(target: string, scene: CodeScene, code: string, ttlSec: number): Promise<void> {
    await this.store.query(
      `INSERT INTO ${this.store.prefix}codes (target, scene, code, expires_at, sent_at, consumed)
       VALUES ($1, $2, $3, now() + ($4 || ' seconds')::interval, now(), FALSE)
       ON CONFLICT (target, scene) DO UPDATE
         SET code = EXCLUDED.code, expires_at = EXCLUDED.expires_at, sent_at = now(), consumed = FALSE`,
      [target, scene, code, String(ttlSec)],
    )
  }

  async consume(target: string, scene: CodeScene, code: string): Promise<boolean> {
    const rows = await this.store.query<{ target: string }>(
      `UPDATE ${this.store.prefix}codes SET consumed = TRUE
       WHERE target = $1 AND scene = $2 AND code = $3 AND consumed = FALSE AND expires_at > now()
       RETURNING target`,
      [target, scene, code],
    )
    return rows.length > 0
  }
}

export { getSchemaSql } from './schema'
