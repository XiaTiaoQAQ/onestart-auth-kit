import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
// PG 集成测试:走 Bun 内置 SQL 客户端注入 SqlExecutor(零额外依赖)。
// 需要本地 PostgreSQL 与 authkit_test 库;连不上时整组跳过(CI 无 PG 不红)。
import { SQL } from 'bun'
import { PostgresAuthStore, type SqlExecutor } from './index'

const PG_URL = process.env.PG_TEST_URL ?? 'postgres://localhost:5432/authkit_test'
const PREFIX = 'akt_'

let sql: SQL | null = null
try {
  const probe = new SQL(PG_URL)
  await probe.unsafe('SELECT 1')
  sql = probe
} catch {
  console.warn(`[store-postgres.spec] 跳过:无法连接 ${PG_URL}`)
}

describe.skipIf(!sql)('PostgresAuthStore(真 PG)', () => {
  const exec: SqlExecutor = (t, p) => (sql as SQL).unsafe(t, p)
  let store: PostgresAuthStore

  beforeAll(async () => {
    for (const t of ['codes', 'sessions', 'identities', 'users']) {
      await (sql as SQL).unsafe(`DROP TABLE IF EXISTS ${PREFIX}${t} CASCADE`)
    }
  })

  beforeEach(async () => {
    store = new PostgresAuthStore(exec, { prefix: PREFIX })
    await store.ready()
    for (const t of ['codes', 'sessions', 'identities', 'users']) {
      await (sql as SQL).unsafe(`TRUNCATE ${PREFIX}${t} RESTART IDENTITY CASCADE`)
    }
  })

  afterAll(async () => {
    await sql?.end()
  })

  test('建号 + 身份直中 + 联系方式唯一索引', async () => {
    const { user, created } = await store.createUserWithIdentity(
      { phone: '+8613800138000' },
      { platform: 'wechat_mini', appId: 'wx1', openId: 'o1', unionId: 'u1' },
    )
    expect(created).toBe(true)
    expect((await store.findIdentity('wechat_mini', 'wx1', 'o1'))?.userId).toBe(user.id)
    expect((await store.findUserByContact('phone', '+8613800138000'))?.id).toBe(user.id)
    expect((await store.findIdentityByUnionId(['wechat_mini', 'wechat_open'], 'u1'))?.userId).toBe(user.id)
  })

  test('并发兜底:100 并发同 openid 只建 1 个用户,0 孤儿身份', async () => {
    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        store.createUserWithIdentity(
          {},
          { platform: 'wechat_mini', appId: 'wx1', openId: 'race', unionId: null },
        ),
      ),
    )
    const ids = new Set(results.map((r) => r.user.id))
    expect(ids.size).toBe(1)
    expect(results.filter((r) => r.created)).toHaveLength(1)
    const users = (await store.query<{ n: string }>(`SELECT count(*) n FROM ${PREFIX}users`, []))[0]
    const idents = (await store.query<{ n: string }>(`SELECT count(*) n FROM ${PREFIX}identities`, []))[0]
    expect(Number(users?.n)).toBe(1)
    expect(Number(idents?.n)).toBe(1)
  })

  test('并发兜底:同手机号并发自动注册只建 1 个用户', async () => {
    const results = await Promise.all(
      Array.from({ length: 50 }, () => store.createUserWithIdentity({ phone: '+8613900139000' }, null)),
    )
    expect(new Set(results.map((r) => r.user.id)).size).toBe(1)
  })

  test('withTransaction + onCreateInTx:业务扩展表同事务初始化', async () => {
    await (sql as SQL).unsafe(
      `CREATE TABLE IF NOT EXISTS ${PREFIX}profile (user_id BIGINT PRIMARY KEY, nick TEXT)`,
    )
    await (sql as SQL).unsafe(`TRUNCATE ${PREFIX}profile`)
    const txStore = new PostgresAuthStore(exec, {
      prefix: PREFIX,
      withTransaction: (fn) => (sql as SQL).begin((tx) => fn((t, p) => tx.unsafe(t, p))),
      onCreateInTx: async (txSql, userId) => {
        await txSql(`INSERT INTO ${PREFIX}profile (user_id, nick) VALUES ($1, $2)`, [userId, 'newbie'])
      },
    })
    const { user } = await txStore.createUserWithIdentity(
      {},
      {
        platform: 'wechat_mini',
        appId: 'wx1',
        openId: 'tx-1',
        unionId: null,
      },
    )
    const rows = await txStore.query<{ nick: string }>(
      `SELECT nick FROM ${PREFIX}profile WHERE user_id = $1`,
      [user.id],
    )
    expect(rows[0]?.nick).toBe('newbie')
  })

  test('软删/解绑/回填/改挂身份', async () => {
    const { user: a } = await store.createUserWithIdentity(
      {},
      {
        platform: 'wechat_mini',
        appId: 'wx1',
        openId: 'a1',
        unionId: null,
      },
    )
    const { user: b } = await store.createUserWithIdentity(
      {},
      {
        platform: 'douyin_mini',
        appId: 'tt1',
        openId: 'b1',
        unionId: null,
      },
    )
    const identity = await store.findIdentity('wechat_mini', 'wx1', 'a1')
    if (!identity) throw new Error('identity missing')
    await store.setIdentityUnionId(identity.id, 'u-fill')
    expect((await store.findIdentity('wechat_mini', 'wx1', 'a1'))?.unionId).toBe('u-fill')

    await store.reassignIdentities(a.id, b.id)
    expect((await store.listIdentities(b.id)).length).toBe(2)
    await store.softDeleteUser(a.id)
    expect(await store.findUserById(a.id)).toBeNull()

    await store.unbindIdentity(identity.id)
    expect(await store.findIdentity('wechat_mini', 'wx1', 'a1')).toBeNull()
    // 解绑后同 openid 可重新绑定(部分唯一索引只约束未删行)
    await store.bindIdentity(b.id, { platform: 'wechat_mini', appId: 'wx1', openId: 'a1', unionId: null })
  })

  test('sessions:插入/查找/吊销/按用户吊销', async () => {
    const { user } = await store.createUserWithIdentity({}, null)
    await store.sessions.insert({
      userId: user.id,
      key: 'k1',
      client: 'test',
      expiresAt: new Date(Date.now() + 60000),
    })
    await store.sessions.insert({
      userId: user.id,
      key: 'k2',
      client: 'test',
      expiresAt: new Date(Date.now() + 60000),
    })
    expect((await store.sessions.find('k1'))?.userId).toBe(user.id)
    await store.sessions.revoke('k1')
    expect((await store.sessions.find('k1'))?.revokedAt).not.toBeNull()
    await store.sessions.revokeAllForUser(user.id)
    expect((await store.sessions.find('k2'))?.revokedAt).not.toBeNull()
  })

  test('codes:UPSERT 覆盖旧码,原子消费一次性', async () => {
    await store.codes.save('+8613800138000', 'login', '111111', 300)
    await store.codes.save('+8613800138000', 'login', '222222', 300)
    expect(await store.codes.consume('+8613800138000', 'login', '111111')).toBe(false)
    expect(await store.codes.consume('+8613800138000', 'login', '222222')).toBe(true)
    expect(await store.codes.consume('+8613800138000', 'login', '222222')).toBe(false)
  })

  test('bumpTokenVersion / setStatus / password hash 读写', async () => {
    const { user } = await store.createUserWithIdentity({}, null)
    expect(await store.bumpTokenVersion(user.id)).toBe(2)
    await store.setStatus(user.id, 'blocked')
    expect((await store.findUserById(user.id))?.status).toBe('blocked')
    await store.setPasswordHash(user.id, '$argon2id$fake')
    expect(await store.getPasswordHash(user.id)).toBe('$argon2id$fake')
    expect((await store.findUserById(user.id))?.hasPassword).toBe(true)
  })
})
