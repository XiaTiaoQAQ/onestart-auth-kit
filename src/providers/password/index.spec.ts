import { describe, expect, test } from 'bun:test'
import { InMemoryAuthStore } from '../../core/memory-store'
import { AutoHasher, PasswordProvider } from './index'

describe('AutoHasher', () => {
  test('新哈希为 argon2id,roundtrip 验证通过', async () => {
    const h = new AutoHasher()
    const hash = await h.hash('hello-world')
    expect(hash.startsWith('$argon2id$')).toBe(true)
    expect(await h.verify(hash, 'hello-world')).toBe(true)
    expect(await h.verify(hash, 'wrong')).toBe(false)
  })

  test('bcrypt 存量哈希(rensheji)按前缀分发验证通过', async () => {
    // 模拟 rensheji 现网:Bun.password bcrypt cost=10 产出的存量哈希
    const legacy = await Bun.password.hash('old-pass-123', { algorithm: 'bcrypt', cost: 10 })
    expect(legacy.startsWith('$2')).toBe(true)
    const h = new AutoHasher()
    expect(await h.verify(legacy, 'old-pass-123')).toBe(true)
    expect(await h.verify(legacy, 'nope')).toBe(false)
  })
})

describe('PasswordProvider account 解析', () => {
  async function setup() {
    const store = new InMemoryAuthStore()
    const hasher = new AutoHasher()
    const provider = new PasswordProvider({ store, hasher, allowUsername: true })
    const hash = await hasher.hash('pw123456')
    const { user: phoneUser } = await store.createUserWithIdentity(
      { phone: '+8613800138000', passwordHash: hash },
      null,
    )
    const { user: emailUser } = await store.createUserWithIdentity(
      { email: 'a@b.com', passwordHash: hash },
      null,
    )
    const { user: nameUser } = await store.createUserWithIdentity(
      { passwordHash: hash },
      {
        platform: 'username',
        appId: '',
        openId: 'alice',
        unionId: null,
      },
    )
    return { provider, phoneUser, emailUser, nameUser }
  }

  test('E.164/裸手机号 → phone 用户;邮箱 → email 用户;username → identity 用户', async () => {
    const { provider, phoneUser, emailUser, nameUser } = await setup()
    expect((await provider.verify({ account: '13800138000', password: 'pw123456' }, {})).userId).toBe(
      phoneUser.id,
    )
    expect((await provider.verify({ account: 'A@B.com', password: 'pw123456' }, {})).userId).toBe(
      emailUser.id,
    )
    expect((await provider.verify({ account: 'alice', password: 'pw123456' }, {})).userId).toBe(nameUser.id)
  })

  test('错密码 / 不存在账号统一 credential_invalid(不泄露账号存在性)', async () => {
    const { provider } = await setup()
    expect(provider.verify({ account: '13800138000', password: 'wrong!' }, {})).rejects.toMatchObject({
      kind: 'credential_invalid',
    })
    expect(provider.verify({ account: 'ghost', password: 'pw123456' }, {})).rejects.toMatchObject({
      kind: 'credential_invalid',
    })
  })

  test('allowUsername=false 时 username 不可登录', async () => {
    const store = new InMemoryAuthStore()
    const hasher = new AutoHasher()
    await store.createUserWithIdentity(
      { passwordHash: await hasher.hash('pw123456') },
      {
        platform: 'username',
        appId: '',
        openId: 'alice',
        unionId: null,
      },
    )
    const provider = new PasswordProvider({ store, hasher })
    expect(provider.verify({ account: 'alice', password: 'pw123456' }, {})).rejects.toMatchObject({
      kind: 'credential_invalid',
    })
  })
})
