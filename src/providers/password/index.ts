import type { PasswordManager } from '../../core/engine'
import { AuthError } from '../../core/errors'
import { tryNormalizeEmail, tryNormalizePhone } from '../../core/normalize'
// 账密登录 provider(local):account 解析顺序 E.164 手机号 → 邮箱 → username 身份(需显式开启)。
// 密码哈希走 PasswordHasher 接口;AutoHasher 新哈希一律 Argon2id,verify 按前缀分发
// argon2/bcrypt —— 存量 bcrypt 库(rensheji)免迁移直接接入。
import type { AuthProvider, AuthStore, IdentityClaim, RequestContext } from '../../core/types'

export interface PasswordHasher {
  hash(plain: string): Promise<string>
  verify(hash: string, plain: string): Promise<boolean>
}

/**
 * 运行时自适应哈希:Bun 用内置 Bun.password(原生支持 argon2id 与 bcrypt 验证),
 * Node 回退 @node-rs/argon2(optional peer;bcrypt 存量在 Node 下需要 bcryptjs 类库,自行注入替代实现)。
 */
export class AutoHasher implements PasswordHasher {
  async hash(plain: string): Promise<string> {
    const bunPw = (globalThis as { Bun?: { password: BunPassword } }).Bun?.password
    if (bunPw) return bunPw.hash(plain, { algorithm: 'argon2id', memoryCost: 65536, timeCost: 3 })
    const argon2 = await importArgon2()
    return argon2.hash(plain, { memoryCost: 65536, timeCost: 3, parallelism: 1 })
  }

  async verify(hash: string, plain: string): Promise<boolean> {
    try {
      const bunPw = (globalThis as { Bun?: { password: BunPassword } }).Bun?.password
      if (bunPw) return await bunPw.verify(plain, hash)
      const argon2 = await importArgon2()
      return await argon2.verify(hash, plain)
    } catch {
      return false
    }
  }
}

interface BunPassword {
  hash(plain: string, opts: { algorithm: 'argon2id'; memoryCost: number; timeCost: number }): Promise<string>
  verify(plain: string, hash: string): Promise<boolean>
}

async function importArgon2(): Promise<{
  hash(p: string, o: object): Promise<string>
  verify(h: string, p: string): Promise<boolean>
}> {
  try {
    const name = '@node-rs/argon2'
    return await import(name)
  } catch {
    throw new AuthError('provider_not_configured', {
      platform: 'password',
      reason: 'install @node-rs/argon2 or run on Bun',
    })
  }
}

export interface PasswordCredential {
  account: string
  password: string
}

export interface PasswordProviderOptions {
  store: Pick<AuthStore, 'findUserByContact' | 'findIdentity' | 'getPasswordHash' | 'findUserById'>
  hasher?: PasswordHasher
  /** 允许 username 作为 account(人设机存量);新项目建议保持关闭 */
  allowUsername?: boolean
}

export class PasswordProvider implements AuthProvider<PasswordCredential>, PasswordManager {
  readonly platform = 'password'
  readonly appId = ''
  readonly identityKind = 'local' as const
  private readonly store: PasswordProviderOptions['store']
  private readonly hasher: PasswordHasher
  private readonly allowUsername: boolean

  constructor(opts: PasswordProviderOptions) {
    this.store = opts.store
    this.hasher = opts.hasher ?? new AutoHasher()
    this.allowUsername = opts.allowUsername ?? false
  }

  lockKeyOf(credential: PasswordCredential): string | null {
    return credential?.account ? credential.account.trim().toLowerCase() : null
  }

  async hashPassword(plain: string): Promise<string> {
    if (typeof plain !== 'string' || plain.length < 6) {
      throw new AuthError('credential_invalid', { reason: 'password_too_short' })
    }
    return this.hasher.hash(plain)
  }

  async verify(credential: PasswordCredential, _ctx: RequestContext): Promise<IdentityClaim> {
    const { account, password } = credential ?? {}
    if (!account || !password) throw new AuthError('credential_invalid')

    const phone = tryNormalizePhone(account)
    const email = phone ? null : tryNormalizeEmail(account)
    let user = phone
      ? await this.store.findUserByContact('phone', phone)
      : email
        ? await this.store.findUserByContact('email', email)
        : null
    if (!user && !phone && !email && this.allowUsername) {
      const identity = await this.store.findIdentity('username', '', account.trim())
      if (identity) user = await this.store.findUserById(identity.userId)
    }

    const hash = user ? await this.store.getPasswordHash(user.id) : null
    const ok = hash ? await this.hasher.verify(hash, password) : false
    if (!user || !ok) throw new AuthError('credential_invalid')

    return {
      platform: this.platform,
      appId: '',
      openId: phone ?? email ?? account.trim(),
      userId: user.id,
      ...(phone ? { phone } : {}),
      ...(email ? { email } : {}),
    }
  }
}
