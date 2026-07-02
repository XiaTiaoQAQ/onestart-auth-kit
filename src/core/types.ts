// 端口接口的唯一事实源。所有模块(providers / store-postgres / hono)只依赖这里的类型。
// 契约细节见 docs/DESIGN.md §3。

export type PlatformId = string
export const PLATFORMS = {
  wechatMini: 'wechat_mini',
  wechatOpen: 'wechat_open',
  douyinMini: 'douyin_mini',
  alipayMini: 'alipay_mini',
  apple: 'apple',
  qq: 'qq',
  sms: 'sms',
  email: 'email',
  password: 'password',
  username: 'username',
} as const

export interface RequestContext {
  ip?: string
  userAgent?: string
  /** 'h5' | 'mp-weixin' | 'ios' ... 业务自定,透传进会话记录 */
  client?: string
  /** 透传给短信/邮件模板,SDK 不存储 */
  locale?: string
}

export interface IdentityClaim {
  platform: PlatformId
  /** 平台应用维度(微信 openid 按 appid 隔离);无此概念传 '' */
  appId: string
  /** 平台内唯一标识:openid / apple sub / E.164 手机号 / 小写邮箱 */
  openId: string
  /** 跨应用聚合 id(微信/QQ);无则 null */
  unionId?: string | null
  /** provider 验证过的可信手机号(E.164) */
  phone?: string
  /** provider 验证过的可信邮箱(小写) */
  email?: string
  /** provider 已解析出的用户(如 password 验证过程顺带确认),引擎直取跳过身份解析 */
  userId?: string
  profile?: { nickname?: string; avatarUrl?: string; gender?: 0 | 1 | 2; raw?: unknown }
}

export type UserStatus = 'active' | 'locked' | 'blocked'

export interface AuthUser {
  id: string
  status: UserStatus
  tokenVersion: number
  phone: string | null
  email: string | null
  hasPassword: boolean
  createdAt: Date
}

export interface Identity {
  id: string
  userId: string
  platform: PlatformId
  appId: string
  openId: string
  unionId: string | null
  createdAt: Date
}

export type NewIdentity = Pick<Identity, 'platform' | 'appId' | 'openId' | 'unionId'> & {
  profile?: IdentityClaim['profile']
}

// ---------- 端口一:AuthProvider ----------

export interface AuthProvider<TCredential = unknown> {
  readonly platform: PlatformId
  readonly appId: string
  /** federated → 身份走 identity 表三步解析;local → 只走用户表联系方式列 */
  readonly identityKind: 'federated' | 'local'
  /** 返回非空则该 provider 参与登录失败锁定,返回值作为锁维度(如 password 的 account) */
  lockKeyOf?(credential: TCredential): string | null
  /** 校验凭证。失败抛 AuthError(credential_invalid / code_invalid / provider_*) */
  verify(credential: TCredential, ctx: RequestContext): Promise<IdentityClaim>
}

export type CodeScene = 'login' | 'register' | 'bind' | 'reset'

/** 需要"先发码后验证"的 provider(sms / email)额外实现 */
export interface CodeSender {
  sendCode(target: string, scene: CodeScene, ctx: RequestContext): Promise<void>
}

export function isCodeSender(p: unknown): p is CodeSender {
  return typeof (p as CodeSender)?.sendCode === 'function'
}

// ---------- 端口二:AuthStore ----------

export interface AuthStore {
  findUserById(id: string): Promise<AuthUser | null>
  findUserByContact(kind: 'phone' | 'email', value: string): Promise<AuthUser | null>

  findIdentity(platform: PlatformId, appId: string, openId: string): Promise<Identity | null>
  findIdentityByUnionId(platforms: PlatformId[], unionId: string): Promise<Identity | null>
  listIdentities(userId: string): Promise<Identity[]>

  /**
   * 原子:建用户 + 可选首个身份。并发兜底契约:identity 唯一约束冲突时,
   * 实现必须重读既有身份并返回其用户(created: false),不得泄漏驱动异常。
   */
  createUserWithIdentity(
    user: { phone?: string | null; email?: string | null; passwordHash?: string | null },
    identity: NewIdentity | null,
  ): Promise<{ user: AuthUser; created: boolean }>

  bindIdentity(userId: string, identity: NewIdentity): Promise<Identity>
  unbindIdentity(identityId: string): Promise<void>
  /** 机会性回填 unionId(首次绑定时平台未返回、后续登录补上) */
  setIdentityUnionId(identityId: string, unionId: string): Promise<void>
  /** 账号合并原语:把 from 的全部身份改挂到 to。何时合并由业务决定 */
  reassignIdentities(fromUserId: string, toUserId: string): Promise<void>

  updateContact(userId: string, kind: 'phone' | 'email', value: string | null): Promise<void>
  getPasswordHash(userId: string): Promise<string | null>
  setPasswordHash(userId: string, hash: string | null): Promise<void>
  setStatus(userId: string, status: UserStatus): Promise<void>
  bumpTokenVersion(userId: string): Promise<number>
  markLogin(userId: string, at: Date): Promise<void>
  softDeleteUser(userId: string): Promise<void>
}

/** key = JwtSession 策略的 refresh jti,或 Opaque 策略的 token 本身 */
export interface SessionStore {
  insert(s: {
    userId: string
    key: string
    client: string
    ip?: string
    userAgent?: string
    expiresAt: Date
  }): Promise<void>
  find(key: string): Promise<{ userId: string; expiresAt: Date; revokedAt: Date | null } | null>
  revoke(key: string): Promise<void>
  revokeAllForUser(userId: string): Promise<void>
}

export interface CodeStore {
  /** UPSERT:同 (target, scene) 一行,覆盖旧码 */
  save(target: string, scene: CodeScene, code: string, ttlSec: number): Promise<void>
  /** 原子消费:匹配且未过期未消费 → 置 consumed 并返回 true */
  consume(target: string, scene: CodeScene, code: string): Promise<boolean>
}

// ---------- 端口三:TokenStrategy ----------

export interface TokenPair {
  access: string
  refresh?: string
  expiresInSec: number
}

export interface VerifiedAccess {
  userId: string
  /** JwtSession:用于登出拉黑 */
  jti?: string
  /** JwtSession:引擎与 user.tokenVersion 比对;Opaque 无需 */
  tokenVersion?: number
  /** JwtSession:签发时写入的业务 claims 原样带回(如 role) */
  claims?: Record<string, unknown>
}

export interface TokenStrategy {
  issue(user: AuthUser, ctx: RequestContext): Promise<TokenPair>
  /** 失败抛 AuthError(token_invalid / token_expired / token_revoked) */
  verifyAccess(token: string): Promise<VerifiedAccess>
  /**
   * 旋转式刷新。resolveUser 由引擎注入:按 userId 取用户并完成 status/ver 检查,
   * 策略拿返回的 AuthUser 签发新对 —— 策略自身保持无 store 依赖。
   */
  refresh?(
    refreshToken: string,
    ctx: RequestContext,
    resolveUser: (userId: string) => Promise<AuthUser>,
  ): Promise<TokenPair>
  revoke(input: { access?: string; refresh?: string }): Promise<void>
  revokeAllForUser(userId: string): Promise<void>
}

// ---------- 端口四:RedisLike ----------

/** 与 onestart-ai-kit 同构的最小 KV 接口,ioredis 实例直接满足。多实例部署必须注入真 Redis。 */
export interface RedisLike {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>
  del(key: string): Promise<unknown>
  incr(key: string): Promise<number>
  expire(key: string, ttlSec: number): Promise<unknown>
  ttl(key: string): Promise<number>
}

// ---------- 引擎配置 ----------

export interface LoggerLike {
  info(obj: unknown, msg?: string): void
  warn(obj: unknown, msg?: string): void
}

export interface AuthKitHooks {
  /** 事务外异步,失败仅 warn 不阻塞:初始化业务扩展表、发券、通知 */
  onUserCreated?: (user: AuthUser, claim: IdentityClaim | null) => Promise<void>
  /** 审计挂点:每次成功登录 */
  onLogin?: (user: AuthUser, platform: PlatformId, ctx: RequestContext) => Promise<void>
}

export interface AuthKitPolicy {
  /** 账密类登录失败锁定;false 关闭 */
  loginLock?: { maxFails: number; lockSec: number } | false
  /** 验证码发送限流 */
  codeRate?: { resendIntervalSec: number; perTargetDaily: number; perIpHourly: number }
  /** unionid 跨应用合并的平台家族 */
  unionFamilies?: PlatformId[][]
  /** 身份/联系方式不存在时自动建号 */
  autoRegister?: boolean
}

export interface AuthKitOptions {
  store: AuthStore
  tokens: TokenStrategy
  providers: AuthProvider[]
  kv?: RedisLike
  hooks?: AuthKitHooks
  policy?: AuthKitPolicy
  logger?: LoggerLike
}

export interface LoginResult {
  user: AuthUser
  tokens: TokenPair
  isNewUser: boolean
  claim: IdentityClaim
}

export interface VerifyResult {
  user: AuthUser
  /** JwtSession 策略下签发时写入的业务 claims(如 role) */
  claims?: Record<string, unknown>
  jti?: string
}
