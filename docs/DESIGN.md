# onestart-auth-kit 设计文档

> 2026-07-02 首版。提炼自 m612-pet-api 与 rensheji-backend 的用户系统(分析结论见本文档,代码参照见文末索引)。
> 阅读顺序:先看 §1 核心模型想清楚"什么进 SDK",再看 §3 接口定义,最后看 §6 集成模式理解两个老项目怎么接。

## 0. 设计原则(继承 onestart-ai-kit)

1. **模块间只靠接口耦合**,依赖方向严格单向(core ← providers / store / hono,用测试断言守护,见 §2);core 零运行时依赖。
2. **零驱动依赖**:postgres / redis 全部走结构化接口注入(`SqlExecutor` / `RedisLike`),默认实现自动建表(幂等,表前缀可配,校验表名合法性)。
3. **保门面接入**:老项目接入时既有 service 签名不动,内部委托 SDK。
4. **Bun / Node 双兼容**:只用标准 API(WebCrypto、fetch、`crypto.randomUUID`);Bun 专属能力(如 `Bun.password`)只出现在可注入的默认实现里,且有纯 JS 回退。
5. **SDK 的生命力取决于它拒绝了什么**:邀请码、能量、onboarding、昵称规则、RBAC 一律不进,走 hook 与业务扩展表。

## 1. 核心模型:一条不变的管线

所有登录方式(Apple / 手机号 / 邮箱 / 微信 / 抖音 / 支付宝小程序)本质是同一条管线:

```
凭证 credential ──▶ [AuthProvider.verify] ──▶ 统一身份声明 IdentityClaim
                                                      │
                              ┌────────────────────────┘
                              ▼
              [解析身份到用户](openid 直中 → unionid 家族合并 → 新建)
                              │
                              ▼
                    [TokenStrategy.issue] ──▶ tokens
```

变的只有第一步。因此:

- **管线进 core**(`AuthKit.login()`),提炼自 m612 的 `resolveUserByThirdParty`(三步解析、防一人多号、并发唯一约束兜底)。
- **验证方式做成 provider 插件**。新增一个平台 = 新增一个 provider + 组装时注册一行。
- **存储、凭证策略、KV 是端口**,由外部实现注入。

### 1.1 数据边界:SDK 窄核心 + 业务扩展表

SDK 只拥有它逻辑上必须写的数据;业务字段放业务自己的表,1:1 挂 `userId`。**SDK 表不为任何业务需求加列**——这条纪律是它能跨项目的前提。

| 归属 | 数据 | 例子 |
|---|---|---|
| SDK(`auth_` 前缀表) | 用户最小核、第三方身份、会话、验证码 | status / tokenVersion / phone / email / passwordHash / openid / unionid |
| 业务(扩展表) | 一切画像与业务状态 | 昵称、头像、onboarded、邀请码、能量账户、locale、时区 |

业务在用户创建时初始化扩展表,走两个 hook(见 §3.6):`onCreateInTx`(默认 store 事务内)或 `onUserCreated`(事务外异步,失败不阻塞——m612 已验证的模式)。

### 1.2 userId 约定

SDK 全程用 `string` 承载 userId(接口层不出现 bigint/number)。默认 postgres store 内部用 `BIGSERIAL`,对外 `String(id)`;m612 适配器把它的 `bigint` id 转字符串。防枚举的 `public_id` 属于业务 API 层关切,不进 SDK。

## 2. 发布形态:一个包,四个模块入口

**决策(2026-07-02 修订):后端侧只发一个 npm 包 `@1start/auth-kit`,用 subpath exports 暴露模块入口**;"core / providers / store / hono"从四个包降级为包内的四个目录模块。包边界(npm 发布单元)与模块边界(代码分层)是两回事——需要守住的是后者,前者切几份只是发布策略。

```
@1start/auth-kit
  .                        → core:AuthKit 引擎、四个端口接口、错误模型、双 token 策略、
                             MemoryKv / InMemory* 测试替身、规范化工具(零运行时依赖)
  ./providers/wechat-mini  → 登录方式插件,一平台一入口
  ./providers/douyin-mini    (另有 /alipay-mini /apple /sms /password /email)
  ./store-postgres         → AuthStore + SessionStore + CodeStore 默认实现
  ./hono                   → authMiddleware + 标准路由工厂
```

```jsonc
// package.json(节选)
{
  "name": "@1start/auth-kit",
  "exports": {
    ".": "./dist/core/index.js",
    "./providers/*": "./dist/providers/*/index.js",
    "./store-postgres": "./dist/store-postgres/index.js",
    "./hono": "./dist/hono/index.js"
  },
  "peerDependencies": { "hono": ">=4", "jose": ">=5", "@node-rs/argon2": ">=1" },
  "peerDependenciesMeta": {
    "hono": { "optional": true }, "jose": { "optional": true },
    "@node-rs/argon2": { "optional": true }
  }
}
```

单包的理由(记录决策依据):

1. **消费者是同栈后端项目**(Bun + Hono + PG)。四包的"可替换性"服务的是假想项目;现实收益是零,成本是真的——core 接口一动,三个下游包要协调 bump、依赖序 build、分别发版。
2. **子入口已经给了四包想要的一切**:按需加载(不 import `./providers/apple` 就不会碰 `jose`)、依赖隔离(重依赖全部走 optional peerDependencies,装了才用)、心智分层(import 路径即模块边界)。
3. **一次发版,版本永远对齐**,两个业务项目各只挂一个依赖号。

单包丢掉的唯一东西:包边界对依赖方向的天然强制。补偿:**依赖方向检查进测试**——core 不得 import providers/store/hono;providers/store/hono 互相不得 import,只准向 core 要类型。阶段 0 用一个遍历 import 图的 `bun test` 断言守护,违反即红。

仍然独立发包的例外:阶段 6 的 `@1start/auth-client-front`(前端半边)——运行环境不同(uni-app/小程序),消费者不同,和 ai-kit 的 client-front 同理。未来若某 provider 引入重依赖需要拆出,exports 结构让拆包只是"改 import 前缀"的迁移。

`core` 零运行时依赖(JWT HS256 用 WebCrypto 自实现);`jose` 只被 `./providers/apple` 引用,`@node-rs/argon2` 只被 Node 环境下的 `./providers/password` 引用,`hono` 只被 `./hono` 引用。

## 3. 接口定义(冻结前逐条评审)

### 3.1 身份声明与实体

```ts
export type PlatformId = string
// 内置常量:'wechat_mini' | 'wechat_open' | 'douyin_mini' | 'alipay_mini'
//          | 'apple' | 'qq' | 'sms' | 'password' | 'email' | 'username';允许业务自定义
// 'username' 是本地登录名身份(见 §5 password 行):不是可验证联系方式,建模为一种 identity

export interface RequestContext {
  ip?: string
  userAgent?: string
  client?: string        // 'h5' | 'mp-weixin' | 'ios' ... 业务自定,透传进会话
  locale?: string        // 透传给短信/邮件模板,SDK 不存储
}

export interface IdentityClaim {
  platform: PlatformId
  appId: string                  // 平台应用维度(微信 openid 按 appid 隔离);无此概念传 ''
  openId: string                 // 平台内唯一标识:openid / apple sub / E.164 手机号 / 小写邮箱
  unionId?: string | null        // 跨应用聚合 id(微信/QQ);无则 null
  phone?: string                 // provider 验证过的可信手机号(E.164)
  email?: string                 // provider 验证过的可信邮箱(小写)
  profile?: { nickname?: string; avatarUrl?: string; gender?: 0 | 1 | 2; raw?: unknown }
}

export interface AuthUser {
  id: string
  status: 'active' | 'locked' | 'blocked'
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
```

### 3.2 端口一:AuthProvider(变化的部分)

```ts
export interface AuthProvider<TCredential = unknown> {
  readonly platform: PlatformId
  readonly appId: string
  /** 校验凭证。失败抛 AuthError:credential_invalid / code_invalid /
   *  provider_not_configured / provider_upstream */
  verify(credential: TCredential, ctx: RequestContext): Promise<IdentityClaim>
}

/** 需要"先发码后验证"的 provider(sms / email)额外实现: */
export interface CodeSender {
  sendCode(target: string, scene: CodeScene, ctx: RequestContext): Promise<{ resendAfterSec: number }>
}
export type CodeScene = 'login' | 'register' | 'bind' | 'reset'
```

### 3.3 端口二:AuthStore(存储)

契约要点:
- `createUserWithIdentity` **语义上要求原子**——怎么开事务是实现的事,core 保持零 IO。
- 并发兜底契约:唯一约束 `(platform, appId, openId)` 冲突时,实现必须捕获冲突、重读既有身份并返回既有用户(m612 验证过的 23505 兜底),不得把驱动异常泄漏给 core。
- 所有"查活体"的方法默认过滤软删行;是否物理删由实现决定,`unbindIdentity` 建议软删留痕。

```ts
export interface AuthStore {
  findUserById(id: string): Promise<AuthUser | null>
  findUserByContact(kind: 'phone' | 'email', value: string): Promise<AuthUser | null>

  findIdentity(platform: PlatformId, appId: string, openId: string): Promise<Identity | null>
  findIdentityByUnionId(platforms: PlatformId[], unionId: string): Promise<Identity | null>
  listIdentities(userId: string): Promise<Identity[]>

  /** 原子:建用户 + 可选首个身份 + 可选可信联系方式。见上方并发兜底契约。 */
  createUserWithIdentity(
    user: { phone?: string | null; email?: string | null; passwordHash?: string | null },
    identity: Omit<Identity, 'id' | 'userId' | 'createdAt'> | null,
  ): Promise<{ user: AuthUser; created: boolean }>

  bindIdentity(userId: string, identity: Omit<Identity, 'id' | 'userId' | 'createdAt'>): Promise<Identity>
  unbindIdentity(identityId: string): Promise<void>
  /** 账号合并原语:把 from 的全部身份改挂到 to(合并的"何时/是否"由业务决定,见 §5.3) */
  reassignIdentities(fromUserId: string, toUserId: string): Promise<void>

  updateContact(userId: string, kind: 'phone' | 'email', value: string | null): Promise<void>
  getPasswordHash(userId: string): Promise<string | null>
  setPasswordHash(userId: string, hash: string | null): Promise<void>
  setStatus(userId: string, status: AuthUser['status']): Promise<void>
  bumpTokenVersion(userId: string): Promise<number>
  markLogin(userId: string, at: Date): Promise<void>
  softDeleteUser(userId: string): Promise<void>
}
```

会话与验证码单独成接口——只有用到对应策略/provider 才需要实现:

```ts
export interface SessionStore {
  insert(s: { userId: string; key: string; client: string; ip?: string
              userAgent?: string; expiresAt: Date }): Promise<void>
  find(key: string): Promise<{ userId: string; expiresAt: Date; revokedAt: Date | null } | null>
  revoke(key: string): Promise<void>
  revokeAllForUser(userId: string): Promise<void>
}
// key = JwtSession 策略的 refresh jti,或 Opaque 策略的 token 本身

export interface CodeStore {
  /** UPSERT:同 (target, scene) 一行,覆盖旧码 */
  save(target: string, scene: CodeScene, code: string, ttlSec: number): Promise<void>
  /** 原子消费:匹配且未过期未消费 → 置 consumed 并返回 true */
  consume(target: string, scene: CodeScene, code: string): Promise<boolean>
}
```

### 3.4 端口三:TokenStrategy(凭证策略)

两个项目现状恰好是两种合法取舍,所以不二选一,抽成接口、内置双实现:

```ts
export interface TokenPair { access: string; refresh?: string; expiresInSec: number }

export interface VerifiedAccess {
  userId: string
  jti?: string          // JwtSession:用于登出拉黑
  tokenVersion?: number // JwtSession:引擎与 user.tokenVersion 比对;Opaque 无需
  claims?: Record<string, unknown> // JwtSession:签发时写入的业务 claims 原样带回(如 m612 的 role)
}

export interface TokenStrategy {
  issue(user: AuthUser, ctx: RequestContext): Promise<TokenPair>
  /** 失败抛 AuthError:token_invalid / token_expired / token_revoked */
  verifyAccess(token: string): Promise<VerifiedAccess>
  refresh?(refreshToken: string, ctx: RequestContext): Promise<TokenPair>
  revoke(input: { access?: string; refresh?: string }): Promise<void>
  revokeAllForUser(userId: string): Promise<void>
}
```

内置实现:

| | `OpaqueTokenStrategy`(人设机模式) | `JwtSessionStrategy`(m612 模式) |
|---|---|---|
| access | 32B hex,存 `SessionStore`,查库校验 | JWT HS256(WebCrypto),payload 含 `sub/jti/ver/exp` |
| refresh | 无(可配长 TTL 单 token) | JWT,jti 落 `SessionStore`,旋转式刷新(旧 jti revoke) |
| 即时吊销 | 天然(删行) | jti 黑名单进 `RedisLike` + `tokenVersion` 全端登出 |
| 依赖 | `SessionStore` | `secret` + `SessionStore` + `RedisLike`(黑名单) |
| 适用 | 小项目、免 Redis、单进程 | 上量、多实例、水平扩展 |

构造:`new OpaqueTokenStrategy({ sessions, ttlSec })`;`new JwtSessionStrategy({ secret, accessTtlSec, refreshTtlSec, sessions, kv, claimsFromUser? })`。业务从一种换到另一种,只改组装处一行。

`claimsFromUser?: (user: AuthUser) => Record<string, unknown>`——返回值并入 access payload,`verifyAccess` 经 `claims` 原样带回。配套约定:**store 实现可以返回 `AuthUser` 的结构超集**(TS 结构类型天然允许),`claimsFromUser` 与 hooks 收到的就是这个超集——m612 适配器借此把自有的 `role` 透传进 JWT 而不污染核心接口(`AuthUser` 不加 role 字段)。

分层纪律:strategy 只管凭证本身;`user.status` 封禁检查与 `tokenVersion` 比对由引擎在 `verify()` 里统一做(策略返回什么就校验什么)。

### 3.5 端口四:RedisLike(KV)

登录失败锁定、验证码限流、jti 黑名单、JWKS 缓存共用一个最小 KV 接口(与 ai-kit 的 `RedisLike` 同构,ioredis 实例直接满足):

```ts
export interface RedisLike {
  get(key: string): Promise<string | null>
  set(key: string, value: string, ...args: unknown[]): Promise<unknown>  // 兼容 'EX', sec
  del(key: string): Promise<unknown>
  incr(key: string): Promise<number>
  expire(key: string, ttlSec: number): Promise<unknown>
  ttl(key: string): Promise<number>
}
```

core 提供 `MemoryKv`(带 TTL 的 Map)。**多实例部署必须换真 Redis**——黑名单/锁定在内存里不跨进程,这一条在类型注释与 README 双处标注。

### 3.6 引擎:AuthKit

```ts
export interface AuthKitOptions {
  store: AuthStore
  tokens: TokenStrategy
  providers: AuthProvider[]
  kv?: RedisLike                 // 缺省 MemoryKv
  hooks?: {
    /** 事务外异步,失败仅 logger.warn 不阻塞(m612 模式):初始化业务扩展表、发券、通知 */
    onUserCreated?: (user: AuthUser, claim: IdentityClaim | null) => Promise<void>
    /** 审计挂点:每次成功登录 */
    onLogin?: (user: AuthUser, platform: PlatformId, ctx: RequestContext) => Promise<void>
  }
  policy?: {
    loginLock?: { maxFails: number; lockSec: number } | false   // 缺省 5 次 / 600s(账密类)
    codeRate?: { resendIntervalSec: number; perTargetDaily: number; perIpHourly: number }
    unionFamilies?: PlatformId[][]   // 缺省 [['wechat_mini','wechat_open'], ['qq']]
    autoRegister?: boolean           // 缺省 true:身份/联系方式不存在时自动建号
  }
  logger?: { info(o: unknown, msg?: string): void; warn(o: unknown, msg?: string): void }
}

export interface LoginResult {
  user: AuthUser
  tokens: TokenPair
  isNewUser: boolean
  claim: IdentityClaim
}

export class AuthKit {
  constructor(opts: AuthKitOptions)

  // 登录管线(所有方式统一入口)
  login(platform: PlatformId, credential: unknown, ctx?: RequestContext): Promise<LoginResult>
  sendCode(platform: PlatformId, target: string, scene: CodeScene, ctx?: RequestContext): Promise<{ resendAfterSec: number }>

  // 凭证生命周期
  verify(accessToken: string): Promise<AuthUser>       // 中间件用:校验 + status/ver 检查
  refresh(refreshToken: string, ctx?: RequestContext): Promise<TokenPair>
  logout(input: { access?: string; refresh?: string; userId?: string; allDevices?: boolean }): Promise<void>

  // 绑定 / 解绑 / 合并
  bind(userId: string, platform: PlatformId, credential: unknown): Promise<Identity>
  unbind(userId: string, platform: PlatformId, openId: string): Promise<void>
  bindContact(userId: string, kind: 'phone' | 'email', value: string): Promise<void>
  mergeUsers(fromUserId: string, toUserId: string, ctx?: RequestContext): Promise<{ tokens: TokenPair }>

  // 密码管理(password provider 的伴生操作)
  setPassword(userId: string, newPassword: string): Promise<void>
  resetPasswordByCode(input: { kind: 'phone' | 'email'; target: string
                               code: string; newPassword: string }): Promise<void>
}
```

`login()` 内部流程(不变管线,全部方式共用):

1. `provider.verify(credential)` → `IdentityClaim`;
2. 解析身份:`findIdentity` 直中 → 命中即复用(机会性回填 unionId);未中且有 unionId → `findIdentityByUnionId(家族)` 命中 → `bindIdentity` 到既有用户;仍未中 → claim 带可信 phone/email 时先 `findUserByContact`(短信登录找回老用户);全部未中且 `autoRegister` → `createUserWithIdentity`;
3. 引擎检查 `status`(blocked → `user_blocked`,locked → `account_locked`);
4. `tokens.issue()` + `markLogin` + hooks(`onUserCreated` 仅新用户,`onLogin` 每次)。

### 3.7 错误模型

SDK 抛自己的错误,业务层映射到各自错误码体系(m612 的 `BusinessError` / 人设机的 `ApiError`),core 不依赖任何业务错误类型:

```ts
export type AuthErrorKind =
  | 'credential_invalid' | 'code_invalid' | 'code_rate_limited'
  | 'provider_not_configured' | 'provider_upstream'
  | 'account_locked'          // detail: { retryAfterSec }
  | 'user_blocked'
  | 'token_invalid' | 'token_expired' | 'token_revoked'
  | 'identity_taken' | 'contact_taken' | 'identity_not_found' | 'last_identity'
  | 'user_not_found' | 'password_required'

export class AuthError extends Error {
  constructor(readonly kind: AuthErrorKind, readonly detail?: Record<string, unknown>)
}
```

`unbind` 保护:解绑后若用户既无其余身份也无 password/phone/email 登录手段 → 抛 `last_identity`。

### 3.8 规范化工具(单一事实源)

修掉 m612"手机号规范化散落两处"的问题:core 导出 `normalizePhone(raw, defaultRegion='CN'): string`(输出 E.164)与 `normalizeEmail(raw): string`(trim + 小写)。provider 与 store 适配器统一调用,禁止各写各的。

## 4. 默认存储:`./store-postgres` 模块

### 4.1 注入与建表

```ts
export type SqlExecutor = (text: string, params: unknown[]) => Promise<unknown>
// postgres 库:new PostgresAuthStore((t, p) => sql.unsafe(t, p))
// pg 库:     new PostgresAuthStore((t, p) => pool.query(t, p).then(r => r.rows))

new PostgresAuthStore(sql, {
  prefix: 'auth_',          // 表前缀,校验 /^[a-z_][a-z0-9_]*$/i
  ensureSchema: true,       // 首次访问幂等建表;生产建议 false 走迁移
  onCreateInTx?: (sql: SqlExecutor, userId: string) => Promise<void>,
                            // 业务在同事务里建扩展表行的扩展点
})
```

建表双模式:`ensureSchema()`(幂等 `CREATE TABLE IF NOT EXISTS` + `ALTER ... ADD COLUMN IF NOT EXISTS`,人设机 schema.ts 风格;失败不得缓存 rejected promise——沿用 PostgresSink 的教训)与 `getSchemaSql({ prefix })`(导出完整 SQL 给正式迁移系统,m612 migrations 风格)。

### 4.2 表结构

```sql
CREATE TABLE auth_users (
  id             BIGSERIAL PRIMARY KEY,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked','blocked')),
  token_version  INT  NOT NULL DEFAULT 1,
  phone          TEXT,                -- E.164
  email          TEXT,                -- 小写
  password_hash  TEXT,
  last_login_at  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX ux_auth_users_phone ON auth_users (phone) WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX ux_auth_users_email ON auth_users (email) WHERE email IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE auth_identities (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES auth_users(id),
  platform      TEXT NOT NULL,
  app_id        TEXT NOT NULL DEFAULT '',     -- 空串而非 NULL,规避唯一索引 NULL 陷阱
  open_id       TEXT NOT NULL,
  union_id      TEXT,
  profile       JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at    TIMESTAMPTZ                   -- 解绑软删留痕
);
CREATE UNIQUE INDEX ux_auth_identities_openid ON auth_identities (platform, app_id, open_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_auth_identities_union ON auth_identities (platform, union_id) WHERE union_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX ix_auth_identities_user  ON auth_identities (user_id) WHERE deleted_at IS NULL;

CREATE TABLE auth_sessions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL,
  key         TEXT NOT NULL UNIQUE,           -- refresh jti 或 opaque token
  client      TEXT NOT NULL DEFAULT '',
  ip          TEXT,
  user_agent  TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_auth_sessions_user ON auth_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE auth_codes (
  target      TEXT NOT NULL,                  -- E.164 手机号或小写邮箱
  scene       TEXT NOT NULL,
  code        TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  sent_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed    BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (target, scene)
);
```

业务扩展表由业务自建,例如 `user_profile (user_id BIGINT PRIMARY KEY, nickname TEXT, ...)`,在 `onCreateInTx` 或 `onUserCreated` 里初始化。SDK 对它一无所知。

## 5. Provider 规格

| provider | credential | 验证方式 | 配置 | 备注 |
|---|---|---|---|---|
| `wechat-mini` | `{ code }` | `jscode2session` | appid / secret / kv?(access_token 缓存,缺省 MemoryKv) | 返回 openid + unionid?;另暴露 `getPhoneNumber(code)` 辅助方法(新版免 session_key 解密,依赖缓存的 access_token——m612 已验证),供 §5.3 绑定流用 |
| `douyin-mini` | `{ code }` | v2 `jscode2session`(POST) | appid / secret | 取自人设机实现 |
| `alipay-mini` | `{ code }` | `alipay.system.oauth.token` + RSA2 签名(`node:crypto`) | appid / privateKey / alipayPublicKey | openId 用 user_id;无 unionid,跨端归一靠手机号 |
| `apple` | `{ identityToken }` | 对 Apple JWKS 验 JWS(`jose`),校验 iss/aud/exp | clientId(bundle id) | openId = `sub`;email 仅首次授权返回,进 claim.email;JWKS 经 `RedisLike` 缓存 |
| `sms` | `{ phone, code }` | `CodeStore.consume` | `SmsChannel` + `CodeStore` + 限流策略 | 亦实现 `CodeSender`;scene 隔离 + 单发冷却 + 日/时限流(KV) |
| `password` | `{ account, password }` | `PasswordHasher.verify` | `PasswordHasher` + `allowUsername?: boolean`(缺省 false) | account 解析顺序:E.164 成功 → phone;含 `@` → email;否则(需开启 allowUsername)→ username 身份 `findIdentity('username', '', account)`。username 不是可验证联系方式,建模为一种 identity——零表结构改动,复用唯一索引与绑定语义;人设机存量 `users.username` 迁为 identity 行即可。失败锁定走引擎 policy |
| `email`(阶段 6) | `{ email, code }` | 同 sms | `EmailChannel` + `CodeStore` | 与 sms 共用验证码生命周期 |

### 5.1 PasswordHasher 与哈希迁移

```ts
export interface PasswordHasher {
  hash(plain: string): Promise<string>
  verify(hash: string, plain: string): Promise<boolean>
}
```

默认实现 `AutoHasher`:新哈希一律 Argon2id;`verify` 按哈希前缀分发(`$argon2id$` → argon2,`$2a/$2b$` → bcrypt)。两个项目现状不同(m612 = Argon2id,人设机 = bcrypt),这让人设机的存量密码免迁移直接接入,验证通过后可选择性 rehash 升级。运行时探测:Bun 下用 `Bun.password`(两种算法原生支持),Node 下用 `@node-rs/argon2`(optional peer)。

### 5.2 SmsChannel(发送渠道)

```ts
export interface SmsChannel {
  send(phone: string, code: string, opts: { scene: CodeScene; locale?: string }): Promise<void>
}
```

内置:`AliyunSmsChannel`(把两项目 >80% 雷同的 `sms.ts` 收编:零依赖 HMAC-SHA1 签名、Dysmsapi 2017-05-25)、`StubSmsChannel`(打日志 + 可选回传 devCode,等价人设机 `SMS_PROVIDER=stub`)。腾讯云渠道留接口不实现(m612 config 有枚举无实现,不接这笔虚账)。

### 5.3 微信手机号绑定与账号合并(m612 流程映射到 SDK 原语)

m612 的 `bindWxPhone` + `mergeIntoPhoneOwner` 里,"是否允许合并"取决于 `onboarded`——这是业务概念,所以 SDK 只提供原语,编排留业务:

```ts
const phone = await wechatProvider.getPhoneNumber(code)      // 1. 可信手机号
try {
  await kit.bindContact(userId, 'phone', phone)              // 2. 空闲 → 直接绑定
} catch (e) {
  if (e instanceof AuthError && e.kind === 'contact_taken') {
    if (!currentUserProfile.onboarded) {                     // 3. 业务判断是否吞并空壳号
      const { tokens } = await kit.mergeUsers(userId, e.detail.ownerId)
      return { merged: true, tokens }                        // 4. 换发新 token,旧全失效
    }
    throw e
  }
}
```

`mergeUsers` 契约:`reassignIdentities(from→to)` + `softDeleteUser(from)` + `revokeAllForUser(from)` + 对 to `issue` 新 tokens。默认 store 在一个事务内完成前三步。

## 6. 集成模式

### 6.1 新项目(分钟级)

```ts
const sql = postgres(DB_URL)
const store = new PostgresAuthStore((t, p) => sql.unsafe(t, p), {
  onCreateInTx: async (tx, userId) => {
    await tx(`INSERT INTO user_profile (user_id, nickname) VALUES ($1, $2)`, [userId, randomNick()])
  },
})
const kit = new AuthKit({
  store,
  tokens: new OpaqueTokenStrategy({ sessions: store.sessions, ttlSec: 7 * 86400 }),
  providers: [
    new WechatMiniProvider({ appid: ENV.wx.appid, secret: ENV.wx.secret }),
    new SmsProvider({ channel: new AliyunSmsChannel(ENV.sms), codes: store.codes }),
    new PasswordProvider({ store }),
  ],
  hooks: { onUserCreated: async (u) => notify.welcome(u.id) },
})
// Hono:app.use('/api/*', authMiddleware(kit));app.route('/api/auth', createAuthRoutes(kit))
```

### 6.2 rensheji-backend(全量接入,阶段 4)

默认 store + 一次性迁移 SQL(`users/user_identities/user_tokens/sms_codes` → `auth_*` 窄核心 + `user_profile` 扩展表;它的表形状与默认 store 高度同源,以列搬运为主)。存量 `users.username` 迁为 identity 行(platform=`'username'`),password provider 开 `allowUsername`;存量 bcrypt 密码靠 `AutoHasher` 免迁移。顺手补齐本来欠的活:支付宝真实 RSA2、refresh、登录失败锁定、去 `LOGIN_MOCK`(换 `StubProvider`)。对外 `/api/auth/*` 契约不变。

### 6.3 m612-pet-api(保门面,阶段 5)

`AuthService` 公开签名一个不动,内部委托 `AuthKit`;写 `KyselyAuthStore` 适配器(~200 行)把 `AuthStore` 映射到现有 `users` / `user_third_platform_accounts` / `auth_sessions` 表——一行数据不迁。两个无缝要点:适配器令 `AuthUser.id = public_id`(m612 现状 JWT `sub` 即 public_id,旧 token 校验路径不变,内部 bigint 由适配器换算);`JwtSessionStrategy` 对齐现有 `JWT_SECRET/TTL` 并配 `claimsFromUser: u => ({ role: u.role })`(适配器返回的 AuthUser 超集带 role),新旧 payload 字段一致,middleware 行为零变化。invite / 钱包 / 通知原样留在 composition-root 的 `onUserCreated`。四个 e2e spec 原样跑通作回归闸门。

## 7. 安全基线(从两项目提炼,SDK 默认给足)

- 登录失败锁定:账号+IP 双维度计数,超限锁定并返回 `retryAfterSec`(m612)
- 验证码:scene 隔离、一次性消费、单发冷却 60s、按目标日限 + 按 IP 时限(两项目并集)
- 封禁即时生效:`verify()` 每次核对 `status`(Opaque 天然;JwtSession 靠黑名单 + ver,access 期内 blocked 用户也会在下一次 verify 被拒——引擎查库核对)
- 全端登出:`tokenVersion` 递增(m612)
- 配置 fail fast:provider 构造时校验必填配置,缺失即 throw(修 m612"调用时才炸"的问题);显式 `StubProvider` 才允许无配置跑
- 凭证明文不落日志:`logger` 调用点约定只记 kind 与脱敏字段

## 8. 已知取舍与待决

- **Opaque 每请求 1 次 DB 查询**:人设机池 10 实测够用;量级上来换 `JwtSessionStrategy`,业务代码不动。
- **MemoryKv 不跨进程**:多实例必须注入 Redis,文档与类型注释双标注。
- **支付宝无 unionid**:跨端归一依赖手机号绑定,产品层要引导绑手机。
- **`Bun.password` 与 `@node-rs/argon2` 哈希互验**:理论兼容(标准 PHC 格式),阶段 2 验收项里实测一次。
- **JWT 混部署迁移**(m612 接入期新旧签发并存):秘钥与 payload 字段保持一致即可,`ver` 字段名对齐现有 `ver`。
- **邮箱 provider 的送达渠道**:阶段 6 定(SMTP 直发 vs 阿里云 DirectMail),接口先留 `EmailChannel`。

## 9. 代码参照索引

| 提炼目标 | 参照 |
|---|---|
| 三步身份解析 + 并发兜底 | `m612-pet-planet/m612-pet-api/apps/api/src/services/auth.service.ts` 的 `resolveUserByThirdParty` |
| JWT + session + token_version | 同上 `issueTokens/mintTokens` + `apps/api/src/infra/auth/jwt.ts` + `repositories/session.repository.ts` |
| 微信 client(code2session/getPhoneNumber) | `apps/api/src/infra/wechat/wechat-miniprogram.client.ts` |
| hook 解耦(onUserCreated) | `apps/api/src/composition-root.ts` |
| Opaque token / 幂等建表风格 | `rensheji/rensheji-backend/src/domains/auth/repo.ts` + `src/db/schema.ts` |
| 抖音 code2session | `rensheji/rensheji-backend/src/lib/platform-login.ts` |
| 阿里云短信(收编为 AliyunSmsChannel) | 两项目的 `sms.ts`(同源,取 m612 版为准) |
| SqlExecutor 注入 + ensure 防 rejected 缓存 | `onestart-ai-kit/packages/ai-analytics/src/sinks/postgres.ts` |
