# onestart-auth-kit 路线图

> 完整背景:本 SDK 提炼自 m612-pet-api(三步身份解析 + JWT/session/token_version + hook 解耦)与 rensheji-backend(opaque token + 幂等建表 + 多平台 code2session)两套经线上验证的实现。接口定义与数据边界见 [DESIGN.md](./DESIGN.md)——先冻结接口再动工,阶段内不返工接口。
> DB 解耦沿用 onestart-ai-kit 已验证模式:`SqlExecutor` / `RedisLike` 注入,SDK 零驱动依赖。

## 阶段 0:脚手架 + core(接口冻结)

单包仓库:`@1start/auth-kit` 一包多入口(subpath exports,见 DESIGN §2),`src/{core,providers,store-postgres,hono}` 四个模块目录;`examples/` 以 `file:..` 依赖联调。沿用 ai-kit 的 biome / `tsconfig.base` / `bun test` 约定,build 脚本简化为单包多入口产物。**依赖方向检查进测试**:遍历 import 图断言 core 不 import 其他模块、providers/store/hono 互不 import,违反即红(替代包边界的天然强制)。

1. **接口落地**:DESIGN.md §3 全量类型进根入口(`AuthProvider` / `AuthStore` / `SessionStore` / `CodeStore` / `TokenStrategy` / `RedisLike` / `AuthError` / `AuthKitOptions`)。
2. **引擎**:`AuthKit.login()` 管线(直中 → unionid 家族合并 → 可信联系方式找回 → 新建)、`verify/refresh/logout/bind/unbind/bindContact/mergeUsers`、登录失败锁定与验证码限流的 policy 执行。
3. **内置件**:`OpaqueTokenStrategy`、`JwtSessionStrategy`(WebCrypto HS256,零依赖)、`MemoryKv`、`InMemoryAuthStore` + `MemorySessionStore` + `MemoryCodeStore`(测试替身,兼 demo 用)。
4. **规范化工具**:`normalizePhone`(E.164)/ `normalizeEmail`,单一事实源。
5. 纯单测覆盖管线全分支:直中回填 unionid、家族合并、并发新建冲突兜底(用 InMemory store 模拟冲突)、blocked/locked 拒绝、`last_identity` 保护、双策略同一测试矩阵。

**验收**:`bun test` 全绿;`OpaqueTokenStrategy` 与 `JwtSessionStrategy` 跑同一套引擎行为测试矩阵零差异(除吊销语义注明项);接口 diff 评审通过后打 tag 冻结。

## 阶段 1:auth-store-postgres

1. `PostgresAuthStore`(`SqlExecutor` 注入)实现 `AuthStore` + `store.sessions` + `store.codes`;`ensureSchema()` 幂等建表(失败不缓存 rejected promise——PostgresSink 教训)+ `getSchemaSql({ prefix })` 导出。
2. `createUserWithIdentity` 事务原子 + 23505 冲突重读契约;`onCreateInTx` 扩展点。
3. 集成测试跑真 PG(本地 compose):唯一索引兜底、软删过滤、`mergeUsers` 三步事务。

**验收**:同 openid 100 并发登录只产生 1 个用户、0 孤儿身份;`postgres` 库与 `pg` 库两种 executor 注入各跑一遍全量集成测试;`getSchemaSql` 输出可被 psql 干跑。

## 阶段 2:providers

1. `password`:`PasswordHasher` 接口 + `AutoHasher`(新哈希 Argon2id;verify 按前缀分发 argon2/bcrypt——人设机存量 bcrypt 免迁移);Bun 用 `Bun.password`,Node 回退 `@node-rs/argon2`(optional peer)。
2. `sms`:`SmsChannel` 接口 + `AliyunSmsChannel`(收编两项目同源 sms.ts,零依赖 HMAC-SHA1)+ `StubSmsChannel`(devCode 回传,等价 LOGIN_MOCK 开发体验);scene 隔离 + 冷却 + 日/时限流。
3. `wechat-mini`(code2session + `getPhoneNumber` 辅助)、`douyin-mini`(v2 POST)、`alipay-mini`(RSA2,`node:crypto`)。
4. 每个 provider:配置缺失构造即 throw(fail fast);`StubProvider` 显式替身供四端联调。

**验收**:各 provider 对录制响应的单测全绿;`Bun.password` 产出的 bcrypt/argon2 哈希与 `@node-rs/argon2` 互验实测通过(DESIGN §8 待决项销账);Stub 链路走通引擎全流程。

## 阶段 3:auth-hono + 端到端样例

1. `authMiddleware(kit)`:Bearer 解析 → `kit.verify` → `c.set('authUser')`;`AuthError` → HTTP 状态映射表(401/403/423/429)。
2. `createAuthRoutes(kit)` 标准路由:`POST /login/:platform`、`/code/send`、`/refresh`、`/logout`、`/bind`、`/password/reset`。
3. `examples/bun-hono-demo`:默认组件组装(§6.1 代码即 demo 源码),含 `user_profile` 扩展表 + `onCreateInTx` 示范。

**验收**:demo 一条命令起服;curl 脚本全流程(发码 → 短信登录建号 → 绑微信 → 改密 → 刷新 → 单端登出 → 全端登出)通过;README 快速开始按 demo 重写。

## 阶段 4:rensheji 接入(收益最大)

目标路径:`1startnet-projects/rensheji/rensheji-backend/`

1. `domains/auth` 内部改为委托 `AuthKit`,对外 `/api/auth/*` 契约与 `{code,data}` 响应不变;`http/auth.ts` 中间件换 `kit.verify`。
2. 一次性迁移 SQL:`users/user_identities/user_tokens/sms_codes` → `auth_*` 窄核心 + 新建 `user_profile`(nickname/avatar/bound_platform 等业务列搬出);存量 `username` 迁为 identity 行(platform='username',password provider 开 `allowUsername`);存量 bcrypt 密码靠 `AutoHasher` 免迁移。
3. 顺手补欠账:支付宝真实 RSA2 接入、refresh token(策略仍可先选 Opaque 平滑)、登录失败锁定、删 `LOGIN_MOCK`(换 StubProvider,仅 dev 组装)。
4. 能量账户初始化、`bumpDaily/markActive` 埋点移入 `onUserCreated` / `onLogin` hook。

**验收**:四端(微信/抖音/支付宝/H5)真机登录 + 绑定/解绑;存量用户老密码可登录;封禁即时生效回归;迁移脚本在副本库演练一遍零数据丢失;admin 域鉴权不受影响。

## 阶段 5:m612-pet-api 保门面接入(风险最低)

目标路径:`1startnet-projects/m612-pet-planet/m612-pet-api/`

- `AuthService` 公开签名不动,内部委托 AuthKit;`KyselyAuthStore` 适配器映射现有 `users` / `user_third_platform_accounts` / `auth_sessions`,零数据迁移。
- `JwtSessionStrategy` 对齐现有 `JWT_SECRET` / TTL / payload 字段(`ver`),并配 `claimsFromUser: u => ({ role: u.role })` 保持 payload 含 role;适配器令 `AuthUser.id = public_id`(现状 JWT `sub` 即 public_id)——已发放 token 无缝有效,用户不重登。
- invite / 钱包 / 通知留在 composition-root 的 `onUserCreated`;`bindWxPhone` 合并流按 DESIGN §5.3 用 `bindContact` + `mergeUsers` 原语重排,`onboarded` 判断留业务侧。
- **回归闸门**:`auth.service.e2e.test.ts`、`user.e2e.test.ts` 原样跑通;39.106.25.41 灰度。

**验收**:e2e 原样绿;灰度期新旧 token 混验通过;微信手机号绑定 + 空壳号合并真机回归;顺手销掉 m612 已知欠账(手机号规范化散落、配置运行时校验缺失)。

## 阶段 6(后置):apple / email provider + 前端半边

- `apple`(JWS + JWKS 缓存)与 `email`(`EmailChannel`,渠道选型 SMTP vs DirectMail 在此定)。
- `@1start/auth-client-front`:uni.login / getPhoneNumber / Apple 原生的多端封装,与 ai-kit 阶段 6 的 client-front 同期做,复用其 HttpAdapter 注入模式。

**验收**:新项目(或人设机)接 Apple/邮箱登录真机通过;前端包在微信 + 抖音小程序 + H5 三端联调。

## 前置

- npm `@1start` org(与 ai-kit 共用;被占退 `@1startnet`);开发期两项目用 `file:../../onestart-auth-kit` 联调(单包,一个依赖项),合并前切正式版本。
- 阶段 4 动工前:人设机 `.env` 补齐微信/抖音/支付宝真实 appid/secret(见该仓库《需人工提供的密钥清单.md》)。

## 边界(不做)

邀请码、能量/钱包、onboarding、昵称生成、admin RBAC、OAuth2 授权服务器(对外发 token)、SSO/多租户管理、用户画像 CRUD、权限系统(role 仅作透传字段)。业务扩展一律走 hook 与扩展表。
