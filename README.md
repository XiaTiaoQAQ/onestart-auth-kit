# onestart-auth-kit

1start.net 的多平台用户/认证 SDK。管线不变、provider 可插、存储走端口:一个包、四个模块入口,模块间只靠接口耦合,为下一个项目分钟级接入而设计。

> 当前状态:**v0.1.3 已发布 npm 并完成两个生产项目接入**(rensheji 全量 / m612 保门面,验证详见 ROADMAP 各阶段验收)。完整设计见 [docs/DESIGN.md](docs/DESIGN.md),执行计划见 [docs/ROADMAP.md](docs/ROADMAP.md)。
>
> ```bash
> bun add @1start/auth-kit        # 或 npm i @1start/auth-kit
> ```

## 包:一个,`@1start/auth-kit`

后端侧只发一个包,subpath exports 暴露四个模块入口(决策依据见 DESIGN.md §2:消费者是同栈项目,四包只剩发版协调成本;子入口 + optional peerDependencies 已给足按需加载与依赖隔离):

| 入口 | 职责 | 状态 |
|---|---|---|
| `@1start/auth-kit`(根) | core:登录管线(验证凭证 → 解析身份 → 签发凭证)、四个端口接口、双 token 策略、错误模型、内存测试替身 | 设计中 |
| `./providers/*` | 各登录方式插件:wechat-mini / douyin-mini / alipay-mini / apple / sms / password / email | 设计中 |
| `./store-postgres` | `AuthStore` 默认实现:`SqlExecutor` 注入、幂等建表、表前缀可配 | 设计中 |
| `./hono` | 可选薄层:标准路由 + `authMiddleware` | 设计中 |

模块依赖方向(严格单向,测试断言守护):core ← providers / store-postgres / hono,三者互相不得 import。core 零运行时依赖;`jose` / `@node-rs/argon2` / `hono` 均为 optional peerDependencies,只在 import 对应入口时需要。前端半边 `@1start/auth-client-front`(阶段 6)因运行环境不同(uni-app/小程序)独立发包。

## 设计血统

提炼自两个经线上验证的实现,去其形取其神:

- **m612-pet-api**:`resolveUserByThirdParty` 三步身份解析(openid 直中 → unionid 家族合并 → 新建)、JWT + refresh + token_version 全端登出、`onUserCreated` hook 解耦业务、微信 getPhoneNumber 绑定与账号合并
- **rensheji-backend**:有状态 opaque token(即时吊销、零 Redis 依赖)、幂等建表风格、多平台 code2session 分发、短信验证码生命周期(scene 隔离 + 频率限制)

DB 解耦沿用 onestart-ai-kit 已验证的模式:`SqlExecutor` / `RedisLike` 结构化接口注入,SDK 零驱动依赖,Bun 与 Node 双兼容。

## 边界(不做)

邀请码、能量/钱包、onboarding、昵称生成规则、admin RBAC、OAuth2 授权服务器、SSO 与多租户管理。业务扩展一律走 hook 与业务侧扩展表。
