// SDK 表结构(窄核心,业务字段一律走业务侧扩展表)。
// 双模式:ensureSchema() 幂等建表(开发/新项目);getSchemaSql() 导出给正式迁移系统(生产)。

export function assertPrefix(prefix: string): void {
  if (!/^[a-z_][a-z0-9_]*$/i.test(prefix)) throw new Error(`非法表前缀: ${prefix}`)
}

export function getSchemaSql(opts: { prefix?: string } = {}): string {
  const p = opts.prefix ?? 'auth_'
  assertPrefix(p)
  return `
CREATE TABLE IF NOT EXISTS ${p}users (
  id             BIGSERIAL PRIMARY KEY,
  status         TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked','blocked')),
  token_version  INT  NOT NULL DEFAULT 1,
  phone          TEXT,
  email          TEXT,
  password_hash  TEXT,
  last_login_at  TIMESTAMPTZ,
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at     TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_${p}users_phone ON ${p}users (phone)
  WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS ux_${p}users_email ON ${p}users (email)
  WHERE email IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS ${p}identities (
  id            BIGSERIAL PRIMARY KEY,
  user_id       BIGINT NOT NULL REFERENCES ${p}users(id),
  platform      TEXT NOT NULL,
  app_id        TEXT NOT NULL DEFAULT '',
  open_id       TEXT NOT NULL,
  union_id      TEXT,
  profile       JSONB,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at    TIMESTAMPTZ
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_${p}identities_openid ON ${p}identities (platform, app_id, open_id)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_${p}identities_union ON ${p}identities (platform, union_id)
  WHERE union_id IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS ix_${p}identities_user ON ${p}identities (user_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS ${p}sessions (
  id          BIGSERIAL PRIMARY KEY,
  user_id     BIGINT NOT NULL,
  key         TEXT NOT NULL UNIQUE,
  client      TEXT NOT NULL DEFAULT '',
  ip          TEXT,
  user_agent  TEXT,
  expires_at  TIMESTAMPTZ NOT NULL,
  revoked_at  TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_${p}sessions_user ON ${p}sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS ${p}codes (
  target      TEXT NOT NULL,
  scene       TEXT NOT NULL,
  code        TEXT NOT NULL,
  expires_at  TIMESTAMPTZ NOT NULL,
  sent_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  consumed    BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (target, scene)
);
`.trim()
}
