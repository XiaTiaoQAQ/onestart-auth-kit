// 手机号 / 邮箱规范化的单一事实源。provider 与 store 适配器统一调用,禁止各写各的。

/** E.164 规范化;非法返回 null。裸 11 位国内号补 +86,已带 + 的原样校验。 */
export function tryNormalizePhone(raw: string, defaultRegion: 'CN' = 'CN'): string | null {
  const s = raw.replace(/[\s()-]/g, '')
  if (/^1[3-9]\d{9}$/.test(s)) return defaultRegion === 'CN' ? `+86${s}` : null
  if (/^\+86(1[3-9]\d{9})$/.test(s)) return s
  if (/^\+[1-9]\d{5,14}$/.test(s)) return s
  return null
}

export function normalizePhone(raw: string): string {
  const p = tryNormalizePhone(raw)
  if (!p) throw new RangeError(`invalid phone: ${raw}`)
  return p
}

export function tryNormalizeEmail(raw: string): string | null {
  const s = raw.trim().toLowerCase()
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s) ? s : null
}

export function normalizeEmail(raw: string): string {
  const e = tryNormalizeEmail(raw)
  if (!e) throw new RangeError(`invalid email: ${raw}`)
  return e
}
