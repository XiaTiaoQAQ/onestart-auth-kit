import { describe, expect, test } from 'bun:test'
import { tryNormalizeEmail, tryNormalizePhone } from './normalize'

describe('normalizePhone', () => {
  test('裸 11 位国内号补 +86', () => {
    expect(tryNormalizePhone('13800138000')).toBe('+8613800138000')
  })
  test('已带 +86 原样;空格破折号剔除', () => {
    expect(tryNormalizePhone('+86 138-0013-8000')).toBe('+8613800138000')
  })
  test('其他国家 E.164 放行', () => {
    expect(tryNormalizePhone('+14155552671')).toBe('+14155552671')
  })
  test('非法号返回 null', () => {
    for (const bad of ['12345', '2380013800011', 'abc', '', '+', '10800138000']) {
      expect(tryNormalizePhone(bad)).toBeNull()
    }
  })
})

describe('normalizeEmail', () => {
  test('trim + 小写', () => {
    expect(tryNormalizeEmail('  Foo@Bar.COM ')).toBe('foo@bar.com')
  })
  test('非法返回 null', () => {
    for (const bad of ['a@b', 'a b@c.com', 'nope', '']) {
      expect(tryNormalizeEmail(bad)).toBeNull()
    }
  })
})
