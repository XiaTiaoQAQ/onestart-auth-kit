// 依赖方向守护(替代包边界的天然强制):
//   core 不得 import providers / store-postgres / hono;
//   providers / store-postgres / hono 互相不得 import,只准向 core 要类型。
import { describe, expect, test } from 'bun:test'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative, resolve } from 'node:path'

const SRC = resolve(import.meta.dir)

function walk(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) out.push(...walk(p))
    else if (p.endsWith('.ts') && !p.endsWith('.spec.ts')) out.push(p)
  }
  return out
}

function moduleOf(file: string): string {
  const rel = relative(SRC, file)
  const seg = rel.split('/')[0] ?? ''
  return seg
}

function importsOf(file: string): string[] {
  const text = readFileSync(file, 'utf8')
  const specs: string[] = []
  const re = /(?:^|\n)\s*(?:import|export)[^'"\n]*from\s+['"]([^'"]+)['"]/g
  for (let m = re.exec(text); m; m = re.exec(text)) {
    const spec = m[1]
    if (spec) specs.push(spec)
  }
  return specs
}

describe('模块依赖方向', () => {
  const files = walk(SRC)
  const MODULES = ['core', 'providers', 'store-postgres', 'hono']

  test('core 不 import 其他模块;providers/store/hono 互不 import', () => {
    const violations: string[] = []
    for (const file of files) {
      const from = moduleOf(file)
      if (!MODULES.includes(from)) continue
      for (const spec of importsOf(file)) {
        if (!spec.startsWith('.')) continue
        const target = resolve(join(file, '..'), spec)
        const to = moduleOf(target)
        if (!MODULES.includes(to) || to === from) continue
        if (to === 'core') continue // 任何模块都可依赖 core
        violations.push(`${relative(SRC, file)} → ${to} (${spec})`)
      }
    }
    expect(violations).toEqual([])
  })

  test('core 零外部运行时依赖(仅裸导入白名单)', () => {
    const allowed = new Set(['bun:test'])
    const violations: string[] = []
    for (const file of files.filter((f) => moduleOf(f) === 'core')) {
      for (const spec of importsOf(file)) {
        if (spec.startsWith('.') || spec.startsWith('node:')) continue
        if (!allowed.has(spec)) violations.push(`${relative(SRC, file)} → ${spec}`)
      }
    }
    expect(violations).toEqual([])
  })
})
