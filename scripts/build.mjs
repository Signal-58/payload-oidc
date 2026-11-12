#!/usr/bin/env node
import { spawnSync } from 'node:child_process'
import { existsSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'

/*
 * Builds dist/: ESM JavaScript and declarations from tsc, then makes every relative import fully
 * specified. The source imports without extensions (it was written for a bundler), but Payload's
 * CLI and job runner load the package through Node, which needs `./plugin.js`, not `./plugin`.
 */
const root = resolve(dirname(new URL(import.meta.url).pathname), '..')
const dist = join(root, 'dist')

rmSync(dist, { force: true, recursive: true })
const tsc = spawnSync('tsc', ['-p', 'tsconfig.build.json'], {
  cwd: root,
  shell: process.platform === 'win32',
  stdio: 'inherit',
})
if (tsc.status !== 0) process.exit(tsc.status ?? 1)

const files = (dir) =>
  readdirSync(dir, { withFileTypes: true }).flatMap((entry) =>
    entry.isDirectory() ? files(join(dir, entry.name)) : [join(dir, entry.name)],
  )

// `from '…'`, `import '…'` and `import('…')`, the only forms tsc emits for module specifiers.
const SPECIFIER = /(\bfrom\s*|\bimport\s*|\bimport\(\s*)(['"])(\.{1,2}\/[^'"]*)\2/g

const problems = []
for (const file of files(dist).filter((name) => /\.(js|d\.ts)$/.test(name))) {
  const source = readFileSync(file, 'utf8')
  const output = source.replace(SPECIFIER, (match, prefix, quote, specifier) => {
    if (specifier.endsWith('.js')) return match
    const base = resolve(dirname(file), specifier)
    const target = existsSync(`${base}.js`)
      ? `${specifier}.js`
      : existsSync(join(base, 'index.js'))
        ? `${specifier}/index.js`
        : undefined
    if (!target) {
      problems.push(`${relative(root, file)}: can't resolve ${specifier}`)
      return match
    }
    return `${prefix}${quote}${target}${quote}`
  })
  if (output !== source) writeFileSync(file, output)
}

// Next only treats the module as a client component if the directive comes first.
const client = readFileSync(join(dist, 'exports/client.js'), 'utf8')
if (!/^['"]use client['"];?\n/.test(client)) {
  problems.push("dist/exports/client.js: 'use client' isn't the first statement")
}

if (problems.length > 0) {
  console.error(problems.join('\n'))
  process.exit(1)
}
