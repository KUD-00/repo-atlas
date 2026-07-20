import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export function makeRepo() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-test-'))
  execFileSync('git', ['init', '-q'], { cwd: root })
  execFileSync('git', ['config', 'user.email', 'repo-atlas-test@example.invalid'], { cwd: root })
  execFileSync('git', ['config', 'user.name', 'repo-atlas test'], { cwd: root })
  fs.mkdirSync(path.join(root, '.atlas', 'audits'), { recursive: true })
  fs.writeFileSync(path.join(root, '.atlas', 'config.json'), JSON.stringify({ formatVersion: 1, exclude: [] }) + '\n')
  return root
}

export function commitAll(root, message = 'fixture') {
  execFileSync('git', ['add', '-A'], { cwd: root })
  execFileSync('git', ['commit', '-qm', message], { cwd: root })
}

export function write(root, rel, contents) {
  const file = path.join(root, rel)
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, contents)
}

export function scopeHash(root, files) {
  const lines = files.map((file) => {
    const sha = execFileSync('git', ['hash-object', '--', file], { cwd: root, encoding: 'utf8' }).trim()
    return `${sha}  ${file}`
  }).sort()
  return createHash('sha1').update(lines.join('\n') + '\n').digest('hex')
}

export function cleanup(root) {
  fs.rmSync(root, { recursive: true, force: true })
}
