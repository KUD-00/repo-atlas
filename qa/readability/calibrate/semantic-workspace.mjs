import { createHash, randomUUID } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const semanticWorkspaceBase = (calibrateDir) => path.join(calibrateDir, '.work', 'semantic')
export const semanticRepoKey = (repoRoot) => createHash('sha256').update(fs.realpathSync(repoRoot)).digest('hex').slice(0, 16)

export function workspaceForManifest(calibrateDir, manifest) {
  if (!manifest || !/^[0-9a-f]{64}$/u.test(manifest.sampleHash ?? '')) throw new Error('manifest has no valid sampleHash')
  const repoKey = semanticRepoKey(manifest.repoRoot)
  const repoDir = path.join(semanticWorkspaceBase(calibrateDir), repoKey)
  return { repoKey, repoDir, out: path.join(repoDir, manifest.sampleHash) }
}

export function writeCurrentWorkspace(calibrateDir, manifest) {
  const workspace = workspaceForManifest(calibrateDir, manifest)
  fs.mkdirSync(workspace.repoDir, { recursive: true })
  const target = path.join(workspace.repoDir, 'current.json')
  const temp = path.join(workspace.repoDir, `.current.${process.pid}.${randomUUID()}.tmp`)
  try {
    fs.writeFileSync(temp, JSON.stringify({
      formatVersion: 1,
      repoRoot: manifest.repoRoot,
      sampleHash: manifest.sampleHash,
    }, null, 2) + '\n', { flag: 'wx', mode: 0o600 })
    fs.renameSync(temp, target)
  } finally {
    try { fs.unlinkSync(temp) } catch {}
  }
  return workspace
}

export function currentWorkspace(calibrateDir, repoRoot) {
  const realRoot = fs.realpathSync(repoRoot)
  const repoKey = semanticRepoKey(realRoot)
  const repoDir = path.join(semanticWorkspaceBase(calibrateDir), repoKey)
  const pointer = JSON.parse(fs.readFileSync(path.join(repoDir, 'current.json'), 'utf8'))
  if (pointer?.formatVersion !== 1 || pointer.repoRoot !== realRoot || !/^[0-9a-f]{64}$/u.test(pointer.sampleHash ?? '')) {
    throw new Error('invalid current semantic workspace; run semantic-build.mjs')
  }
  return { repoKey, repoDir, out: path.join(repoDir, pointer.sampleHash) }
}

const self = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (self) {
  try {
    console.log(currentWorkspace(path.dirname(fileURLToPath(import.meta.url)), process.cwd()).out)
  } catch (error) {
    console.error(`semantic workspace unavailable: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
