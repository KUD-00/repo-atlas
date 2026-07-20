import { createHash } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const SHA256 = /^[0-9a-f]{64}$/u

function sampleDigest(repoRoot, files, fileHashes) {
  const orderedHashes = Object.fromEntries(files.map((repoPath) => [repoPath, fileHashes[repoPath]]))
  return createHash('sha256').update(JSON.stringify({ repoRoot, files, fileHashes: orderedHashes })).digest('hex')
}

export function semanticFileListError(files) {
  if (!Array.isArray(files) || !files.length || !files.every((item) => typeof item === 'string' && item)) {
    return 'files.json must be a nonempty string array'
  }
  if (files.some((item) => path.isAbsolute(item) || item.includes('\\') || item.includes('\0') ||
      path.posix.normalize(item) !== item || item === '.' || item.startsWith('../'))) {
    return 'files.json paths must be normalized POSIX repository-relative paths'
  }
  if (new Set(files).size !== files.length) return 'files.json must not contain duplicate paths'
  return null
}

function openSafeRepoFile(repo, repoPath) {
  const root = fs.realpathSync(repo)
  if (typeof repoPath !== 'string' || !repoPath || path.isAbsolute(repoPath)) throw new Error(`unsafe semantic path: ${repoPath}`)
  const lexical = path.resolve(root, repoPath)
  if (lexical === root || !lexical.startsWith(root + path.sep)) throw new Error(`semantic path is outside repository: ${repoPath}`)
  let fd = null
  try {
    fd = fs.openSync(lexical, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0))
    const opened = fs.fstatSync(fd)
    const real = fs.realpathSync(lexical)
    const resolved = fs.statSync(real)
    if (!opened.isFile() || real !== lexical || real === root || !real.startsWith(root + path.sep) ||
        opened.dev !== resolved.dev || opened.ino !== resolved.ino) {
      throw new Error(`semantic path is not a regular in-repository file: ${repoPath}`)
    }
    return { fd, lexical, stat: opened }
  } catch (error) {
    if (fd !== null) fs.closeSync(fd)
    throw error
  }
}

export function safeRepoFile(repo, repoPath) {
  const opened = openSafeRepoFile(repo, repoPath)
  fs.closeSync(opened.fd)
  return opened.lexical
}

export function readSafeRepoFile(repo, repoPath) {
  const opened = openSafeRepoFile(repo, repoPath)
  try {
    const buffer = fs.readFileSync(opened.fd)
    const after = fs.fstatSync(opened.fd)
    if (buffer.length !== opened.stat.size || after.size !== opened.stat.size ||
        after.mtimeMs !== opened.stat.mtimeMs || after.ctimeMs !== opened.stat.ctimeMs) {
      throw new Error(`semantic source changed while it was being read: ${repoPath}`)
    }
    return buffer
  } finally {
    fs.closeSync(opened.fd)
  }
}

export function createSemanticManifest(repo, files) {
  const repoRoot = fs.realpathSync(repo)
  const listError = semanticFileListError(files)
  if (listError) throw new Error(listError)
  const fileHashes = Object.fromEntries(files.map((repoPath) => {
    return [repoPath, createHash('sha256').update(readSafeRepoFile(repoRoot, repoPath)).digest('hex')]
  }))
  const sampleHash = sampleDigest(repoRoot, files, fileHashes)
  return { formatVersion: 1, repoRoot, sampleHash, files, fileHashes }
}

export function storedSemanticManifestError(manifest) {
  if (!manifest || typeof manifest !== 'object' || manifest.formatVersion !== 1) return 'missing or unsupported semantic manifest'
  if (typeof manifest.repoRoot !== 'string' || !path.isAbsolute(manifest.repoRoot)) return 'manifest repoRoot must be absolute'
  const listError = semanticFileListError(manifest.files)
  if (listError) return listError
  if (!manifest.fileHashes || typeof manifest.fileHashes !== 'object' || Array.isArray(manifest.fileHashes)) return 'manifest fileHashes must be an object'
  const hashKeys = Object.keys(manifest.fileHashes)
  if (hashKeys.length !== manifest.files.length || manifest.files.some((repoPath) => !SHA256.test(manifest.fileHashes[repoPath] ?? ''))) {
    return 'manifest fileHashes must contain one lowercase SHA-256 for every sample path'
  }
  if (hashKeys.some((repoPath) => !manifest.files.includes(repoPath))) return 'manifest fileHashes contains an unexpected path'
  if (!SHA256.test(manifest.sampleHash ?? '')) return 'manifest sampleHash must be a lowercase SHA-256'
  if (manifest.sampleHash !== sampleDigest(manifest.repoRoot, manifest.files, manifest.fileHashes)) return 'manifest sampleHash does not match its stored sample'
  return null
}

export function semanticManifestError(manifest, current) {
  const storedError = storedSemanticManifestError(manifest)
  if (storedError) return storedError
  if (manifest.repoRoot !== current.repoRoot) return `manifest belongs to ${manifest.repoRoot}, current repository is ${current.repoRoot}`
  if (manifest.sampleHash !== current.sampleHash) return 'sample paths or file bytes changed; run semantic-build.mjs again'
  return null
}

const self = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (self) {
  const [, , manifestFile, filesFile] = process.argv
  if (!manifestFile || !filesFile) {
    console.error('usage: node semantic-manifest.mjs <manifest.json> <files.json>')
    process.exit(2)
  }
  try {
    const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'))
    const files = JSON.parse(fs.readFileSync(filesFile, 'utf8'))
    const listError = semanticFileListError(files)
    if (listError) throw new Error(listError)
    const current = createSemanticManifest(process.cwd(), files)
    const error = semanticManifestError(manifest, current)
    if (error) throw new Error(error)
  } catch (error) {
    console.error(`invalid semantic calibration manifest: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
}
