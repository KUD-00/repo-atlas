import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { storedSemanticManifestError } from './semantic-manifest.mjs'

export const isRating = (value) => Number.isInteger(value) && value >= 1 && value <= 5
const SHA256 = /^[0-9a-f]{64}$/u

function antipatternError(value) {
  if (!Array.isArray(value) || value.length > 3) return 'antipatterns must be an array with at most 3 entries'
  if (!value.every((item) => item && typeof item === 'object' &&
      typeof item.kind === 'string' && typeof item.where === 'string' && typeof item.why === 'string')) {
    return 'each antipattern must contain string kind, where, and why fields'
  }
  return null
}

export function semanticAgentResponseError(response) {
  if (!response || typeof response !== 'object') return 'agent response must be an object'
  if (!Object.hasOwn(response, 'naming') || !isRating(response.naming)) return 'naming must be an integer from 1 to 5'
  if (!Object.hasOwn(response, 'commentCoherence') || !(response.commentCoherence === null || isRating(response.commentCoherence))) {
    return 'commentCoherence must be present and null or an integer from 1 to 5'
  }
  const antiError = antipatternError(response.antipatterns)
  if (antiError) return antiError
  if (typeof response.barrel !== 'boolean') return 'barrel must be boolean'
  if (typeof response.reason !== 'string') return 'reason must be a string'
  return null
}

export function semanticRowError(row, expectedPath, expectedSourceHash = null) {
  if (!row || typeof row !== 'object') return 'row must be an object'
  if (row.path !== expectedPath) return `row.path ${JSON.stringify(row.path)} does not match ${JSON.stringify(expectedPath)}`
  if (!SHA256.test(row.sourceHash ?? '')) return 'sourceHash must be a lowercase SHA-256'
  if (expectedSourceHash !== null && row.sourceHash !== expectedSourceHash) return 'sourceHash does not match the sampled source bytes'
  if (Object.hasOwn(row, 'error')) return typeof row.error === 'string' && row.error ? row.error : 'row.error is not allowed'
  if (!isRating(row.naming)) return 'naming must be an integer from 1 to 5'
  if (!(row.commentCoherence === null || isRating(row.commentCoherence))) return 'commentCoherence must be null or an integer from 1 to 5'
  const antiError = antipatternError(row.antipatterns)
  if (antiError) return antiError
  if (typeof row.barrel !== 'boolean') return 'barrel must be boolean'
  if (typeof row.reason !== 'string') return 'reason must be a string'
  return null
}

export function semanticDocumentError(document, expectedPath, manifest = null) {
  if (!document || typeof document !== 'object' || !Array.isArray(document.rows) || document.rows.length !== 1) {
    return 'document must contain exactly one rows[] entry'
  }
  if (manifest) {
    const manifestError = storedSemanticManifestError(manifest)
    if (manifestError) return manifestError
    if (document.formatVersion !== 1) return 'document formatVersion must be 1'
    if (document.sampleHash !== manifest.sampleHash) return 'document sampleHash does not match the calibration sample'
    if (!(expectedPath in manifest.fileHashes)) return `path ${JSON.stringify(expectedPath)} is not in the calibration sample`
    return semanticRowError(document.rows[0], expectedPath, manifest.fileHashes[expectedPath])
  }
  return semanticRowError(document.rows[0], expectedPath)
}

const self = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
if (self) {
  const [, , file, expectedPath, manifestFile] = process.argv
  if (!file || !expectedPath) {
    console.error('usage: node semantic-result.mjs <result.json> <expected-path> [manifest.json]')
    process.exit(2)
  }
  let document, manifest = null
  try {
    document = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (manifestFile) manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'))
  } catch (error) {
    console.error(`invalid semantic evaluation: ${error instanceof Error ? error.message : String(error)}`)
    process.exit(1)
  }
  const error = semanticDocumentError(document, expectedPath, manifest)
  if (error) {
    console.error(`invalid semantic evaluation for ${expectedPath}: ${error}`)
    process.exit(1)
  }
}
