import { createHash } from 'node:crypto'
import { types as utilTypes } from 'node:util'
import {
  AUDIT_LIMITS,
  normalizeAuditRepoPath,
} from './audit-core.js'

export interface ReviewCoverageInventoryTuple {
  marker: string
  path: string
}

const GENERATED_PROOF = 'GENERATED-PROOF'
const COVERAGE_PATH = '.atlas/review-coverage.json'
const SHA1_RE = /^[0-9a-f]{40}$/

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function hasLoneSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index)
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!Number.isFinite(next) || next < 0xdc00 || next > 0xdfff) {
        return true
      }
      index += 1
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true
    }
  }
  return false
}

function dataProperty(
  value: object,
  key: string,
  context: string,
): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key)
  if (
    descriptor === undefined ||
    !('value' in descriptor) ||
    !descriptor.enumerable
  ) {
    throw new Error(
      `review coverage inventory ${context} must be an enumerable data property`,
    )
  }
  return descriptor.value
}

function snapshotInventoryTuples(
  input: readonly ReviewCoverageInventoryTuple[],
): ReviewCoverageInventoryTuple[] {
  if (
    utilTypes.isProxy(input) ||
    !Array.isArray(input) ||
    Object.getPrototypeOf(input) !== Array.prototype
  ) {
    throw new Error(
      'review coverage inventory must be a plain dense array',
    )
  }
  if (
    !Number.isSafeInteger(input.length) ||
    input.length > AUDIT_LIMITS.collectionItems
  ) {
    throw new Error('review coverage inventory exceeds its tuple bound')
  }
  if (
    Object.getOwnPropertySymbols(input).length !== 0 ||
    Object.getOwnPropertyNames(input).length !== input.length + 1
  ) {
    throw new Error(
      'review coverage inventory must be dense and have no extra properties',
    )
  }

  const paths = new Set<string>()
  const tuples: ReviewCoverageInventoryTuple[] = []
  let totalCodeUnits = 0
  let totalBytes = 0
  for (let index = 0; index < input.length; index += 1) {
    const tuple = dataProperty(
      input,
      String(index),
      `tuple ${index}`,
    )
    if (
      tuple === null ||
      typeof tuple !== 'object' ||
      utilTypes.isProxy(tuple) ||
      Array.isArray(tuple) ||
      Object.getPrototypeOf(tuple) !== Object.prototype
    ) {
      throw new Error(
        `review coverage inventory tuple ${index} must be a plain object`,
      )
    }
    const keys = Reflect.ownKeys(tuple)
    if (
      keys.length !== 2 ||
      !keys.includes('marker') ||
      !keys.includes('path')
    ) {
      throw new Error(
        `review coverage inventory tuple ${index} must contain exactly marker and path`,
      )
    }
    const marker = dataProperty(tuple, 'marker', `tuple ${index} marker`)
    const repoPath = dataProperty(tuple, 'path', `tuple ${index} path`)
    if (
      typeof marker !== 'string' ||
      (marker !== GENERATED_PROOF && !SHA1_RE.test(marker))
    ) {
      throw new Error(
        `review coverage inventory tuple ${index} marker must be a lowercase SHA-1 or GENERATED-PROOF`,
      )
    }
    if (
      typeof repoPath !== 'string' ||
      repoPath.length > AUDIT_LIMITS.textCodeUnits ||
      hasLoneSurrogate(repoPath) ||
      repoPath.normalize('NFC') !== repoPath
    ) {
      throw new Error(
        `review coverage inventory tuple ${index} path exceeds its bound or is invalid Unicode`,
      )
    }
    let normalized: string
    try {
      normalized = normalizeAuditRepoPath(repoPath)
    } catch {
      throw new Error(
        `review coverage inventory tuple ${index} path must be normalized and repository-relative`,
      )
    }
    if (
      (normalized === COVERAGE_PATH) !==
        (marker === GENERATED_PROOF)
    ) {
      throw new Error(
        `review coverage inventory tuple ${index} must reserve GENERATED-PROOF for ${COVERAGE_PATH}`,
      )
    }
    if (paths.has(normalized)) {
      throw new Error(
        `review coverage inventory tuple ${index} repeats a path`,
      )
    }
    paths.add(normalized)
    totalCodeUnits += marker.length + normalized.length
    totalBytes +=
      Buffer.byteLength(marker, 'utf8') +
      Buffer.byteLength(normalized, 'utf8')
    if (
      totalCodeUnits > AUDIT_LIMITS.textTotalCodeUnits ||
      totalBytes > AUDIT_LIMITS.jsonBytes
    ) {
      throw new Error(
        'review coverage inventory exceeds its aggregate text bound',
      )
    }
    tuples.push({ marker, path: normalized })
  }
  return tuples
}

function lengthPrefix(value: number): Buffer {
  const prefix = Buffer.allocUnsafe(8)
  prefix.writeBigUInt64BE(BigInt(value))
  return prefix
}

/**
 * Canonical V1 inventory identity. Existing line-safe inventories retain the
 * normative `sorted "<blob>  <path>" lines + final LF` wire digest. A distinct
 * framed domain is used only when CR/LF would make that legacy representation
 * ambiguous. GENERATED-PROOF remains a marker value in either encoding.
 */
export function reviewCoverageInventoryHash(
  input: readonly ReviewCoverageInventoryTuple[],
): string {
  const snapshot = snapshotInventoryTuples(input)
  if (snapshot.every((tuple) =>
    !/[\r\n]/u.test(tuple.marker) && !/[\r\n]/u.test(tuple.path))) {
    const lines = snapshot
      .map((tuple) => `${tuple.marker}  ${tuple.path}`)
      .sort(compareText)
    return createHash('sha256')
      .update(`${lines.join('\n')}\n`, 'utf8')
      .digest('hex')
  }

  const tuples = snapshot.map((tuple) => ({
    marker: tuple.marker,
    path: tuple.path,
  })).sort((left, right) =>
    compareText(left.marker, right.marker) ||
    compareText(left.path, right.path))
  const hash = createHash('sha256')
    .update('atlas-review-coverage-inventory-v1-framed\0', 'utf8')
    .update(lengthPrefix(tuples.length))
  for (const tuple of tuples) {
    const marker = Buffer.from(tuple.marker, 'utf8')
    const repoPath = Buffer.from(tuple.path, 'utf8')
    hash
      .update(lengthPrefix(marker.byteLength))
      .update(marker)
      .update(lengthPrefix(repoPath.byteLength))
      .update(repoPath)
  }
  return hash.digest('hex')
}
