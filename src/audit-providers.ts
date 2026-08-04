import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { TextDecoder } from 'node:util'
import {
  AUDIT_LIMITS,
  canonicalJson,
  normalizeAuditRepoPath,
  parseBoundedAuditJsonBytes,
  readBoundedAuditBytes,
  readBoundedAuditJsonDocument,
} from './audit-core.js'
import type {
  AuditGitBlob,
  AuditPromptReceiptV3,
  AuditProviderPhaseKind,
  AuditProviderRunReceiptV3,
  AuditProviderTranscriptChunkV3,
  AuditRulesetReceiptV3,
  AuditConfidence,
  AuditSeverity,
  AuditSha256,
} from './audit-v3-types.js'

// Provider orchestration for first-party audit producers.
//
// A provider is never invoked implicitly: the only entry point is
// runAuditProviderInvocation, which requires an explicit
// `audit run security` invocation request. No check/status/build/install path
// imports this module's runner. Clone-local resume/transcript state lives
// under `.atlas/.runtime/audit-runs/<invocationId>/` (gitignored, never
// coverage evidence); run receipts contain no wall-clock fields.

export const AUDIT_PROVIDER_INVOCATION_COMMAND = 'audit run security'
export const AUDIT_PROVIDER_PHASE_ORDER: readonly AuditProviderPhaseKind[] = [
  'inventory',
  'review',
  'verification',
  'synthesis',
]
export const AUDIT_PROVIDER_RUNTIME_PATH = '.atlas/.runtime/audit-runs'

const UTF8 = new TextDecoder('utf-8', { fatal: true })
const INVOCATION_ID_PATTERN = /^arun_[0-9a-f]{24}$/
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/
const SEVERITIES: readonly AuditSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'informational',
]
const DISPOSITIONS = [
  'reportable',
  'suppressed',
  'not_applicable',
  'deferred',
] as const
const CONFIDENCES: readonly AuditConfidence[] = ['high', 'medium', 'low']
const MAX_TEXT_BYTES = 256 * 1024
const MAX_BINARY_DIGEST_BYTES = 256 * 1024 * 1024
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024

export type AuditProviderErrorCode =
  | 'invalid-request'
  | 'policy-invalid'
  | 'preflight-rejected'
  | 'spawn-failed'
  | 'timeout'
  | 'signal'
  | 'exit-code'
  | 'output-limit'
  | 'output-invalid'
  | 'missing-file-receipt'
  | 'transcript-invalid'
  | 'transcript-mismatch'
  | 'snapshot-mismatch'
  | 'source-mutation'
  | 'resume-invalid'

export class AuditProviderError extends Error {
  readonly code: AuditProviderErrorCode
  readonly phase?: AuditProviderPhaseKind

  constructor(
    code: AuditProviderErrorCode,
    message: string,
    phase?: AuditProviderPhaseKind,
  ) {
    super(`audit provider ${code}: ${message}`)
    this.name = 'AuditProviderError'
    this.code = code
    this.phase = phase
  }
}

function fail(
  code: AuditProviderErrorCode,
  message: string,
  phase?: AuditProviderPhaseKind,
): never {
  throw new AuditProviderError(code, message, phase)
}

export type AuditProviderDisposition = (typeof DISPOSITIONS)[number]

export interface AuditProviderTarget {
  path: string
  role?: 'review' | 'context'
}

export interface AuditProviderSnapshotEntry {
  path: string
  role: 'review' | 'context'
  sha256: AuditSha256
  blob: AuditGitBlob
  bytes: number
  lines: number
}

export interface AuditProviderPolicyInput {
  command?: string
  model?: string
  concurrency?: number
  maxAttempts?: number
  maxBatchFiles?: number
  maxVerificationCandidates?: number
  timeoutMs?: number
  killGraceMs?: number
  maxFileBytes?: number
  maxSnapshotFiles?: number
  maxStdoutBytes?: number
  maxStderrBytes?: number
  maxResponseBytes?: number
  maxResponseDepth?: number
  maxTranscriptBytes?: number
  maxTranscriptEvents?: number
  maxPromptBytes?: number
  maxFindingsPerFile?: number
  apiKeyEnv?: string
  authRecordPath?: string
  approvedConfigDigests?: AuditSha256[]
}

export interface AuditProviderPolicy {
  command: string
  model: string
  concurrency: number
  maxAttempts: number
  maxBatchFiles: number
  maxVerificationCandidates: number
  timeoutMs: number
  killGraceMs: number
  maxFileBytes: number
  maxSnapshotFiles: number
  maxStdoutBytes: number
  maxStderrBytes: number
  maxResponseBytes: number
  maxResponseDepth: number
  maxTranscriptBytes: number
  maxTranscriptEvents: number
  maxPromptBytes: number
  maxFindingsPerFile: number
  apiKeyEnv?: string
  authRecordPath: string
  approvedConfigDigests: AuditSha256[]
}

export interface AuditProviderInvocationRequest {
  command: typeof AUDIT_PROVIDER_INVOCATION_COMMAND
  provider: 'grok'
  repoRoot: string
  policy: AuditProviderPolicy
  targets: readonly AuditProviderTarget[]
  extraPrompt?: string
  resumeInvocationId?: string
}

export interface AuditProviderDescriptor {
  provider: 'grok'
  adapter: string
  adapterVersion: string
  rulesetId: string
  promptBuiltinVersion: string
  promptTemplateDigest: AuditSha256
  tools: readonly string[]
  permissionFlags: readonly string[]
}

export interface AuditProvider {
  readonly name: string
  readonly descriptor: AuditProviderDescriptor
  run(context: AuditProviderContext): Promise<AuditProviderResult>
}

export interface AuditProviderContext {
  repoRoot: string
  snapshotRoot: string
  invocationId: string
  policy: AuditProviderPolicy
  prompt: string
  targets: AuditProviderSnapshotEntry[]
  resumeDir: string
  tempRoot: string
  resumeSourceDir?: string
  snapshotManifestDigest: AuditSha256
  inventoryDigest: AuditSha256
  ruleset: AuditRulesetReceiptV3
  promptReceipt: AuditPromptReceiptV3
  environmentPolicyDigest: AuditSha256
  providerDescriptor: AuditProviderDescriptor
  signal: AbortSignal
  assertSnapshotIntact(): void
  manifestEntry(repoPath: string): AuditProviderSnapshotEntry | undefined
}

export interface AuditProviderCandidateFinding {
  fingerprint: string
  ruleId: string
  title: string
  severity: AuditSeverity
  confidence: AuditConfidence
  summary: string
  path: string
  startLine: number
  endLine?: number
  detail: string
  fix: string
}

export interface AuditProviderFinding extends AuditProviderCandidateFinding {
  disposition: AuditProviderDisposition
  dispositionRationale: string
}

export interface AuditProviderFileOutcome {
  path: string
  blob: AuditGitBlob
  lines: number
  status: 'reviewed'
  outcome: 'clean' | 'findings'
  findingFingerprints: string[]
}

export interface AuditProviderResult {
  status: 'completed'
  invocationId: string
  resumedFromInvocationId?: string
  files: AuditProviderFileOutcome[]
  findings: AuditProviderFinding[]
  receipt: AuditProviderRunReceiptV3
  reusedChunks: string[]
  executedChunks: string[]
}

export interface AuditProviderReviewReceipt {
  path: string
  status: 'reviewed'
  outcome: 'clean' | 'findings'
  summary: string
  findings: Array<{
    ruleId: string
    title: string
    severity: AuditSeverity
    confidence: AuditConfidence
    summary: string
    startLine: number
    endLine?: number
    detail: string
    fix: string
  }>
}

export interface AuditProviderReviewUnitOutput {
  receipts: AuditProviderReviewReceipt[]
}

export interface AuditProviderVerificationUnitOutput {
  dispositions: Array<{
    fingerprint: string
    disposition: AuditProviderDisposition
    rationale: string
  }>
}

export interface AuditProviderInventoryFacts {
  binaryVersion: string
  binaryDigest: AuditSha256
  effectiveConfigDigest: AuditSha256
  probeDigests: AuditSha256[]
}

export interface AuditProviderUnitExecution<TOutput> {
  output: TOutput
  processCount: number
  sessionIds: string[]
  transcriptDigests: AuditSha256[]
}

export interface AuditProviderReviewUnit {
  unit: string
  index: number
  files: AuditProviderSnapshotEntry[]
  /**
   * 1 on the first try, incremented per retry. A retry used to re-send the
   * byte-identical prompt, so a model that answered about a path it invented
   * kept inventing it and burned every attempt on the same wrong answer. The
   * handler uses this to add a corrective instruction naming the required paths.
   */
  attempt: number
}

export interface AuditProviderVerificationUnit {
  unit: string
  index: number
  candidates: AuditProviderCandidateFinding[]
  files: AuditProviderSnapshotEntry[]
}

export interface AuditProviderSynthesisInput {
  reviewOutputs: AuditProviderReviewUnitOutput[]
  verificationOutputs: AuditProviderVerificationUnitOutput[]
  candidates: AuditProviderCandidateFinding[]
}

export interface AuditProviderSynthesisOutput {
  files: AuditProviderFileOutcome[]
  findings: AuditProviderFinding[]
}

export interface AuditProviderPhaseHandlers {
  inventory(
    context: AuditProviderContext,
  ): Promise<AuditProviderUnitExecution<AuditProviderInventoryFacts>>
  review(
    context: AuditProviderContext,
    unit: AuditProviderReviewUnit,
  ): Promise<AuditProviderUnitExecution<AuditProviderReviewUnitOutput>>
  verification(
    context: AuditProviderContext,
    unit: AuditProviderVerificationUnit,
  ): Promise<AuditProviderUnitExecution<AuditProviderVerificationUnitOutput>>
  synthesize(
    context: AuditProviderContext,
    input: AuditProviderSynthesisInput,
  ): AuditProviderSynthesisOutput
}

function sha256Hex(bytes: Uint8Array | string): string {
  return createHash('sha256').update(bytes).digest('hex')
}

export function auditProviderSha256(bytes: Uint8Array | string): AuditSha256 {
  return `sha256:${sha256Hex(bytes)}`
}

function canonicalDigest(value: unknown): AuditSha256 {
  return auditProviderSha256(canonicalJson(value))
}

function gitBlobId(bytes: Uint8Array): AuditGitBlob {
  const digest = createHash('sha1')
    .update(`blob ${bytes.byteLength}\0`, 'utf8')
    .update(bytes)
    .digest('hex')
  return `git-sha1:${digest}`
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  )
}

function boundedText(value: unknown, description: string): string {
  if (typeof value !== 'string' || value.length === 0) {
    fail('output-invalid', `${description} must be a nonempty string`)
  }
  if (value.includes('\0') || Buffer.byteLength(value, 'utf8') > MAX_TEXT_BYTES) {
    fail('output-invalid', `${description} exceeds the ${MAX_TEXT_BYTES}-byte limit`)
  }
  return value
}

function optionalBoundedText(value: unknown, description: string): string | undefined {
  if (value === undefined) return undefined
  return boundedText(value, description)
}

// ---------------------------------------------------------------------------
// Provider policy
// ---------------------------------------------------------------------------

function policyInteger(
  input: unknown,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (input === undefined) return fallback
  if (
    typeof input !== 'number' ||
    !Number.isSafeInteger(input) ||
    input < minimum ||
    input > maximum
  ) {
    fail(
      'policy-invalid',
      `provider policy ${name} must be an integer between ${minimum} and ${maximum}`,
    )
  }
  return input
}

export function resolveAuditProviderPolicy(
  input: AuditProviderPolicyInput,
): AuditProviderPolicy {
  if (!isPlainObject(input)) {
    fail('policy-invalid', 'provider policy must be a plain object')
  }
  const values: AuditProviderPolicyInput = input
  const command = values.command ?? 'grok'
  if (typeof command !== 'string' || command.length === 0 || command.includes('\0')) {
    fail('policy-invalid', 'provider policy command must be a nonempty path or name')
  }
  if (
    typeof values.model !== 'string' ||
    values.model.length === 0 ||
    values.model.includes('\0') ||
    Buffer.byteLength(values.model, 'utf8') > 1024
  ) {
    fail(
      'policy-invalid',
      'provider policy requires an explicit model identifier',
    )
  }
  const model = values.model
  const concurrency = policyInteger(
    values.concurrency,
    'concurrency',
    Math.max(1, Math.min(4, os.cpus().length)),
    1,
    64,
  )
  // Attempts, not retries: 1 reproduces the previous abort-on-first-failure.
  const maxAttempts = policyInteger(values.maxAttempts, 'maxAttempts', 3, 1, 5)
  const policy: AuditProviderPolicy = {
    command,
    model,
    concurrency,
    maxAttempts,
    maxBatchFiles: policyInteger(values.maxBatchFiles, 'maxBatchFiles', 8, 1, 500),
    maxVerificationCandidates: policyInteger(
      values.maxVerificationCandidates,
      'maxVerificationCandidates',
      10,
      1,
      500,
    ),
    timeoutMs: policyInteger(values.timeoutMs, 'timeoutMs', 600_000, 50, 3_600_000),
    killGraceMs: policyInteger(values.killGraceMs, 'killGraceMs', 5_000, 50, 60_000),
    maxFileBytes: policyInteger(values.maxFileBytes, 'maxFileBytes', 4 * 1024 * 1024, 1, 64 * 1024 * 1024),
    maxSnapshotFiles: policyInteger(values.maxSnapshotFiles, 'maxSnapshotFiles', 4_096, 1, 100_000),
    maxStdoutBytes: policyInteger(values.maxStdoutBytes, 'maxStdoutBytes', 8 * 1024 * 1024, 1_024, 64 * 1024 * 1024),
    maxStderrBytes: policyInteger(values.maxStderrBytes, 'maxStderrBytes', 1024 * 1024, 1_024, 16 * 1024 * 1024),
    maxResponseBytes: policyInteger(values.maxResponseBytes, 'maxResponseBytes', 1024 * 1024, 1_024, 16 * 1024 * 1024),
    maxResponseDepth: policyInteger(values.maxResponseDepth, 'maxResponseDepth', 48, 4, 256),
    maxTranscriptBytes: policyInteger(values.maxTranscriptBytes, 'maxTranscriptBytes', 16 * 1024 * 1024, 1_024, 64 * 1024 * 1024),
    maxTranscriptEvents: policyInteger(values.maxTranscriptEvents, 'maxTranscriptEvents', 8_192, 1, 1_000_000),
    maxPromptBytes: policyInteger(values.maxPromptBytes, 'maxPromptBytes', 512 * 1024, 1_024, 4 * 1024 * 1024),
    maxFindingsPerFile: policyInteger(values.maxFindingsPerFile, 'maxFindingsPerFile', 64, 1, 1_024),
    authRecordPath: '.grok/auth.json',
    approvedConfigDigests: [],
  }
  if (values.apiKeyEnv !== undefined) {
    if (!ENV_NAME_PATTERN.test(values.apiKeyEnv)) {
      fail('policy-invalid', 'provider policy apiKeyEnv must be an environment variable name')
    }
    policy.apiKeyEnv = values.apiKeyEnv
  }
  if (values.authRecordPath !== undefined) {
    try {
      normalizeAuditRepoPath(values.authRecordPath)
    } catch {
      fail('policy-invalid', 'provider policy authRecordPath must be a safe home-relative path')
    }
    policy.authRecordPath = values.authRecordPath
  }
  if (values.approvedConfigDigests !== undefined) {
    if (
      !Array.isArray(values.approvedConfigDigests) ||
      values.approvedConfigDigests.length > 1_024 ||
      values.approvedConfigDigests.some(
        (digest) => typeof digest !== 'string' || !SHA256_PATTERN.test(digest),
      )
    ) {
      fail(
        'policy-invalid',
        'provider policy approvedConfigDigests must be a bounded list of sha256 digests',
      )
    }
    policy.approvedConfigDigests = [...values.approvedConfigDigests] as AuditSha256[]
  }
  return policy
}

const PROVIDER_POLICY_PATH = '.atlas/audit-providers.json'
const PROVIDER_POLICY_KEYS = new Set([
  'formatVersion',
  'format',
  'provider',
  'command',
  'model',
  'concurrency',
  'maxAttempts',
  'maxBatchFiles',
  'maxVerificationCandidates',
  'timeoutMs',
  'killGraceMs',
  'maxFileBytes',
  'maxSnapshotFiles',
  'maxStdoutBytes',
  'maxStderrBytes',
  'maxResponseBytes',
  'maxResponseDepth',
  'maxTranscriptBytes',
  'maxTranscriptEvents',
  'maxPromptBytes',
  'maxFindingsPerFile',
  'apiKeyEnv',
  'authRecordPath',
  'approvedConfigDigests',
])

export function loadAuditProviderPolicy(root: string): AuditProviderPolicyInput | null {
  let document: { bytes: Uint8Array; value: unknown }
  try {
    document = readBoundedAuditJsonDocument(root, PROVIDER_POLICY_PATH, 1024 * 1024)
  } catch (error) {
    const code =
      error && typeof error === 'object' && 'code' in error
        ? String((error as NodeJS.ErrnoException).code)
        : undefined
    if (
      code === 'ENOENT' ||
      code === 'ENOTDIR' ||
      (error instanceof Error &&
        (error.message.includes('is missing or not a safe regular file') ||
          error.message.includes('audit parent is missing')))
    ) {
      return null
    }
    throw error
  }
  const value = document.value
  if (!isPlainObject(value)) {
    fail('policy-invalid', `${PROVIDER_POLICY_PATH} must be a plain JSON object`)
  }
  for (const key of Object.keys(value)) {
    if (!PROVIDER_POLICY_KEYS.has(key)) {
      fail('policy-invalid', `${PROVIDER_POLICY_PATH} has unknown field ${key}`)
    }
  }
  if (value.formatVersion !== 1 || value.format !== 'atlas-audit-providers/v1') {
    fail(
      'policy-invalid',
      `${PROVIDER_POLICY_PATH} must declare format atlas-audit-providers/v1`,
    )
  }
  if (value.provider !== 'grok') {
    fail('policy-invalid', `${PROVIDER_POLICY_PATH} provider must be "grok"`)
  }
  if (typeof value.model !== 'string' || value.model.length === 0) {
    fail('policy-invalid', `${PROVIDER_POLICY_PATH} requires an explicit model`)
  }
  const input: AuditProviderPolicyInput = { model: value.model }
  for (const key of [
    'command',
    'apiKeyEnv',
    'authRecordPath',
  ] as const) {
    if (value[key] !== undefined) {
      if (typeof value[key] !== 'string') {
        fail('policy-invalid', `${PROVIDER_POLICY_PATH} ${key} must be a string`)
      }
      input[key] = value[key] as string
    }
  }
  for (const key of [
    'concurrency',
  'maxAttempts',
    'maxBatchFiles',
    'maxVerificationCandidates',
    'timeoutMs',
    'killGraceMs',
    'maxFileBytes',
    'maxSnapshotFiles',
    'maxStdoutBytes',
    'maxStderrBytes',
    'maxResponseBytes',
    'maxResponseDepth',
    'maxTranscriptBytes',
    'maxTranscriptEvents',
    'maxPromptBytes',
    'maxFindingsPerFile',
  ] as const) {
    if (value[key] !== undefined) input[key] = value[key] as number
  }
  if (value.approvedConfigDigests !== undefined) {
    input.approvedConfigDigests = value.approvedConfigDigests as AuditSha256[]
  }
  // Reuse the resolver for range/shape validation, then return the sparse input.
  resolveAuditProviderPolicy(input)
  return input
}

// ---------------------------------------------------------------------------
// Invocation request validation (structural explicitness)
// ---------------------------------------------------------------------------

function validateResolvedPolicy(policy: AuditProviderPolicy): void {
  if (!isPlainObject(policy)) {
    fail('policy-invalid', 'resolved provider policy must be a plain object')
  }
  resolveAuditProviderPolicy(policy)
}

function validateInvocationRequest(
  request: AuditProviderInvocationRequest,
): AuditProviderTarget[] {
  if (!isPlainObject(request)) {
    fail('invalid-request', 'provider invocation must be an explicit request object')
  }
  if (request.command !== AUDIT_PROVIDER_INVOCATION_COMMAND) {
    fail(
      'invalid-request',
      `providers run only through an explicit \`${AUDIT_PROVIDER_INVOCATION_COMMAND}\` request`,
    )
  }
  if (request.provider !== 'grok') {
    fail('invalid-request', 'the only first-party provider is "grok"')
  }
  if (
    typeof request.repoRoot !== 'string' ||
    request.repoRoot.length === 0 ||
    request.repoRoot.includes('\0')
  ) {
    fail('invalid-request', 'provider invocation repoRoot must be a nonempty path')
  }
  validateResolvedPolicy(request.policy)
  if (!Array.isArray(request.targets) || request.targets.length === 0) {
    fail('invalid-request', 'provider invocation requires an explicit nonempty target list')
  }
  if (request.targets.length > request.policy.maxSnapshotFiles) {
    fail(
      'invalid-request',
      `provider invocation exceeds the ${request.policy.maxSnapshotFiles}-file snapshot limit`,
    )
  }
  const seen = new Set<string>()
  const targets: AuditProviderTarget[] = []
  for (const rawTarget of request.targets) {
    if (!isPlainObject(rawTarget)) {
      fail('invalid-request', 'provider invocation targets must be plain objects')
    }
    const target = rawTarget as unknown as AuditProviderTarget
    let normalized: string
    try {
      normalized = normalizeAuditRepoPath(typeof target.path === 'string' ? target.path : '')
    } catch {
      fail('invalid-request', `provider target path is unsafe: ${String(target.path)}`)
    }
    if (seen.has(normalized)) {
      fail('invalid-request', `provider target path is duplicated: ${normalized}`)
    }
    seen.add(normalized)
    const role = target.role ?? 'review'
    if (role !== 'review' && role !== 'context') {
      fail('invalid-request', `provider target role is unsupported: ${String(target.role)}`)
    }
    targets.push({ path: normalized, role })
  }
  if (!targets.some((target) => target.role === 'review')) {
    fail('invalid-request', 'provider invocation requires at least one review target')
  }
  if (request.extraPrompt !== undefined) {
    if (
      typeof request.extraPrompt !== 'string' ||
      request.extraPrompt.includes('\0') ||
      Buffer.byteLength(request.extraPrompt, 'utf8') > request.policy.maxPromptBytes
    ) {
      fail('invalid-request', 'provider invocation extraPrompt is not bounded text')
    }
  }
  if (
    request.resumeInvocationId !== undefined &&
    !INVOCATION_ID_PATTERN.test(request.resumeInvocationId)
  ) {
    fail('invalid-request', 'provider resume id must be an atlas run id (arun_...)')
  }
  return targets
}

function validateProviderShape(provider: AuditProvider, requestProvider: string): void {
  if (!isPlainObject(provider) || typeof provider.run !== 'function') {
    fail('invalid-request', 'provider must implement the AuditProvider interface')
  }
  if (provider.name !== requestProvider) {
    fail(
      'invalid-request',
      `provider ${String(provider.name)} does not match the explicit request for ${requestProvider}`,
    )
  }
  const descriptor = provider.descriptor
  if (!isPlainObject(descriptor) || descriptor.provider !== requestProvider) {
    fail('invalid-request', 'provider descriptor does not match the explicit request')
  }
  if (
    typeof descriptor.adapter !== 'string' ||
    typeof descriptor.adapterVersion !== 'string' ||
    typeof descriptor.rulesetId !== 'string' ||
    typeof descriptor.promptBuiltinVersion !== 'string' ||
    typeof descriptor.promptTemplateDigest !== 'string' ||
    !SHA256_PATTERN.test(descriptor.promptTemplateDigest) ||
    !Array.isArray(descriptor.tools) ||
    descriptor.tools.some((tool) => typeof tool !== 'string') ||
    !Array.isArray(descriptor.permissionFlags) ||
    descriptor.permissionFlags.some((flag) => typeof flag !== 'string')
  ) {
    fail('invalid-request', 'provider descriptor is incomplete')
  }
}

// ---------------------------------------------------------------------------
// Snapshot discipline
// ---------------------------------------------------------------------------

interface AuditProviderSnapshotManifest {
  formatVersion: 1
  format: 'atlas-audit-snapshot/v1'
  files: AuditProviderSnapshotEntry[]
}

function countLines(bytes: Uint8Array, repoPath: string): number {
  let text: string
  try {
    text = UTF8.decode(bytes)
  } catch {
    fail('invalid-request', `provider target is not strict UTF-8 text: ${repoPath}`)
  }
  if (text.length === 0) return 0
  let lines = 0
  for (let index = 0; index < text.length; index += 1) {
    if (text.charCodeAt(index) === 0x0a) lines += 1
  }
  return text.endsWith('\n') ? lines : lines + 1
}

function createProviderSnapshot(
  repoRoot: string,
  targets: readonly AuditProviderTarget[],
  snapshotRoot: string,
  policy: AuditProviderPolicy,
): AuditProviderSnapshotEntry[] {
  const directories: string[] = [snapshotRoot]
  fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o755 })
  const entries: AuditProviderSnapshotEntry[] = []
  for (const target of targets) {
    const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes)
    const destination = path.join(snapshotRoot, ...target.path.split('/'))
    const parent = path.dirname(destination)
    if (!fs.existsSync(parent)) {
      fs.mkdirSync(parent, { recursive: true, mode: 0o755 })
      let current = parent
      while (current !== snapshotRoot && current.startsWith(snapshotRoot)) {
        directories.push(current)
        current = path.dirname(current)
      }
    }
    fs.writeFileSync(destination, bytes, { mode: 0o444 })
    fs.chmodSync(destination, 0o444)
    entries.push({
      path: target.path,
      role: target.role ?? 'review',
      sha256: auditProviderSha256(bytes),
      blob: gitBlobId(bytes),
      bytes: bytes.byteLength,
      lines: countLines(bytes, target.path),
    })
  }
  entries.sort((left, right) => left.path.localeCompare(right.path))
  for (const directory of directories) {
    fs.chmodSync(directory, 0o555)
  }
  return entries
}

function buildSnapshotManifest(
  entries: readonly AuditProviderSnapshotEntry[],
): AuditProviderSnapshotManifest {
  return {
    formatVersion: 1,
    format: 'atlas-audit-snapshot/v1',
    files: [...entries],
  }
}

function assertSnapshotIntact(
  snapshotRoot: string,
  manifest: AuditProviderSnapshotManifest,
  policy: AuditProviderPolicy,
): void {
  const discovered: string[] = []
  const walk = (directory: string, relative: string): void => {
    let children: fs.Dirent[]
    try {
      children = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      fail('snapshot-mismatch', `snapshot directory is unreadable: ${relative || '.'}`)
    }
    if (discovered.length + children.length > policy.maxSnapshotFiles + 64) {
      fail('snapshot-mismatch', 'snapshot contains unexpected extra entries')
    }
    for (const child of children) {
      const childRelative = relative ? `${relative}/${child.name}` : child.name
      const childPath = path.join(directory, child.name)
      if (child.isDirectory()) {
        const stat = fs.lstatSync(childPath)
        if ((stat.mode & 0o222) !== 0) {
          fail('snapshot-mismatch', `snapshot directory became writable: ${childRelative}`)
        }
        walk(childPath, childRelative)
      } else if (child.isFile()) {
        discovered.push(childRelative)
      } else {
        fail('snapshot-mismatch', `snapshot entry is not a regular file: ${childRelative}`)
      }
    }
  }
  walk(snapshotRoot, '')
  const expected = new Map(manifest.files.map((entry) => [entry.path, entry]))
  if (discovered.length !== expected.size) {
    fail('snapshot-mismatch', 'snapshot file count differs from the canonical manifest')
  }
  for (const repoPath of discovered) {
    const entry = expected.get(repoPath)
    if (entry === undefined) {
      fail('snapshot-mismatch', `snapshot contains an unexpected file: ${repoPath}`)
    }
    const absolute = path.join(snapshotRoot, ...repoPath.split('/'))
    const stat = fs.lstatSync(absolute)
    if (stat.isSymbolicLink() || !stat.isFile()) {
      fail('snapshot-mismatch', `snapshot file changed type: ${repoPath}`)
    }
    if ((stat.mode & 0o222) !== 0) {
      fail('snapshot-mismatch', `snapshot file became writable: ${repoPath}`)
    }
    if (Number(stat.size) !== entry.bytes) {
      fail('snapshot-mismatch', `snapshot file changed size: ${repoPath}`)
    }
    const bytes = fs.readFileSync(absolute)
    if (auditProviderSha256(bytes) !== entry.sha256) {
      fail('snapshot-mismatch', `snapshot bytes changed for ${repoPath}`)
    }
  }
}

function hashOriginalTargets(
  repoRoot: string,
  targets: readonly AuditProviderTarget[],
  policy: AuditProviderPolicy,
): Map<string, AuditSha256> {
  const hashes = new Map<string, AuditSha256>()
  for (const target of targets) {
    const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes)
    hashes.set(target.path, auditProviderSha256(bytes))
  }
  return hashes
}

function assertOriginalsUnchanged(
  repoRoot: string,
  targets: readonly AuditProviderTarget[],
  policy: AuditProviderPolicy,
  before: Map<string, AuditSha256>,
): void {
  for (const target of targets) {
    let digest: AuditSha256
    try {
      const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes)
      digest = auditProviderSha256(bytes)
    } catch {
      fail(
        'source-mutation',
        `tracked source ${target.path} became unreadable during the provider run`,
      )
    }
    if (digest !== before.get(target.path)) {
      fail(
        'source-mutation',
        `tracked source bytes changed during the provider run: ${target.path}`,
      )
    }
  }
}

// ---------------------------------------------------------------------------
// Clone-local journal
// ---------------------------------------------------------------------------

interface AuditProviderJournal {
  formatVersion: 1
  format: 'atlas-audit-provider-journal/v1'
  invocationId: string
  provider: 'grok'
  status: 'running' | 'completed' | 'failed'
  chunks: string[]
  failure?: { code: string; message: string }
}

function journalPath(resumeDir: string): string {
  return path.join(resumeDir, 'journal.json')
}

function chunkFilePath(resumeDir: string, chunkId: string): string {
  return path.join(resumeDir, 'chunks', `${chunkId}.json`)
}

function writeJournalFile(resumeDir: string, journal: AuditProviderJournal): void {
  const destination = journalPath(resumeDir)
  const temporary = `${destination}.tmp-${process.pid}`
  fs.writeFileSync(temporary, `${canonicalJson(journal)}\n`, { mode: 0o600 })
  fs.renameSync(temporary, destination)
  fs.chmodSync(destination, 0o600)
}

function writeChunkRecord(
  resumeDir: string,
  chunk: AuditProviderTranscriptChunkV3,
  output: unknown,
): void {
  const chunksDir = path.join(resumeDir, 'chunks')
  fs.mkdirSync(chunksDir, { recursive: true, mode: 0o700 })
  const destination = chunkFilePath(resumeDir, chunk.chunkId)
  const record = {
    formatVersion: 1,
    format: 'atlas-audit-provider-chunk/v1',
    chunk,
    output,
  }
  const temporary = `${destination}.tmp-${process.pid}`
  fs.writeFileSync(temporary, `${canonicalJson(record)}\n`, { mode: 0o600 })
  fs.renameSync(temporary, destination)
  fs.chmodSync(destination, 0o600)
}

interface AuditProviderChunkRecord {
  chunk: AuditProviderTranscriptChunkV3
  output: unknown
}

function readChunkRecord(
  resumeDir: string,
  chunkId: string,
): AuditProviderChunkRecord | null {
  let bytes: Uint8Array
  try {
    bytes = fs.readFileSync(chunkFilePath(resumeDir, chunkId))
  } catch {
    return null
  }
  if (bytes.byteLength > MAX_JOURNAL_BYTES) return null
  let value: unknown
  try {
    value = parseBoundedAuditJsonBytes(bytes, MAX_JOURNAL_BYTES, 'provider chunk')
  } catch {
    return null
  }
  if (!isPlainObject(value)) return null
  if (value.formatVersion !== 1 || value.format !== 'atlas-audit-provider-chunk/v1') {
    return null
  }
  if (!isPlainObject(value.chunk) || value.output === undefined) return null
  return {
    chunk: value.chunk as unknown as AuditProviderTranscriptChunkV3,
    output: value.output,
  }
}

function validateResumeSource(resumeSourceDir: string, invocationId: string): void {
  let bytes: Uint8Array
  try {
    bytes = fs.readFileSync(journalPath(resumeSourceDir))
  } catch {
    fail(
      'resume-invalid',
      `resume source ${invocationId} has no readable clone-local journal`,
    )
  }
  let value: unknown
  try {
    value = parseBoundedAuditJsonBytes(bytes, MAX_JOURNAL_BYTES, 'provider journal')
  } catch {
    fail('resume-invalid', `resume source ${invocationId} journal is not valid JSON`)
  }
  if (
    !isPlainObject(value) ||
    value.formatVersion !== 1 ||
    value.format !== 'atlas-audit-provider-journal/v1' ||
    value.invocationId !== invocationId
  ) {
    fail('resume-invalid', `resume source ${invocationId} journal is not a matching run`)
  }
}

// ---------------------------------------------------------------------------
// Chunk digests and resume
// ---------------------------------------------------------------------------

function chunkContentDigest(
  chunk: Omit<AuditProviderTranscriptChunkV3, 'digest'>,
): AuditSha256 {
  return canonicalDigest(chunk)
}

function makeChunk(
  phase: AuditProviderPhaseKind,
  unit: string,
  inputDigest: AuditSha256,
  execution: { output: unknown; processCount: number; sessionIds: string[]; transcriptDigests: AuditSha256[] },
): AuditProviderTranscriptChunkV3 {
  const chunkId = `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}`
  const base = {
    chunkId,
    phase,
    unit,
    inputDigest,
    outputDigest: canonicalDigest(execution.output),
    processCount: execution.processCount,
    sessionIds: [...execution.sessionIds],
    transcriptDigests: [...execution.transcriptDigests],
  }
  return { ...base, digest: chunkContentDigest(base) }
}

function verifyChunkRecord(
  record: AuditProviderChunkRecord,
  phase: AuditProviderPhaseKind,
  unit: string,
  inputDigest: AuditSha256,
): boolean {
  const { chunk, output } = record
  if (
    chunk.chunkId !== `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}` ||
    chunk.phase !== phase ||
    chunk.unit !== unit ||
    chunk.inputDigest !== inputDigest ||
    !SHA256_PATTERN.test(chunk.digest) ||
    !SHA256_PATTERN.test(chunk.outputDigest) ||
    !Array.isArray(chunk.sessionIds) ||
    !Array.isArray(chunk.transcriptDigests)
  ) {
    return false
  }
  const { digest, ...rest } = chunk
  if (chunkContentDigest(rest) !== digest) return false
  return canonicalDigest(output) === chunk.outputDigest
}

// ---------------------------------------------------------------------------
// Unit output validation (fail-closed, reused for fresh and resumed outputs)
// ---------------------------------------------------------------------------

export function validateAuditProviderReviewUnitOutput(
  output: unknown,
  files: readonly AuditProviderSnapshotEntry[],
  policy: AuditProviderPolicy,
  /**
   * Resolves a path against the run's inventory. Without it every off-batch
   * receipt is treated as unverifiable, which is the conservative default for
   * callers that cannot check.
   */
  inventoryHas?: (path: string) => boolean,
): AuditProviderReviewUnitOutput {
  if (!isPlainObject(output) || !Array.isArray(output.receipts)) {
    fail('output-invalid', 'review unit output must be an object with a receipts array', 'review')
  }
  const expected = new Map(files.map((file) => [file.path, file]))
  const seen = new Set<string>()
  const receipts: AuditProviderReviewReceipt[] = []
  /** Real files this batch did not own; kept, and owned by whichever batch has them. */
  const offBatchReceipts: string[] = []
  /** Paths that exist nowhere. Rejected individually and reported. */
  const fabricatedReceipts: string[] = []
  for (const raw of output.receipts) {
    if (!isPlainObject(raw)) {
      fail('output-invalid', 'review receipt must be a plain object', 'review')
    }
    const receiptPath = typeof raw.path === 'string' ? raw.path : ''
    const file = expected.get(receiptPath)
    if (file === undefined) {
      // Two very different things used to share one hard failure.
      //
      // A receipt for a REAL file outside this batch is a genuine review of a
      // genuine file — another batch owns its coverage, so this one keeps the
      // observation and moves on. Discarding it would throw away work; failing
      // on it aborts a completed run over a bookkeeping detail.
      //
      // A receipt for a path that exists nowhere in the inventory is a
      // fabrication, and it is the one case that must not be absorbed quietly:
      // the generator invented `capabilities/devices/index.ts`,
      // `capabilities/packets/index.ts`, and `capabilities/votes.test.ts` on
      // three separate runs, none of which exist. That single receipt is
      // rejected and recorded; the rest of the unit still stands or falls on its
      // own proof.
      if (receiptPath !== '' && inventoryHas?.(receiptPath) === true) {
        offBatchReceipts.push(receiptPath)
        continue
      }
      fabricatedReceipts.push(receiptPath || '<missing>')
      continue
    }
    if (seen.has(receiptPath)) {
      fail('missing-file-receipt', `duplicate review receipt for ${receiptPath}`, 'review')
    }
    seen.add(receiptPath)
    if (raw.status !== 'reviewed') {
      fail('output-invalid', `review receipt for ${receiptPath} is not marked reviewed`, 'review')
    }
    if (raw.outcome !== 'clean' && raw.outcome !== 'findings') {
      fail('output-invalid', `review receipt for ${receiptPath} has an invalid outcome`, 'review')
    }
    if (!Array.isArray(raw.findings) || raw.findings.length > policy.maxFindingsPerFile) {
      fail('output-invalid', `review receipt for ${receiptPath} has unbounded findings`, 'review')
    }
    if (raw.outcome === 'findings' && raw.findings.length === 0) {
      fail('output-invalid', `findings review receipt for ${receiptPath} carries none`, 'review')
    }
    // A clean receipt may still list the candidates the model evaluated:
    // every listed candidate flows to independent verification, and the
    // terminal disposition decides. Synthesis rejects a candidate the fact
    // checker confirms reportable on a clean receipt as a contradiction;
    // terminally non-reportable candidates are preserved as evidence.
    const findings: AuditProviderReviewReceipt['findings'] = []
    for (const rawFinding of raw.findings) {
      if (!isPlainObject(rawFinding)) {
        fail('output-invalid', `finding on ${receiptPath} must be a plain object`, 'review')
      }
      const severity = rawFinding.severity as AuditSeverity
      if (!SEVERITIES.includes(severity)) {
        fail('output-invalid', `finding on ${receiptPath} has an invalid severity`, 'review')
      }
      const confidence = rawFinding.confidence as AuditConfidence
      if (!CONFIDENCES.includes(confidence)) {
        fail('output-invalid', `finding on ${receiptPath} has an invalid confidence`, 'review')
      }
      const startLine = rawFinding.startLine
      if (typeof startLine !== 'number' || !Number.isSafeInteger(startLine) || startLine < 1 || startLine > Math.max(1, file.lines)) {
        // Carry the numbers: "out of range" alone cannot tell a hallucinated
        // citation from an off-by-one at EOF, and re-running a provider to find
        // out costs a whole audit run.
        fail(
          'output-invalid',
          `finding on ${receiptPath} has an out-of-range startLine (observed ${String(
            startLine,
          )}, file has ${String(file.lines)} lines)`,
          'review',
        )
      }
      let endLine: number | undefined
      if (rawFinding.endLine !== undefined) {
        if (
          typeof rawFinding.endLine !== 'number' ||
          !Number.isSafeInteger(rawFinding.endLine) ||
          rawFinding.endLine < startLine ||
          rawFinding.endLine > Math.max(1, file.lines)
        ) {
          fail(
            'output-invalid',
            `finding on ${receiptPath} has an out-of-range endLine (observed ${String(
              rawFinding.endLine,
            )}, startLine ${String(startLine)}, file has ${String(file.lines)} lines)`,
            'review',
          )
        }
        endLine = rawFinding.endLine
      }
      findings.push({
        ruleId: boundedText(rawFinding.ruleId, `finding ruleId on ${receiptPath}`),
        title: boundedText(rawFinding.title, `finding title on ${receiptPath}`),
        severity,
        confidence,
        summary: boundedText(rawFinding.summary, `finding summary on ${receiptPath}`),
        startLine,
        ...(endLine !== undefined ? { endLine } : {}),
        detail: boundedText(rawFinding.detail, `finding detail on ${receiptPath}`),
        fix: boundedText(rawFinding.fix, `finding fix on ${receiptPath}`),
      })
    }
    receipts.push({
      path: receiptPath,
      status: 'reviewed',
      outcome: raw.outcome,
      summary: boundedText(raw.summary, `review summary for ${receiptPath}`),
      findings,
    })
  }
  // Visible, not swallowed: an inventory-absent path is a fabrication, and the
  // operator has to be able to see that a unit produced one even though the run
  // continued past it.
  if (fabricatedReceipts.length > 0) {
    process.stderr.write(
      `audit provider warning: rejected ${String(
        fabricatedReceipts.length,
      )} receipt(s) for path(s) absent from the inventory: ${fabricatedReceipts.join(', ')}\n`,
    )
  }
  if (offBatchReceipts.length > 0) {
    process.stderr.write(
      `audit provider note: ${String(
        offBatchReceipts.length,
      )} receipt(s) named real files owned by another batch, which covers them: ${offBatchReceipts.join(
        ', ',
      )}\n`,
    )
  }
  for (const file of files) {
    if (!seen.has(file.path)) {
      fail(
        'missing-file-receipt',
        `review output is missing the required receipt for ${file.path}`,
        'review',
      )
    }
  }
  return { receipts }
}

export function validateAuditProviderVerificationUnitOutput(
  output: unknown,
  candidates: readonly AuditProviderCandidateFinding[],
  policy: AuditProviderPolicy,
): AuditProviderVerificationUnitOutput {
  void policy
  if (!isPlainObject(output) || !Array.isArray(output.dispositions)) {
    fail(
      'output-invalid',
      'verification unit output must be an object with a dispositions array',
      'verification',
    )
  }
  const expected = new Set(candidates.map((candidate) => candidate.fingerprint))
  const seen = new Set<string>()
  const dispositions: AuditProviderVerificationUnitOutput['dispositions'] = []
  for (const raw of output.dispositions) {
    if (!isPlainObject(raw)) {
      fail('output-invalid', 'verification disposition must be a plain object', 'verification')
    }
    const fingerprint = typeof raw.fingerprint === 'string' ? raw.fingerprint : ''
    if (!expected.has(fingerprint)) {
      fail(
        'output-invalid',
        `verification output references an unknown candidate: ${fingerprint || '<missing>'}`,
        'verification',
      )
    }
    if (seen.has(fingerprint)) {
      fail('output-invalid', `duplicate verification disposition for ${fingerprint}`, 'verification')
    }
    seen.add(fingerprint)
    if (!DISPOSITIONS.includes(raw.disposition as AuditProviderDisposition)) {
      fail('output-invalid', `verification disposition for ${fingerprint} is not terminal`, 'verification')
    }
    dispositions.push({
      fingerprint,
      disposition: raw.disposition as AuditProviderDisposition,
      rationale: boundedText(raw.rationale, `verification rationale for ${fingerprint}`),
    })
  }
  for (const candidate of candidates) {
    if (!seen.has(candidate.fingerprint)) {
      fail(
        'output-invalid',
        `verification output is missing a terminal disposition for ${candidate.fingerprint}`,
        'verification',
      )
    }
  }
  return { dispositions }
}

// ---------------------------------------------------------------------------
// Bounded parallel dispatch
// ---------------------------------------------------------------------------

/**
 * Provider failures that a second attempt can legitimately clear: the model
 * produced output this run could not validate. Every attempt is validated
 * identically, so a retry never accepts something the first attempt rejected —
 * it only gives a nondeterministic generator another chance to emit a fully
 * proven transcript.
 *
 * Deliberately narrow. `timeout` is excluded because an attempt already burned
 * the full per-process budget and the usual cause (a credential that needs
 * re-auth) does not clear by trying again; `spawn-failed` and policy/inventory
 * errors are deterministic.
 */
const RETRYABLE_PROVIDER_CODES = new Set([
  'transcript-invalid',
  'output-invalid',
  // Receipts that do not match the requested file set — an extra file, or a
  // missing one — are the same failure in a different shape: the generator
  // answered a question other than the one asked. Leaving this out meant a
  // model naming one file outside its batch still aborted a completed run.
  'missing-file-receipt',
])

function isRetryableProviderFailure(error: unknown): boolean {
  return (
    error instanceof AuditProviderError && RETRYABLE_PROVIDER_CODES.has(error.code)
  )
}

async function boundedMapUnits<T, R>(
  items: readonly T[],
  concurrency: number,
  signal: AbortSignal,
  fn: (item: T, index: number, attempt: number) => Promise<R>,
  maxAttempts = 1,
): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let next = 0
  let firstFailure: unknown
  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    async () => {
      while (next < items.length && firstFailure === undefined && !signal.aborted) {
        const index = next
        next += 1
        let attempt = 0
        for (;;) {
          attempt += 1
          try {
            results[index] = await fn(items[index], index, attempt)
            break
          } catch (error) {
            // One unit's unvalidatable output used to abort the whole run, so a
            // corpus large enough to make model variance likely could never
            // finish: every remaining unit had to succeed on the same pass.
            if (
              attempt < maxAttempts &&
              !signal.aborted &&
              isRetryableProviderFailure(error)
            ) {
              continue
            }
            if (firstFailure === undefined) firstFailure = error
            break
          }
        }
      }
    },
  )
  await Promise.all(workers)
  if (firstFailure !== undefined) throw firstFailure
  if (signal.aborted) {
    fail('spawn-failed', 'provider run was aborted')
  }
  return results
}

// ---------------------------------------------------------------------------
// Phase-graph driver
// ---------------------------------------------------------------------------

interface ChunkSlot {
  chunk: AuditProviderTranscriptChunkV3
  reused: boolean
}

export async function runAuditProviderPhases(
  context: AuditProviderContext,
  handlers: AuditProviderPhaseHandlers,
): Promise<AuditProviderResult> {
  const journal: AuditProviderJournal = {
    formatVersion: 1,
    format: 'atlas-audit-provider-journal/v1',
    invocationId: context.invocationId,
    provider: 'grok',
    status: 'running',
    chunks: [],
  }
  writeJournalFile(context.resumeDir, journal)

  const slots: ChunkSlot[] = []
  const reusedChunks: string[] = []
  const executedChunks: string[] = []
  const persistChunk = (
    chunk: AuditProviderTranscriptChunkV3,
    output: unknown,
    reused: boolean,
  ): void => {
    writeChunkRecord(context.resumeDir, chunk, output)
    journal.chunks.push(chunk.chunkId)
    writeJournalFile(context.resumeDir, journal)
    slots.push({ chunk, reused })
    if (reused) reusedChunks.push(chunk.chunkId)
    else executedChunks.push(chunk.chunkId)
  }

  const descriptor = context.providerDescriptor
  const policy = context.policy

  const resumeSourceDir = context.resumeSourceDir
  const tryResume = <TOutput>(
    phase: AuditProviderPhaseKind,
    unit: string,
    inputDigest: AuditSha256,
    revalidate: (output: unknown) => TOutput,
  ): { chunk: AuditProviderTranscriptChunkV3; output: TOutput } | null => {
    if (resumeSourceDir === undefined) return null
    const chunkId = `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}`
    const record = readChunkRecord(resumeSourceDir, chunkId)
    if (record === null) return null
    if (!verifyChunkRecord(record, phase, unit, inputDigest)) return null
    let output: TOutput
    try {
      output = revalidate(record.output)
    } catch {
      return null
    }
    return { chunk: record.chunk, output }
  }

  // Phase 1: inventory — always executed fresh so the binary, version, and
  // effective configuration are established in this environment.
  context.assertSnapshotIntact()
  const inventory = await handlers.inventory(context)
  if (
    !isPlainObject(inventory.output) ||
    typeof inventory.output.binaryVersion !== 'string' ||
    inventory.output.binaryVersion.length === 0 ||
    !SHA256_PATTERN.test(inventory.output.binaryDigest) ||
    !SHA256_PATTERN.test(inventory.output.effectiveConfigDigest) ||
    !Array.isArray(inventory.output.probeDigests)
  ) {
    fail('output-invalid', 'inventory facts are incomplete', 'inventory')
  }
  const inventoryFacts = inventory.output
  const inventoryInputDigest = canonicalDigest({
    namespace: 'repo-atlas/provider-chunk-input/v1',
    phase: 'inventory',
    unit: 'inventory',
    snapshotManifestDigest: context.snapshotManifestDigest,
    adapter: descriptor.adapter,
    adapterVersion: descriptor.adapterVersion,
    model: policy.model,
    binaryVersion: inventoryFacts.binaryVersion,
    binaryDigest: inventoryFacts.binaryDigest,
    effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
  })
  persistChunk(
    makeChunk('inventory', 'inventory', inventoryInputDigest, inventory),
    inventory.output,
    false,
  )
  context.assertSnapshotIntact()

  const sharedKeyMaterial = {
    promptDigest: context.promptReceipt.digest,
    promptTemplateDigest: descriptor.promptTemplateDigest,
    model: policy.model,
    adapter: descriptor.adapter,
    adapterVersion: descriptor.adapterVersion,
    binaryVersion: inventoryFacts.binaryVersion,
    effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
    environmentPolicyDigest: context.environmentPolicyDigest,
  }

  // Phase 2: parallel bounded review — one bounded process per batch.
  const reviewFiles = context.targets.filter((target) => target.role === 'review')
  // Slicing the sorted inventory groups siblings, and siblings share basenames:
  // this repository has 23 `index.ts` files under one directory and 147 overall,
  // so a batch could be eight files distinguishable only by parent directory.
  // Asking a generator to keep those apart is a prompt defect, and it showed as
  // one — a batch of same-named files kept emitting a receipt for the wrong
  // sibling, six attempts in a row across two runs, after the whole review phase
  // had otherwise completed.
  //
  // Files are placed into batches largest-basename-group first, each into the
  // emptiest batch that does not already hold its basename. A flat round-robin
  // is not enough: it front-loads the diverse groups and leaves the big group's
  // tail bunched in the final batches. Where a corpus cannot satisfy the
  // constraint — every file sharing one name — placement falls back to the
  // emptiest batch and simply batches as before.
  //
  // This changes no validation: every file is reviewed exactly once, and the
  // batch digest still pins its exact contents.
  const batchCount = Math.max(1, Math.ceil(reviewFiles.length / policy.maxBatchFiles))
  const batches: AuditProviderSnapshotEntry[][] = Array.from(
    { length: batchCount },
    () => [],
  )
  const basenameOf = (file: AuditProviderSnapshotEntry): string =>
    file.path.slice(file.path.lastIndexOf('/') + 1)
  const dirnameOf = (file: AuditProviderSnapshotEntry): string => {
    const cut = file.path.lastIndexOf('/')
    return cut === -1 ? '' : file.path.slice(0, cut)
  }
  const byBasename = new Map<string, AuditProviderSnapshotEntry[]>()
  for (const file of reviewFiles) {
    const group = byBasename.get(basenameOf(file)) ?? []
    group.push(file)
    byBasename.set(basenameOf(file), group)
  }
  const takenNames = batches.map(() => new Set<string>())
  const takenDirs = batches.map(() => new Set<string>())
  const ordered = [...byBasename.values()].sort((left, right) => right.length - left.length)
  // Two files look alike to a generator when they share a name OR sit in one
  // directory under a shared naming template. Both produce the same symptom: a
  // receipt for a plausible sibling that does not exist. A directory of 43
  // `<capability>.ts` / `<capability>.test.ts` pairs got a receipt for
  // `votes.test.ts` — there is no `votes` capability anywhere in the tree — in
  // place of the `artifacts.test.ts` it was given, identically on all three
  // attempts. Basename spreading alone does not reach that: those siblings have
  // distinct basenames.
  //
  // Placement therefore prefers a batch sharing neither the basename nor the
  // directory, falls back to one sharing only the directory, and finally to the
  // emptiest batch when a corpus leaves no choice.
  const place = (file: AuditProviderSnapshotEntry): number => {
    const name = basenameOf(file)
    const dir = dirnameOf(file)
    const pick = (allow: (index: number) => boolean): number => {
      let chosen = -1
      for (let index = 0; index < batches.length; index += 1) {
        if (batches[index]!.length >= policy.maxBatchFiles) continue
        if (!allow(index)) continue
        if (chosen === -1 || batches[index]!.length < batches[chosen]!.length) chosen = index
      }
      return chosen
    }
    const strict = pick(
      (index) => !takenNames[index]!.has(name) && !takenDirs[index]!.has(dir),
    )
    if (strict !== -1) return strict
    const byName = pick((index) => !takenNames[index]!.has(name))
    if (byName !== -1) return byName
    return pick(() => true)
  }
  for (const group of ordered) {
    for (const file of group) {
      const chosen = place(file)
      batches[chosen]!.push(file)
      takenNames[chosen]!.add(basenameOf(file))
      takenDirs[chosen]!.add(dirnameOf(file))
    }
  }
  const inventoryHas = (candidate: string): boolean =>
    context.targets.some((target) => target.path === candidate)
  const reviewKey = (unit: string, files: readonly AuditProviderSnapshotEntry[]): AuditSha256 =>
    canonicalDigest({
      namespace: 'repo-atlas/provider-chunk-input/v1',
      phase: 'review',
      unit,
      files: files.map((file) => ({
        path: file.path,
        sha256: file.sha256,
        lines: file.lines,
      })),
      ...sharedKeyMaterial,
    })
  const reviewExecutions = await boundedMapUnits(
    batches,
    policy.concurrency,
    context.signal,
    async (files, index, attempt) => {
      const unit = `review:${index}`
      const inputDigest = reviewKey(unit, files)
      const resumed = tryResume('review', unit, inputDigest, (output) =>
        validateAuditProviderReviewUnitOutput(output, files, policy, inventoryHas),
      )
      if (resumed !== null) {
        persistChunk(resumed.chunk, resumed.output, true)
        return resumed.output
      }
      // `attempt` deliberately does NOT enter `inputDigest`: the chunk identity
      // must stay the input identity, so a corrected retry resumes as the same
      // chunk instead of forking a second cache entry for the same batch.
      const execution = await handlers.review(context, { unit, index, files, attempt })
      const output = validateAuditProviderReviewUnitOutput(
        execution.output,
        files,
        policy,
        inventoryHas,
      )
      persistChunk(
        makeChunk('review', unit, inputDigest, { ...execution, output }),
        output,
        false,
      )
      return output
    },
    policy.maxAttempts,
  )
  context.assertSnapshotIntact()

/**
 * Stable anchor for a finding: the normalized SOURCE TEXT it points at.
 *
 * Identity used to hash `startLine`, `endLine` and the generator's `title`. Both
 * are unstable across runs for an unchanged issue — any edit or reformat above a
 * finding shifts its lines, and the title is model prose that gets reworded — so
 * every scan minted a fresh id and no disposition ever carried. Measured on a
 * real repository: of 169 findings carrying a canonical fingerprint, ZERO matched
 * a prior decision, which turned "prove one fix" into "re-disposition everything".
 *
 * Hashing the flagged text instead gives the identity the properties it needs:
 *  - lines shift, text does not      -> same id, disposition carries
 *  - the model rewords the title     -> same id
 *  - the flagged code actually changes -> NEW id, which is correct: a changed
 *    construct deserves a fresh review rather than an inherited verdict
 *
 * Whitespace is collapsed so a formatter cannot rotate identity. When the range
 * cannot be read (out-of-range line, unreadable snapshot) this falls back to the
 * line numbers so identity stays deterministic instead of throwing — that case is
 * no more stable than the old scheme, but it is no less.
 */
function findingAnchorDigest(
  snapshotRoot: string,
  repoPath: string,
  startLine: number,
  endLine: number | undefined,
): string {
  const absolute = path.join(snapshotRoot, ...repoPath.split('/'))
  let text: string
  try {
    const lines = fs.readFileSync(absolute, 'utf8').split('\n')
    const from = Math.max(1, startLine)
    const to = Math.max(from, endLine ?? startLine)
    const slice = lines.slice(from - 1, to)
    if (slice.length === 0) throw new Error('range outside file')
    text = slice
      .map((line) => line.trim().replace(/\s+/gu, ' '))
      .filter((line) => line.length > 0)
      .join('\n')
    if (text.length === 0) throw new Error('range is blank')
  } catch {
    text = `unresolved-range:${String(startLine)}:${String(endLine ?? startLine)}`
  }
  return sha256Hex(text)
}

  // Deterministic candidate identity/dedupe between review and verification.
  const candidates: AuditProviderCandidateFinding[] = []
  const seenFingerprints = new Set<string>()
  for (const output of reviewExecutions) {
    const receipts = [...output.receipts].sort((left, right) =>
      left.path.localeCompare(right.path),
    )
    for (const receipt of receipts) {
      for (const finding of receipt.findings) {
        const fingerprint = `cand_${sha256Hex(
          canonicalJson({
            // v2: anchored to normalized source text instead of line numbers and
            // the model's title, so an unchanged issue keeps its identity.
            namespace: 'repo-atlas/provider-candidate/v2',
            ruleId: finding.ruleId,
            path: receipt.path,
            anchor: findingAnchorDigest(
              context.snapshotRoot,
              receipt.path,
              finding.startLine,
              finding.endLine,
            ),
          }),
        ).slice(0, 24)}`
        if (seenFingerprints.has(fingerprint)) continue
        seenFingerprints.add(fingerprint)
        candidates.push({
          fingerprint,
          ruleId: finding.ruleId,
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          summary: finding.summary,
          path: receipt.path,
          startLine: finding.startLine,
          ...(finding.endLine !== undefined ? { endLine: finding.endLine } : {}),
          detail: finding.detail,
          fix: finding.fix,
        })
      }
    }
  }

  // Phase 3: independent verification — bounded parallel fact checking.
  const verificationOutputs: AuditProviderVerificationUnitOutput[] = []
  if (candidates.length === 0) {
    const output: AuditProviderVerificationUnitOutput = { dispositions: [] }
    const inputDigest = canonicalDigest({
      namespace: 'repo-atlas/provider-chunk-input/v1',
      phase: 'verification',
      unit: 'verification',
      candidates: [],
      files: [],
      ...sharedKeyMaterial,
    })
    persistChunk(
      makeChunk('verification', 'verification', inputDigest, {
        output,
        processCount: 0,
        sessionIds: [],
        transcriptDigests: [],
      }),
      output,
      false,
    )
    verificationOutputs.push(output)
  } else {
    const units: AuditProviderVerificationUnit[] = []
    for (let index = 0; index < candidates.length; index += policy.maxVerificationCandidates) {
      const slice = candidates.slice(index, index + policy.maxVerificationCandidates)
      const unitIndex = units.length
      const files = [
        ...new Map(
          slice.map((candidate) => {
            const entry = context.manifestEntry(candidate.path)
            if (entry === undefined) {
              fail(
                'output-invalid',
                `candidate references a file outside the snapshot: ${candidate.path}`,
                'verification',
              )
            }
            return [candidate.path, entry] as const
          }),
        ).values(),
      ]
      units.push({ unit: `verification:${unitIndex}`, index: unitIndex, candidates: slice, files })
    }
    const verificationKey = (unit: AuditProviderVerificationUnit): AuditSha256 =>
      canonicalDigest({
        namespace: 'repo-atlas/provider-chunk-input/v1',
        phase: 'verification',
        unit: unit.unit,
        candidates: unit.candidates.map((candidate) => candidate.fingerprint),
        files: unit.files.map((file) => ({
          path: file.path,
          sha256: file.sha256,
          lines: file.lines,
        })),
        ...sharedKeyMaterial,
      })
    const executions = await boundedMapUnits(
      units,
      policy.concurrency,
      context.signal,
      async (unit) => {
        const inputDigest = verificationKey(unit)
        const resumed = tryResume('verification', unit.unit, inputDigest, (output) =>
          validateAuditProviderVerificationUnitOutput(output, unit.candidates, policy),
        )
        if (resumed !== null) {
          persistChunk(resumed.chunk, resumed.output, true)
          return resumed.output
        }
        const execution = await handlers.verification(context, unit)
        const output = validateAuditProviderVerificationUnitOutput(
          execution.output,
          unit.candidates,
          policy,
        )
        persistChunk(
          makeChunk('verification', unit.unit, inputDigest, { ...execution, output }),
          output,
          false,
        )
        return output
      },
      policy.maxAttempts,
    )
    verificationOutputs.push(...executions)
  }
  context.assertSnapshotIntact()

  // Phase 4: deterministic synthesis.
  const synthesis = handlers.synthesize(context, {
    reviewOutputs: reviewExecutions,
    verificationOutputs,
    candidates,
  })
  validateSynthesisOutput(context, synthesis, candidates)
  const synthesisInputDigest = canonicalDigest({
    namespace: 'repo-atlas/provider-chunk-input/v1',
    phase: 'synthesis',
    unit: 'synthesis',
    reviewChunkDigests: slots
      .filter((slot) => slot.chunk.phase === 'review')
      .map((slot) => slot.chunk.digest),
    verificationChunkDigests: slots
      .filter((slot) => slot.chunk.phase === 'verification')
      .map((slot) => slot.chunk.digest),
    ...sharedKeyMaterial,
  })
  const synthesisOutput = {
    files: synthesis.files,
    findings: synthesis.findings,
  }
  persistChunk(
    makeChunk('synthesis', 'synthesis', synthesisInputDigest, {
      output: synthesisOutput,
      processCount: 0,
      sessionIds: [],
      transcriptDigests: [],
    }),
    synthesisOutput,
    false,
  )
  context.assertSnapshotIntact()

  const orderedChunks = slots
    .map((slot) => slot.chunk)
    .sort(
      (left, right) =>
        AUDIT_PROVIDER_PHASE_ORDER.indexOf(left.phase) -
          AUDIT_PROVIDER_PHASE_ORDER.indexOf(right.phase) ||
        left.chunkId.localeCompare(right.chunkId),
    )
  const transcriptDigest = canonicalDigest(
    orderedChunks.map((chunk) => ({ chunkId: chunk.chunkId, digest: chunk.digest })),
  )
  const receiptBase = {
    formatVersion: 1,
    format: 'atlas-audit-provider-run/v1',
    provider: 'grok',
    adapter: descriptor.adapter,
    adapterVersion: descriptor.adapterVersion,
    invocationId: context.invocationId,
    ruleset: context.ruleset,
    prompt: context.promptReceipt,
    model: policy.model,
    effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
    environmentPolicyDigest: context.environmentPolicyDigest,
    snapshotManifestDigest: context.snapshotManifestDigest,
    inventoryDigest: context.inventoryDigest,
    chunks: orderedChunks,
    transcriptDigest,
  } as const
  const receipt: AuditProviderRunReceiptV3 = {
    ...receiptBase,
    receiptDigest: canonicalDigest(receiptBase),
  }
  journal.status = 'completed'
  writeJournalFile(context.resumeDir, journal)

  return {
    status: 'completed',
    invocationId: context.invocationId,
    files: synthesis.files,
    findings: synthesis.findings,
    receipt,
    reusedChunks,
    executedChunks,
  }
}

function validateSynthesisOutput(
  context: AuditProviderContext,
  synthesis: AuditProviderSynthesisOutput,
  candidates: readonly AuditProviderCandidateFinding[],
): void {
  const reviewTargets = context.targets.filter((target) => target.role === 'review')
  const byPath = new Map(synthesis.files.map((file) => [file.path, file]))
  if (byPath.size !== reviewTargets.length) {
    fail('missing-file-receipt', 'synthesis does not cover every review target exactly once', 'synthesis')
  }
  const knownFingerprints = new Set(candidates.map((candidate) => candidate.fingerprint))
  for (const target of reviewTargets) {
    const file = byPath.get(target.path)
    if (file === undefined) {
      fail('missing-file-receipt', `synthesis is missing ${target.path}`, 'synthesis')
    }
    if (file.blob !== target.blob || file.lines !== target.lines) {
      fail('output-invalid', `synthesis receipt drifted from the snapshot for ${target.path}`, 'synthesis')
    }
    for (const fingerprint of file.findingFingerprints) {
      if (!knownFingerprints.has(fingerprint)) {
        fail('output-invalid', `synthesis references an unknown finding on ${target.path}`, 'synthesis')
      }
    }
  }
  for (const finding of synthesis.findings) {
    if (!knownFingerprints.has(finding.fingerprint)) {
      fail('output-invalid', 'synthesis emitted an unknown finding', 'synthesis')
    }
  }
}

// ---------------------------------------------------------------------------
// Invocation entry point — the only way a provider process can start
// ---------------------------------------------------------------------------

export async function runAuditProviderInvocation(
  request: AuditProviderInvocationRequest,
  provider: AuditProvider,
): Promise<AuditProviderResult> {
  const targets = validateInvocationRequest(request)
  validateProviderShape(provider, request.provider)
  const policy = request.policy
  const repoRoot = path.resolve(request.repoRoot)
  const rootStat = fs.lstatSync(repoRoot, { throwIfNoEntry: false })
  if (!rootStat || rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
    fail('invalid-request', 'provider invocation repoRoot must be an existing safe directory')
  }

  const originalsBefore = hashOriginalTargets(repoRoot, targets, policy)

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-audit-run-'))
  fs.chmodSync(tempRoot, 0o700)
  const controller = new AbortController()
  let resumeDir: string | undefined
  let journalFailure: { code: string; message: string } | undefined

  try {
    const snapshotRoot = path.join(tempRoot, 'snapshot')
    const entries = createProviderSnapshot(repoRoot, targets, snapshotRoot, policy)
    const manifest = buildSnapshotManifest(entries)
    fs.writeFileSync(
      path.join(tempRoot, 'snapshot-manifest.json'),
      `${canonicalJson(manifest)}\n`,
      { mode: 0o444 },
    )
    const snapshotManifestDigest = canonicalDigest(manifest)
    const inventoryDigest = canonicalDigest({
      namespace: 'repo-atlas/provider-inventory/v1',
      files: entries.map((entry) => ({ path: entry.path, blob: entry.blob })),
    })

    const descriptor = provider.descriptor
    const extraPrompt = request.extraPrompt ?? ''
    const extraDigest = extraPrompt.length > 0 ? auditProviderSha256(extraPrompt) : undefined
    const promptDigest = canonicalDigest({
      namespace: 'repo-atlas/provider-prompt/v1',
      builtinVersion: descriptor.promptBuiltinVersion,
      templateDigest: descriptor.promptTemplateDigest,
      extraDigest: extraDigest ?? null,
    })
    const promptReceipt: AuditPromptReceiptV3 =
      extraDigest !== undefined
        ? {
            builtinVersion: descriptor.promptBuiltinVersion,
            digest: promptDigest,
            extraPath: '.atlas/pipeline/security.extra.md',
            extraDigest,
          }
        : {
            builtinVersion: descriptor.promptBuiltinVersion,
            digest: promptDigest,
          }
    // The ruleset identifies *how* a review was conducted — prompt, model, and
    // adapter. It deliberately excludes the run's file inventory: a decision
    // carries forward only while the ruleset digest matches, so folding the
    // inventory in here voided every disposition in a unit as soon as any file
    // in it was added, removed, or edited. Whether a specific finding still
    // describes its file is already answered by that finding's exact blob
    // binding, which is the check that actually protects the evidence. The
    // inventory stays recorded on the observation scope for provenance.
    const ruleset: AuditRulesetReceiptV3 = {
      id: descriptor.rulesetId,
      digest: canonicalDigest({
        namespace: 'repo-atlas/ruleset/v1',
        id: descriptor.rulesetId,
        domain: 'security',
        promptDigest,
        model: policy.model,
        adapter: descriptor.adapter,
        adapterVersion: descriptor.adapterVersion,
      }),
    }
    const environmentPolicyDigest = canonicalDigest({
      namespace: 'repo-atlas/provider-environment/v1',
      envAllowlist: [
        'LANG',
        'LC_ALL',
        'LC_CTYPE',
        'PATH',
        'TZ',
        ...(policy.apiKeyEnv !== undefined ? [policy.apiKeyEnv] : []),
      ].sort(),
      isolatedHome: true,
      homeMode: '0700',
      snapshotReadOnly: true,
      hardlinks: false,
      shell: false,
      tools: [...descriptor.tools].sort(),
      permissionFlags: [...descriptor.permissionFlags].sort(),
      limits: {
        concurrency: policy.concurrency,
        maxBatchFiles: policy.maxBatchFiles,
        timeoutMs: policy.timeoutMs,
        maxStdoutBytes: policy.maxStdoutBytes,
        maxStderrBytes: policy.maxStderrBytes,
        maxResponseBytes: policy.maxResponseBytes,
        maxTranscriptBytes: policy.maxTranscriptBytes,
      },
    })
    const invocationId = `arun_${sha256Hex(
      canonicalJson({
        namespace: 'repo-atlas/provider-run/v1',
        ruleset: ruleset.digest,
        snapshot: snapshotManifestDigest,
      }),
    ).slice(0, 24)}`

    resumeDir = path.join(repoRoot, AUDIT_PROVIDER_RUNTIME_PATH, invocationId)
    fs.mkdirSync(resumeDir, { recursive: true, mode: 0o700 })
    fs.chmodSync(resumeDir, 0o700)

    let resumeSourceDir: string | undefined
    if (request.resumeInvocationId !== undefined) {
      resumeSourceDir = path.join(
        repoRoot,
        AUDIT_PROVIDER_RUNTIME_PATH,
        request.resumeInvocationId,
      )
      validateResumeSource(resumeSourceDir, request.resumeInvocationId)
    }

    const manifestByPath = new Map(entries.map((entry) => [entry.path, entry]))
    const context: AuditProviderContext = {
      repoRoot,
      snapshotRoot,
      invocationId,
      policy,
      prompt: extraPrompt,
      targets: entries,
      resumeDir,
      tempRoot,
      snapshotManifestDigest,
      inventoryDigest,
      ruleset,
      promptReceipt,
      environmentPolicyDigest,
      providerDescriptor: descriptor,
      signal: controller.signal,
      assertSnapshotIntact: () => assertSnapshotIntact(snapshotRoot, manifest, policy),
      manifestEntry: (repoPath: string) => manifestByPath.get(repoPath),
      ...(resumeSourceDir !== undefined ? { resumeSourceDir } : {}),
    }

    try {
      const result = await provider.run(context)
      if (!isPlainObject(result) || result.status !== 'completed') {
        fail('output-invalid', 'provider returned an incomplete result')
      }
      if (result.invocationId !== invocationId) {
        fail('output-invalid', 'provider result does not match the allocated invocation id')
      }
      context.assertSnapshotIntact()
      assertOriginalsUnchanged(repoRoot, targets, policy, originalsBefore)
      fs.writeFileSync(
        path.join(resumeDir, 'receipt.json'),
        `${canonicalJson(result.receipt)}\n`,
        { mode: 0o600 },
      )
      if (request.resumeInvocationId !== undefined) {
        result.resumedFromInvocationId = request.resumeInvocationId
      }
      return result
    } catch (error) {
      controller.abort()
      assertOriginalsUnchanged(repoRoot, targets, policy, originalsBefore)
      const providerError =
        error instanceof AuditProviderError
          ? error
          : new AuditProviderError(
              'spawn-failed',
              error instanceof Error ? error.message : String(error),
            )
      journalFailure = { code: providerError.code, message: providerError.message }
      throw providerError
    } finally {
      if (journalFailure !== undefined && resumeDir !== undefined) {
        try {
          writeJournalFile(resumeDir, {
            formatVersion: 1,
            format: 'atlas-audit-provider-journal/v1',
            invocationId,
            provider: 'grok',
            status: 'failed',
            chunks: listExistingChunkIds(resumeDir),
            failure: journalFailure,
          })
        } catch {
          // The clone-local journal must never mask the primary failure.
        }
      }
    }
  } finally {
    removeProviderTempRoot(tempRoot)
  }
}

// Snapshot directories are read-only by design; restore writability before
// recursive deletion so cleanup cannot fail on our own isolation bits.
function removeProviderTempRoot(tempRoot: string): void {
  const restore = (directory: string): void => {
    let children: fs.Dirent[]
    try {
      children = fs.readdirSync(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const child of children) {
      if (child.isDirectory()) restore(path.join(directory, child.name))
    }
    try {
      fs.chmodSync(directory, 0o755)
    } catch {
      // Best effort; the rmSync below reports any remaining failure.
    }
  }
  // A failed run's evidence lives here and nowhere else: the prompts sent, the
  // session transcripts, and the isolated home. Deleting it on the way out means
  // the only way to ask "why did the generator answer that" is to reproduce and
  // race the cleanup. Set ATLAS_AUDIT_KEEP_RUN=1 to keep it.
  if (process.env.ATLAS_AUDIT_KEEP_RUN === '1') {
    process.stderr.write(`audit provider: keeping run root at ${tempRoot}\n`)
    return
  }
  try {
    restore(tempRoot)
    fs.rmSync(tempRoot, { recursive: true, force: true })
  } catch {
    // A stale temp root is clone-local scratch; never mask the run outcome.
  }
}

function listExistingChunkIds(resumeDir: string): string[] {
  const chunksDir = path.join(resumeDir, 'chunks')
  try {
    return fs
      .readdirSync(chunksDir)
      .filter((name) => name.endsWith('.json'))
      .map((name) => name.slice(0, -'.json'.length))
      .sort()
  } catch {
    return []
  }
}
