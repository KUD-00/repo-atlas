import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import {
  canonicalJson,
  normalizeAuditRepoPath,
  parseBoundedAuditJsonBytes,
} from './audit-core.js'
import {
  AuditProviderError,
  auditProviderSha256,
  runAuditProviderPhases,
  validateAuditProviderReviewUnitOutput,
  validateAuditProviderVerificationUnitOutput,
} from './audit-providers.js'
import type {
  AuditProvider,
  AuditProviderContext,
  AuditProviderFileOutcome,
  AuditProviderFinding,
  AuditProviderInventoryFacts,
  AuditProviderResult,
  AuditProviderReviewUnit,
  AuditProviderReviewUnitOutput,
  AuditProviderSnapshotEntry,
  AuditProviderSynthesisInput,
  AuditProviderSynthesisOutput,
  AuditProviderUnitExecution,
  AuditProviderVerificationUnit,
  AuditProviderVerificationUnitOutput,
} from './audit-providers.js'
import type { AuditProviderPhaseKind, AuditSha256 } from './audit-v3-types.js'

// Isolated first-party Grok CLI adapter (repo-atlas/grok-v1).
//
// Grok is never invoked implicitly: this adapter only runs inside
// runAuditProviderInvocation, which requires an explicit
// `audit run security` request. Every process runs with shell:false, exact
// argv, an allowlisted environment, an isolated mode-0700 HOME/XDG home, a
// read-only byte-copy source snapshot, bounded stdout/stderr, and an abort
// controller timeout. Session transcripts are parsed and validated before any
// output is accepted; failures stay clone-local and never publish.

export const GROK_ADAPTER_ID = 'repo-atlas/grok-v1'
export const GROK_ADAPTER_VERSION = '0.1.0'
export const GROK_SUPPORTED_CLI_VERSION = '0.2.82'
export const GROK_RULESET_ID = 'atlas-security-v3'
export const GROK_PROMPT_BUILTIN_VERSION = 'atlas-security-prompt-v1'
export const GROK_VALIDATION_RUBRIC_VERSION = 'atlas-security-validation-rubric-v1'

const GROK_TOOLS = ['Read', 'Grep', 'Glob'] as const
// The real tool names behind the argv allowlist, verified against live
// 0.2.82 sessions: with `--tools Read,Grep,Glob` the exposed tools are
// read_file, grep, and list_dir (no dedicated glob tool is exposed; the
// model uses list_dir for directory listings). Transcript tool calls use
// these snake_case names.
const GROK_TRANSCRIPT_TOOLS = new Map<string, (typeof GROK_TOOLS)[number]>([
  ['read_file', 'Read'],
  ['grep', 'Grep'],
  ['list_dir', 'Glob'],
])
// Spawn-able flag allowlist, verified against grok CLI 0.2.82 `--help`. Note
// that `-p, --single <PROMPT>` is deliberately absent: in 0.2.82 it requires
// an inline prompt value, and `--prompt-file` alone already selects the
// single-turn headless mode.
const GROK_PERMISSION_FLAGS = [
  '--no-plan',
  '--permission-mode',
  '--tools',
  '--no-memory',
  '--no-subagents',
  '--disable-web-search',
  '--output-format',
  '--model',
  '--session-id',
  '--cwd',
  '--prompt-file',
] as const

const AMBIENT_PROBE_ENV_KEYS = [
  'PATH',
  'HOME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'TMPDIR',
] as const
const ISOLATED_PASSTHROUGH_ENV_KEYS = ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'] as const

const MAX_BINARY_BYTES = 256 * 1024 * 1024
const MAX_PROBE_OUTPUT_BYTES = 1024 * 1024
const MAX_AUTH_RECORD_BYTES = 64 * 1024
const MAX_STDOUT_LINES = 65_536
const MAX_TOOL_ARGUMENT_BYTES = 16 * 1024
const PROBE_TIMEOUT_CAP_MS = 60_000

const GROK_REVIEW_PROMPT = `You are performing a READ-ONLY security audit of an exact byte snapshot of repository source files. This prompt is one bounded sub-review dispatched by the Repo Atlas orchestrator; sibling sub-reviews cover other files in parallel. The ruleset is atlas-security-v3.

## Hard constraints
- READ-ONLY. Use only the Read, Grep, and Glob tools. Never create, modify, or delete anything. Do not spawn subagents.
- Audit exactly the files listed in the ATLAS-UNIT block at the end of this prompt. Paths are relative to the snapshot root, which is your working directory.
- Your working directory IS the snapshot root. Never read, list, grep, or glob anything outside it: no parent directories, no absolute paths outside the snapshot, no home, temp, or system paths. Any such call aborts the audit.
- You must Read every listed file completely, from line 1 to its final line. read_file returns at most 1000 lines per call and does NOT warn when it caps: for any file with more than 1000 lines you MUST make multiple read_file calls with explicit offset/limit (for example offset 1 limit 1000, then offset 1001 limit 1000) so the chunks together cover every line; the transcript must prove full-range coverage.

## Method
1. Read each listed file fully before judging it.
2. For suspicious dataflows, follow a small number of call sites with Grep and Read; do not audit those neighboring files themselves.
3. Classify findings against the ruleset categories: authn-authz, crypto-signing, injection-sql-cmd-path-ssrf, template-injection-proto-pollution, input-validation-deserialization, secret-leakage, info-disclosure, webhook-idempotency-replay, money-integrity, rate-limiting-dos.

## Calibration
- Severities: informational (noteworthy, no action needed), low (defense-in-depth; unreachable from untrusted input today), medium (exploitable under realistic conditions), high (directly exploitable), critical (active compromise, RCE, or auth bypass).
- Only report issues with a concrete abuse path. No style nitpicks and no hypothetical framework CVEs.
- If a file is clean, mark it clean with a one-line summary of what you checked.

## Output contract
Your FINAL message must be ONLY a JSON object (no prose, no markdown fences) of this exact shape:
{"receipts":[{"path":"<file>","status":"reviewed","outcome":"clean"|"findings","summary":"<what you checked>","findings":[{"ruleId":"<category>/<rule>","title":"<one line>","severity":"informational"|"low"|"medium"|"high"|"critical","summary":"<short>","startLine":<n>,"endLine":<n>,"detail":"<abuse path>","fix":"<concrete fix>"}]}]}
Exactly one receipt per listed file; echo each path exactly as listed; every listed file must appear exactly once.`

const GROK_VERIFICATION_PROMPT = `You are an independent security fact checker working inside the same read-only snapshot discipline as the discovery pass. You receive candidate findings, the exact file inventory, and the validation rubric atlas-security-validation-rubric-v1. You do NOT receive the discovery transcript or its hidden reasoning; construct your own evidence trace.

## Hard constraints
- READ-ONLY. Use only the Read, Grep, and Glob tools. Never create, modify, or delete anything. Do not spawn subagents.
- Read every file listed in the ATLAS-UNIT block completely, from line 1 to its final line, before deciding any candidate that touches it. read_file returns at most 1000 lines per call and does NOT warn when it caps: for any file with more than 1000 lines you MUST make multiple read_file calls with explicit offset/limit so the chunks together cover every line.
- Your working directory IS the snapshot root. Never read, list, grep, or glob anything outside it: no parent directories, no absolute paths outside the snapshot, no home, temp, or system paths. Any such call aborts the audit.
- Verify each candidate against the exact snapshot bytes: confirm the code, the dataflow, and the preconditions yourself.

## Output contract
Give every candidate exactly one terminal disposition: reportable (the abuse path is real and in scope), suppressed (real but excluded by policy), not_applicable (the claim does not hold against these bytes), or deferred (cannot be decided within the budget).
Your FINAL message must be ONLY a JSON object (no prose, no markdown fences) of this exact shape:
{"dispositions":[{"fingerprint":"<candidate id>","disposition":"reportable"|"suppressed"|"not_applicable"|"deferred","rationale":"<grounded in your own reads>"}]}
Every candidate in the ATLAS-UNIT block must appear exactly once.`

function canonicalDigest(value: unknown): AuditSha256 {
  return auditProviderSha256(canonicalJson(value))
}

const GROK_PROMPT_TEMPLATE_DIGEST: AuditSha256 = canonicalDigest({
  namespace: 'repo-atlas/grok-prompt-templates/v1',
  builtinVersion: GROK_PROMPT_BUILTIN_VERSION,
  rubricVersion: GROK_VALIDATION_RUBRIC_VERSION,
  review: GROK_REVIEW_PROMPT,
  verification: GROK_VERIFICATION_PROMPT,
})

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  )
}

function redactSecrets(text: string, secrets: readonly string[]): string {
  let redacted = text
  for (const secret of secrets) {
    if (secret.length === 0) continue
    redacted = redacted.split(secret).join('<redacted>')
  }
  return redacted
}

// ---------------------------------------------------------------------------
// Process spawning: shell:false, exact argv, allowlisted env, bounded output,
// abort-controller timeout. No network-related flags are ever added.
// ---------------------------------------------------------------------------

interface GrokProcessResult {
  code: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  timedOut: boolean
}

interface GrokSpawnOptions {
  command: string
  argv: readonly string[]
  cwd: string
  env: NodeJS.ProcessEnv
  timeoutMs: number
  killGraceMs: number
  maxStdoutBytes: number
  maxStderrBytes: number
  secrets: readonly string[]
  runSignal: AbortSignal
  phase: AuditProviderPhaseKind
}

function spawnGrokProcess(options: GrokSpawnOptions): Promise<GrokProcessResult> {
  return new Promise((resolve, reject) => {
    let child
    try {
      child = spawn(options.command, [...options.argv], {
        shell: false,
        cwd: options.cwd,
        env: options.env,
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch (error) {
      reject(
        new AuditProviderError(
          'spawn-failed',
          `unable to start the grok executable: ${
            error instanceof Error ? error.message : String(error)
          }`,
          options.phase,
        ),
      )
      return
    }

    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let timedOut = false
    let settled = false
    let killTimer: NodeJS.Timeout | undefined

    const kill = (): void => {
      try {
        child.kill('SIGTERM')
      } catch {
        // The process may already be gone.
      }
      killTimer = setTimeout(() => {
        try {
          child.kill('SIGKILL')
        } catch {
          // The process may already be gone.
        }
      }, options.killGraceMs)
      killTimer.unref()
    }

    const timeout = setTimeout(() => {
      timedOut = true
      kill()
    }, options.timeoutMs)
    timeout.unref()

    const onRunAbort = (): void => {
      if (!settled) kill()
    }
    options.runSignal.addEventListener('abort', onRunAbort, { once: true })

    const cleanup = (): void => {
      clearTimeout(timeout)
      if (killTimer !== undefined) clearTimeout(killTimer)
      options.runSignal.removeEventListener('abort', onRunAbort)
    }

    child.stdout.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength
      if (stdoutBytes > options.maxStdoutBytes) {
        if (!settled) {
          settled = true
          cleanup()
          kill()
          reject(
            new AuditProviderError(
              'output-limit',
              `grok stdout exceeds the ${options.maxStdoutBytes}-byte limit`,
              options.phase,
            ),
          )
        }
        return
      }
      stdoutChunks.push(chunk)
    })
    child.stderr.on('data', (chunk: Buffer) => {
      stderrBytes += chunk.byteLength
      if (stderrBytes > options.maxStderrBytes) {
        if (!settled) {
          settled = true
          cleanup()
          kill()
          reject(
            new AuditProviderError(
              'output-limit',
              `grok stderr exceeds the ${options.maxStderrBytes}-byte limit`,
              options.phase,
            ),
          )
        }
        return
      }
      stderrChunks.push(chunk)
    })
    child.on('error', (error) => {
      if (settled) return
      settled = true
      cleanup()
      reject(
        new AuditProviderError(
          'spawn-failed',
          redactSecrets(
            `grok process failed to start: ${error.message}`,
            options.secrets,
          ),
          options.phase,
        ),
      )
    })
    child.on('close', (code, signal) => {
      if (settled) return
      settled = true
      cleanup()
      resolve({
        code,
        signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        timedOut,
      })
    })
  })
}

function classifyProcessResult(
  result: GrokProcessResult,
  description: string,
  secrets: readonly string[],
  phase: AuditProviderPhaseKind,
): void {
  if (result.timedOut) {
    throw new AuditProviderError('timeout', `${description} exceeded its timeout`, phase)
  }
  if (result.signal !== null) {
    throw new AuditProviderError(
      'signal',
      `${description} was killed by signal ${result.signal}`,
      phase,
    )
  }
  if (result.code !== 0) {
    const stderrTail = redactSecrets(result.stderr.slice(-2_048), secrets)
    throw new AuditProviderError(
      'exit-code',
      `${description} exited with code ${String(result.code)}: ${stderrTail}`,
      phase,
    )
  }
}

// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------

function ambientProbeEnvironment(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {}
  for (const key of AMBIENT_PROBE_ENV_KEYS) {
    if (process.env[key] !== undefined) env[key] = process.env[key]
  }
  return env
}

function isolatedEnvironment(
  context: AuditProviderContext,
  home: string,
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {}
  for (const key of ISOLATED_PASSTHROUGH_ENV_KEYS) {
    if (process.env[key] !== undefined) env[key] = process.env[key]
  }
  env.HOME = home
  env.XDG_CONFIG_HOME = path.join(home, 'config')
  env.XDG_DATA_HOME = path.join(home, 'data')
  env.XDG_STATE_HOME = path.join(home, 'state')
  env.XDG_CACHE_HOME = path.join(home, 'cache')
  env.TMPDIR = path.join(context.tempRoot, 'tmp')
  const apiKeyEnv = context.policy.apiKeyEnv
  if (apiKeyEnv !== undefined && process.env[apiKeyEnv] !== undefined) {
    env[apiKeyEnv] = process.env[apiKeyEnv]
  }
  return env
}

function collectSecrets(context: AuditProviderContext): string[] {
  const secrets: string[] = []
  const apiKeyEnv = context.policy.apiKeyEnv
  if (apiKeyEnv !== undefined && process.env[apiKeyEnv] !== undefined) {
    secrets.push(process.env[apiKeyEnv]!)
  }
  return secrets
}

function resolveGrokCommand(command: string, phase: AuditProviderPhaseKind): string {
  const candidates: string[] = []
  if (command.includes('/') || command.includes(path.sep)) {
    candidates.push(path.resolve(command))
  } else {
    const pathValue = process.env.PATH ?? ''
    for (const directory of pathValue.split(path.delimiter)) {
      if (directory.length > 0) candidates.push(path.join(directory, command))
    }
  }
  for (const candidate of candidates) {
    try {
      const stat = fs.statSync(candidate)
      if (stat.isFile()) {
        fs.accessSync(candidate, fs.constants.X_OK)
        return candidate
      }
    } catch {
      // Try the next candidate.
    }
  }
  throw new AuditProviderError(
    'preflight-rejected',
    'the explicit grok executable could not be resolved',
    phase,
  )
}

function createIsolatedHome(context: AuditProviderContext): string {
  const home = path.join(context.tempRoot, 'home')
  fs.mkdirSync(home, { recursive: true, mode: 0o700 })
  fs.chmodSync(home, 0o700)
  for (const child of ['config', 'data', 'state', 'cache']) {
    const directory = path.join(home, child)
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
    fs.chmodSync(directory, 0o700)
  }
  const tmp = path.join(context.tempRoot, 'tmp')
  fs.mkdirSync(tmp, { recursive: true, mode: 0o700 })
  fs.chmodSync(tmp, 0o700)
  return home
}

// Copy only the existing Grok authentication record, with mode 0600. Config,
// hooks, plugins, MCP, memory, and sessions are never copied. The bytes never
// enter logs, journals, receipts, or error messages.
function copyAuthenticationRecord(context: AuditProviderContext, home: string): void {
  const policy = context.policy
  if (policy.apiKeyEnv !== undefined && process.env[policy.apiKeyEnv] !== undefined) {
    return
  }
  const source = path.join(os.homedir(), ...policy.authRecordPath.split('/'))
  let stat: fs.Stats
  try {
    stat = fs.lstatSync(source)
  } catch {
    return
  }
  if (stat.isSymbolicLink() || !stat.isFile() || Number(stat.size) > MAX_AUTH_RECORD_BYTES) {
    return
  }
  const bytes = fs.readFileSync(source)
  const destination = path.join(home, ...policy.authRecordPath.split('/'))
  fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 })
  fs.writeFileSync(destination, bytes, { mode: 0o600 })
  fs.chmodSync(destination, 0o600)
}

// ---------------------------------------------------------------------------
// Preflight probes and inspect validation
// ---------------------------------------------------------------------------

function validateInspectPayload(
  value: unknown,
  context: AuditProviderContext,
): AuditSha256 {
  if (!isPlainObject(value)) {
    throw new AuditProviderError(
      'preflight-rejected',
      'grok inspect did not return a JSON object',
      'inventory',
    )
  }
  if (value.version !== undefined && value.version !== GROK_SUPPORTED_CLI_VERSION) {
    throw new AuditProviderError(
      'preflight-rejected',
      'grok inspect reports an unsupported CLI version',
      'inventory',
    )
  }
  for (const key of ['hooks', 'plugins', 'mcpServers', 'projectInstructions'] as const) {
    const member = value[key]
    if (member === undefined) continue
    if (!Array.isArray(member) || member.length > 0) {
      throw new AuditProviderError(
        'preflight-rejected',
        `ambient grok ${key} are present in the isolated environment`,
        'inventory',
      )
    }
  }
  const permissionSources = value.permissionSources
  if (permissionSources !== undefined) {
    if (
      !Array.isArray(permissionSources) ||
      permissionSources.some(
        (source) => source !== 'default' && source !== 'command-line',
      )
    ) {
      throw new AuditProviderError(
        'preflight-rejected',
        'grok reports an unexpected permission source',
        'inventory',
      )
    }
  }
  const effectiveConfig = value.effectiveConfig === undefined ? {} : value.effectiveConfig
  if (!isPlainObject(effectiveConfig)) {
    throw new AuditProviderError(
      'preflight-rejected',
      'grok inspect returned an invalid effective configuration',
      'inventory',
    )
  }
  const digest = canonicalDigest(effectiveConfig)
  if (
    Object.keys(effectiveConfig).length > 0 &&
    !context.policy.approvedConfigDigests.includes(digest)
  ) {
    throw new AuditProviderError(
      'preflight-rejected',
      'grok effective configuration drifted and its digest is not approved',
      'inventory',
    )
  }
  return digest
}

const resolvedCommands = new WeakMap<AuditProviderContext, string>()

async function grokInventory(
  context: AuditProviderContext,
): Promise<AuditProviderUnitExecution<AuditProviderInventoryFacts>> {
  const policy = context.policy
  const secrets = collectSecrets(context)
  const probeTimeout = Math.min(policy.timeoutMs, PROBE_TIMEOUT_CAP_MS)

  // Resolve the executable and record its binary/version before changing the
  // environment.
  const command = resolveGrokCommand(policy.command, 'inventory')
  resolvedCommands.set(context, command)
  const binaryStat = fs.statSync(command)
  if (Number(binaryStat.size) > MAX_BINARY_BYTES) {
    throw new AuditProviderError(
      'preflight-rejected',
      'the grok executable exceeds the binary digest limit',
      'inventory',
    )
  }
  const binaryDigest = auditProviderSha256(fs.readFileSync(command))
  const probesEnv = ambientProbeEnvironment()

  const versionProbe = await spawnGrokProcess({
    command,
    argv: ['--version'],
    cwd: context.tempRoot,
    env: probesEnv,
    timeoutMs: probeTimeout,
    killGraceMs: policy.killGraceMs,
    maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
    maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
    secrets,
    runSignal: context.signal,
    phase: 'inventory',
  })
  classifyProcessResult(versionProbe, 'grok --version', secrets, 'inventory')
  const versionMatch = /(\d+\.\d+\.\d+)/.exec(versionProbe.stdout)
  if (versionMatch === null || versionMatch[1] !== GROK_SUPPORTED_CLI_VERSION) {
    throw new AuditProviderError(
      'preflight-rejected',
      `grok CLI version is unsupported by ${GROK_ADAPTER_ID}`,
      'inventory',
    )
  }
  const binaryVersion = versionMatch[1]

  const helpProbe = await spawnGrokProcess({
    command,
    argv: ['--help'],
    cwd: context.tempRoot,
    env: probesEnv,
    timeoutMs: probeTimeout,
    killGraceMs: policy.killGraceMs,
    maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
    maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
    secrets,
    runSignal: context.signal,
    phase: 'inventory',
  })
  classifyProcessResult(helpProbe, 'grok --help', secrets, 'inventory')
  for (const flag of GROK_PERMISSION_FLAGS) {
    if (!helpProbe.stdout.includes(flag)) {
      throw new AuditProviderError(
        'preflight-rejected',
        `grok --help does not advertise the required flag ${flag}`,
        'inventory',
      )
    }
  }

  // The isolated home and the preflight share one environment.
  const home = createIsolatedHome(context)
  copyAuthenticationRecord(context, home)
  const isolatedEnv = isolatedEnvironment(context, home)

  const inspectProbe = await spawnGrokProcess({
    command,
    argv: ['inspect', '--json'],
    cwd: context.snapshotRoot,
    env: isolatedEnv,
    timeoutMs: probeTimeout,
    killGraceMs: policy.killGraceMs,
    maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
    maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
    secrets,
    runSignal: context.signal,
    phase: 'inventory',
  })
  classifyProcessResult(inspectProbe, 'grok inspect --json', secrets, 'inventory')
  let inspectValue: unknown
  try {
    inspectValue = parseBoundedAuditJsonBytes(
      new Uint8Array(Buffer.from(inspectProbe.stdout, 'utf8')),
      MAX_PROBE_OUTPUT_BYTES,
      'grok inspect --json',
    )
  } catch {
    throw new AuditProviderError(
      'preflight-rejected',
      'grok inspect --json did not return bounded JSON',
      'inventory',
    )
  }
  const effectiveConfigDigest = validateInspectPayload(inspectValue, context)

  return {
    output: {
      binaryVersion,
      binaryDigest,
      effectiveConfigDigest,
      probeDigests: [
        auditProviderSha256(versionProbe.stdout),
        auditProviderSha256(helpProbe.stdout),
        auditProviderSha256(inspectProbe.stdout),
      ],
    },
    processCount: 3,
    sessionIds: [],
    transcriptDigests: [],
  }
}

// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------

function renderUnitPrompt(
  context: AuditProviderContext,
  unitBlock: Record<string, unknown>,
  template: string,
): string {
  const sections = [
    template,
    '',
    '## Repository threat context',
    '',
    context.prompt.trim().length > 0 ? context.prompt.trim() : 'None supplied.',
    '',
    'ATLAS-UNIT',
    JSON.stringify(unitBlock),
    '',
  ]
  const prompt = sections.join('\n')
  if (Buffer.byteLength(prompt, 'utf8') > context.policy.maxPromptBytes) {
    throw new AuditProviderError(
      'output-invalid',
      `rendered prompt exceeds the ${context.policy.maxPromptBytes}-byte limit`,
    )
  }
  return prompt
}

// ---------------------------------------------------------------------------
// Stdout and transcript proof
// ---------------------------------------------------------------------------

// Real grok 0.2.82 `--output-format streaming-json` vocabulary, verified
// against the live CLI: reasoning streams as `thought` chunks, the assistant
// response streams as ordered `text` chunks whose concatenation is the final
// response, and exactly one terminal `end` event with
// `stopReason: "EndTurn"` closes a successful turn. Tool calls never appear
// on stdout; they live only in the session transcript. Failures surface as an
// in-band `error` event (usually paired with a nonzero exit). Unknown
// non-terminal event types are ignored; a missing or non-EndTurn terminal,
// an error event, or anything after the terminal fails closed.
function parseStreamingStdout(
  stdout: string,
  context: AuditProviderContext,
  phase: AuditProviderPhaseKind,
  sessionId: string,
): string {
  const lines = stdout.split('\n').filter((line) => line.trim().length > 0)
  if (lines.length === 0 || lines.length > MAX_STDOUT_LINES) {
    throw new AuditProviderError(
      'output-invalid',
      'grok stdout is not a bounded streaming-json sequence',
      phase,
    )
  }
  const textChunks: string[] = []
  let responseBytes = 0
  let terminal: Record<string, unknown> | undefined
  for (const line of lines) {
    let event: unknown
    try {
      event = JSON.parse(line)
    } catch {
      throw new AuditProviderError(
        'output-invalid',
        'grok stdout contains a non-JSON streaming line',
        phase,
      )
    }
    if (!isPlainObject(event) || typeof event.type !== 'string') {
      throw new AuditProviderError(
        'output-invalid',
        'grok stdout streaming event is malformed',
        phase,
      )
    }
    if (terminal !== undefined) {
      throw new AuditProviderError(
        'output-invalid',
        'grok stdout continues after its terminal end event',
        phase,
      )
    }
    if (event.type === 'error') {
      throw new AuditProviderError(
        'output-invalid',
        'grok stdout reported an error event',
        phase,
      )
    }
    if (event.type === 'end') {
      terminal = event
      continue
    }
    if (event.type === 'text') {
      if (typeof event.data !== 'string') {
        throw new AuditProviderError(
          'output-invalid',
          'grok stdout text event is malformed',
          phase,
        )
      }
      responseBytes += Buffer.byteLength(event.data, 'utf8')
      if (responseBytes > context.policy.maxResponseBytes) {
        throw new AuditProviderError(
          'output-invalid',
          'grok final response exceeds the size bound',
          phase,
        )
      }
      textChunks.push(event.data)
    }
    // Any other non-terminal event type (thought, or a future addition) is
    // ignored: it carries nothing the adapter consumes.
  }
  if (terminal === undefined) {
    throw new AuditProviderError(
      'output-invalid',
      'grok stdout has no terminal end event',
      phase,
    )
  }
  if (terminal.stopReason !== 'EndTurn') {
    throw new AuditProviderError(
      'output-invalid',
      'grok stdout terminal end event is not a successful EndTurn',
      phase,
    )
  }
  if (terminal.sessionId !== sessionId) {
    throw new AuditProviderError(
      'output-invalid',
      'grok stdout terminal end event does not belong to the run session',
      phase,
    )
  }
  const response = textChunks.join('')
  if (response.length === 0) {
    throw new AuditProviderError(
      'output-invalid',
      'grok stdout produced an empty response',
      phase,
    )
  }
  return response
}

interface TranscriptReadInterval {
  start: number
  end: number
}

function normalizeTranscriptPath(
  value: unknown,
  context: AuditProviderContext,
  phase: AuditProviderPhaseKind,
): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript tool call is missing a path',
      phase,
    )
  }
  let relative = value
  if (path.isAbsolute(value)) {
    const snapshotPrefix = context.snapshotRoot + path.sep
    if (!value.startsWith(snapshotPrefix)) {
      throw new AuditProviderError(
        'transcript-invalid',
        `transcript tool path escapes the snapshot: ${value}`,
        phase,
      )
    }
    relative = value.slice(snapshotPrefix.length).split(path.sep).join('/')
  }
  let normalized: string
  try {
    normalized = normalizeAuditRepoPath(relative)
  } catch {
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript tool path is not a safe snapshot-relative path: ${value}`,
      phase,
    )
  }
  if (context.manifestEntry(normalized) === undefined) {
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript tool path is outside the snapshot inventory: ${normalized}`,
      phase,
    )
  }
  return normalized
}

// grep.path and list_dir.target_directory may name the snapshot root itself
// or any directory inside it; unlike a Read target they are not required to
// be manifest files, but they must stay inside the snapshot.
function normalizeTranscriptDirectory(
  value: unknown,
  context: AuditProviderContext,
  phase: AuditProviderPhaseKind,
): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript tool call is missing a path',
      phase,
    )
  }
  let relative = value
  if (path.isAbsolute(value)) {
    if (value === context.snapshotRoot) return '.'
    const snapshotPrefix = context.snapshotRoot + path.sep
    if (!value.startsWith(snapshotPrefix)) {
      throw new AuditProviderError(
        'transcript-invalid',
        `transcript tool path escapes the snapshot: ${value}`,
        phase,
      )
    }
    relative = value.slice(snapshotPrefix.length).split(path.sep).join('/')
  }
  if (relative === '.') return '.'
  try {
    return normalizeAuditRepoPath(relative)
  } catch {
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript tool path is not a safe snapshot-relative path: ${value}`,
      phase,
    )
  }
}

// A read_file result is raw file bytes with line anchors: the first returned
// A read_file result is raw file bytes with line anchors: the first returned
// line is prefixed `<start>→` and every absolute decade line (10, 20, …)
// carries its line number as a `<n>→` prefix (verified against live 0.2.82
// sessions, including 500-line files and ranged reads). The anchors plus the
// returned line count prove the exact range the tool returned, mirroring the
// old startLine/endLine proof.
//
// One large-file quirk, verified live (and the cause of the first consumer
// pilot failure): a read_file call with NO offset/limit arguments appends a
// trailing phantom anchor for the line AFTER the file when that line number
// is a multiple of ten — a 129-line file yields content ending "…\n130→".
// Ranged reads (explicit offset/limit) never emit it, not even when they
// reach EOF. The phantom is not file content — its number is one past the
// manifest line count by construction — so dropping it cannot fabricate
// coverage.
function proveTranscriptReadInterval(
  content: string,
  call: { path: string; offset: number; limit: number },
  context: AuditProviderContext,
  phase: AuditProviderPhaseKind,
): TranscriptReadInterval {
  const anchor = /^(\d+)→/.exec(content)
  if (anchor === null || Number(anchor[1]) !== call.offset) {
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript Read result does not prove its start line (expected offset ${String(
        call.offset,
      )}, observed anchor ${anchor === null ? 'none' : anchor[1]})`,
      phase,
    )
  }
  const entry = context.manifestEntry(call.path)!
  const lines = content.slice(anchor[0].length).split('\n')
  if (lines.length > 0 && lines[lines.length - 1] === '') lines.pop()
  if (call.limit === Number.MAX_SAFE_INTEGER && lines.length > 0) {
    const phantom = /^(\d+)→$/.exec(lines[lines.length - 1])
    if (
      phantom !== null &&
      Number(phantom[1]) === entry.lines + 1 &&
      (entry.lines + 1) % 10 === 0
    ) {
      lines.pop()
    }
  }
  if (lines.length === 0) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript Read result returned no lines',
      phase,
    )
  }
  for (const [index, line] of lines.entries()) {
    const inner = /^(\d+)→/.exec(line)
    if (inner !== null && Number(inner[1]) !== call.offset + index) {
      throw new AuditProviderError(
        'transcript-invalid',
        `transcript Read result line anchor does not match its position (line index ${String(
          index,
        )}, expected absolute ${String(call.offset + index)}, observed ${inner[1]})`,
        phase,
      )
    }
  }
  const end = call.offset + lines.length - 1
  if (end > call.offset + call.limit - 1 || end > entry.lines) {
    const requestedEnd =
      call.limit === Number.MAX_SAFE_INTEGER ? 'none' : String(call.offset + call.limit - 1)
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript Read result does not prove its returned range (offset ${String(
        call.offset,
      )}, counted ${String(lines.length)} lines, requested end ${requestedEnd}, file lines ${String(
        entry.lines,
      )}, computed end ${String(end)})`,
      phase,
    )
  }
  return { start: call.offset, end }
}

// Real grok 0.2.82 session transcript contract, verified against the live
// CLI. `system`, `user`, and `reasoning` events are ambient and ignored.
// `assistant` events carry text content plus optional tool_calls (whose
// arguments are a bounded JSON string); `tool_result` events link back via
// tool_call_id and signal errors with an "Error:" content prefix. The final
// assistant message is the last event, has non-empty content, and no tool
// calls; the concatenation of every assistant content in order is
// byte-identical to the stdout text stream. Anything else fails closed.
function validateSessionTranscript(
  events: unknown[],
  context: AuditProviderContext,
  claimedFiles: readonly AuditProviderSnapshotEntry[],
  phase: AuditProviderPhaseKind,
): string {
  if (events.length === 0 || events.length > context.policy.maxTranscriptEvents) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript event count is out of bounds',
      phase,
    )
  }
  const calls = new Map<
    string,
    { tool: (typeof GROK_TOOLS)[number]; path?: string; offset: number; limit: number }
  >()
  const reads = new Map<string, TranscriptReadInterval[]>()
  const responseParts: string[] = []
  let responseBytes = 0
  let terminalFound = false

  for (const [index, rawEvent] of events.entries()) {
    if (!isPlainObject(rawEvent) || typeof rawEvent.type !== 'string') {
      throw new AuditProviderError(
        'transcript-invalid',
        `transcript event ${index} is malformed`,
        phase,
      )
    }
    if (rawEvent.type === 'system' || rawEvent.type === 'user' || rawEvent.type === 'reasoning') {
      continue
    }
    if (rawEvent.type === 'assistant') {
      const content = rawEvent.content
      if (typeof content !== 'string') {
        throw new AuditProviderError(
          'transcript-invalid',
          'transcript assistant content is malformed',
          phase,
        )
      }
      const toolCalls = rawEvent.tool_calls
      if (toolCalls !== undefined && !Array.isArray(toolCalls)) {
        throw new AuditProviderError(
          'transcript-invalid',
          'transcript assistant tool calls are malformed',
          phase,
        )
      }
      if (toolCalls === undefined || toolCalls.length === 0) {
        // An assistant message without tool calls is the final answer: it
        // must carry content and be the last transcript event.
        if (content.length === 0 || index !== events.length - 1) {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript must contain exactly one final assistant message at the end',
            phase,
          )
        }
        terminalFound = true
      }
      if (content.length > 0) {
        responseBytes += Buffer.byteLength(content, 'utf8')
        if (responseBytes > context.policy.maxResponseBytes) {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript final response exceeds the size bound',
            phase,
          )
        }
        responseParts.push(content)
      }
      for (const rawCall of toolCalls ?? []) {
        if (!isPlainObject(rawCall)) {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript tool call is malformed',
            phase,
          )
        }
        const id = rawCall.id
        if (typeof id !== 'string' || id.length === 0 || calls.has(id)) {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript tool call id is missing or duplicated',
            phase,
          )
        }
        const tool =
          typeof rawCall.name === 'string'
            ? GROK_TRANSCRIPT_TOOLS.get(rawCall.name)
            : undefined
        if (tool === undefined) {
          throw new AuditProviderError(
            'transcript-invalid',
            `transcript used a forbidden tool: ${String(rawCall.name)}`,
            phase,
          )
        }
        if (typeof rawCall.arguments !== 'string') {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript tool call arguments are malformed',
            phase,
          )
        }
        let input: unknown
        try {
          input = parseBoundedAuditJsonBytes(
            new Uint8Array(Buffer.from(rawCall.arguments, 'utf8')),
            MAX_TOOL_ARGUMENT_BYTES,
            'transcript tool call arguments',
          )
        } catch {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript tool call arguments are not bounded JSON',
            phase,
          )
        }
        if (!isPlainObject(input)) {
          throw new AuditProviderError(
            'transcript-invalid',
            'transcript tool call input is malformed',
            phase,
          )
        }
        if (tool === 'Read') {
          const toolPath = normalizeTranscriptPath(input.target_file, context, phase)
          const offset = input.offset === undefined ? 1 : input.offset
          const limit = input.limit === undefined ? Number.MAX_SAFE_INTEGER : input.limit
          if (
            typeof offset !== 'number' ||
            !Number.isSafeInteger(offset) ||
            offset < 1 ||
            typeof limit !== 'number' ||
            !Number.isSafeInteger(limit) ||
            limit < 1
          ) {
            throw new AuditProviderError(
              'transcript-invalid',
              'transcript Read call has an invalid offset/limit',
              phase,
            )
          }
          calls.set(id, { tool, path: toolPath, offset, limit })
        } else if (tool === 'Grep') {
          const directory =
            input.path === undefined
              ? undefined
              : normalizeTranscriptDirectory(input.path, context, phase)
          calls.set(id, { tool, path: directory, offset: 1, limit: 1 })
        } else {
          const directory =
            input.target_directory === undefined
              ? undefined
              : normalizeTranscriptDirectory(input.target_directory, context, phase)
          calls.set(id, { tool, path: directory, offset: 1, limit: 1 })
        }
      }
      continue
    }
    if (rawEvent.type === 'tool_result') {
      const id = rawEvent.tool_call_id
      if (typeof id !== 'string' || !calls.has(id)) {
        throw new AuditProviderError(
          'transcript-invalid',
          'transcript tool result is not linked to a tool call',
          phase,
        )
      }
      const call = calls.get(id)!
      calls.delete(id)
      const content = rawEvent.content
      if (typeof content !== 'string') {
        throw new AuditProviderError(
          'transcript-invalid',
          'transcript tool result is malformed',
          phase,
        )
      }
      if (content.startsWith('Error:')) {
        throw new AuditProviderError(
          'transcript-invalid',
          `transcript contains a tool error (${call.tool}: ${content
            .slice(0, 160)
            .replaceAll('\n', ' ')})`,
          phase,
        )
      }
      if (call.tool === 'Read' && call.path !== undefined) {
        const interval = proveTranscriptReadInterval(
          content,
          { path: call.path, offset: call.offset, limit: call.limit },
          context,
          phase,
        )
        const intervals = reads.get(call.path) ?? []
        intervals.push(interval)
        reads.set(call.path, intervals)
      }
      continue
    }
    throw new AuditProviderError(
      'transcript-invalid',
      `transcript contains an unsupported event: ${rawEvent.type}`,
      phase,
    )
  }

  if (!terminalFound) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript has no final assistant message',
      phase,
    )
  }
  if (calls.size > 0) {
    throw new AuditProviderError(
      'transcript-invalid',
      'transcript has tool calls without results',
      phase,
    )
  }

  // Complete contiguous line-range coverage for every file claimed reviewed.
  for (const file of claimedFiles) {
    if (file.lines === 0) continue
    const intervals = (reads.get(file.path) ?? []).sort(
      (left, right) => left.start - right.start,
    )
    let covered = 0
    for (const interval of intervals) {
      if (interval.start > covered + 1) break
      covered = Math.max(covered, interval.end)
    }
    if (covered < file.lines) {
      throw new AuditProviderError(
        'transcript-invalid',
        `transcript does not prove full-range reads for ${file.path}`,
        phase,
      )
    }
  }
  return responseParts.join('')
}

function checkJsonDepth(value: unknown, depth: number, maxDepth: number): boolean {
  if (depth > maxDepth) return false
  if (Array.isArray(value)) {
    return value.every((entry) => checkJsonDepth(entry, depth + 1, maxDepth))
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).every((entry) =>
      checkJsonDepth(entry, depth + 1, maxDepth),
    )
  }
  return true
}

function parseFinalJsonBlock(
  response: string,
  context: AuditProviderContext,
  phase: AuditProviderPhaseKind,
): unknown {
  let text = response.trim()
  const fenced = /^```(?:json)?\s*\r?\n([\s\S]*?)```\s*$/.exec(text)
  if (fenced !== null) {
    text = fenced[1]!.trim()
  } else if (!(text.startsWith('{') && text.endsWith('}'))) {
    const start = text.indexOf('{')
    const end = text.lastIndexOf('}')
    if (start < 0 || end <= start) {
      throw new AuditProviderError(
        'output-invalid',
        'grok final response contains no JSON block',
        phase,
      )
    }
    text = text.slice(start, end + 1)
  }
  let value: unknown
  try {
    value = parseBoundedAuditJsonBytes(
      new Uint8Array(Buffer.from(text, 'utf8')),
      context.policy.maxResponseBytes,
      'grok final response',
    )
  } catch {
    throw new AuditProviderError(
      'output-invalid',
      'grok final response is not bounded valid JSON',
      phase,
    )
  }
  if (!checkJsonDepth(value, 0, context.policy.maxResponseDepth)) {
    throw new AuditProviderError(
      'output-invalid',
      'grok final response exceeds the depth bound',
      phase,
    )
  }
  return value
}

// ---------------------------------------------------------------------------
// Analysis units (review + verification): one bounded grok process each
// ---------------------------------------------------------------------------

async function runGrokAnalysisUnit(
  context: AuditProviderContext,
  options:
    | { kind: 'review'; unit: AuditProviderReviewUnit }
    | { kind: 'verification'; unit: AuditProviderVerificationUnit },
): Promise<
  AuditProviderUnitExecution<
    AuditProviderReviewUnitOutput | AuditProviderVerificationUnitOutput
  >
> {
  const policy = context.policy
  const phase: AuditProviderPhaseKind = options.kind
  const secrets = collectSecrets(context)
  const command = resolvedCommands.get(context) ?? resolveGrokCommand(policy.command, phase)

  const unitBlock: Record<string, unknown> =
    options.kind === 'review'
      ? {
          kind: 'review',
          unit: options.unit.unit,
          ruleset: context.ruleset.id,
          files: options.unit.files.map((file) => ({
            path: file.path,
            lines: file.lines,
            sha256: file.sha256,
          })),
        }
      : {
          kind: 'verification',
          unit: options.unit.unit,
          candidates: options.unit.candidates.map((candidate) => ({
            fingerprint: candidate.fingerprint,
            ruleId: candidate.ruleId,
            path: candidate.path,
            startLine: candidate.startLine,
            ...(candidate.endLine !== undefined ? { endLine: candidate.endLine } : {}),
            title: candidate.title,
            severity: candidate.severity,
            summary: candidate.summary,
          })),
          files: options.unit.files.map((file) => ({
            path: file.path,
            lines: file.lines,
            sha256: file.sha256,
          })),
        }
  const prompt = renderUnitPrompt(
    context,
    unitBlock,
    options.kind === 'review' ? GROK_REVIEW_PROMPT : GROK_VERIFICATION_PROMPT,
  )

  const promptsDir = path.join(context.tempRoot, 'prompts')
  fs.mkdirSync(promptsDir, { recursive: true, mode: 0o700 })
  const promptFile = path.join(
    promptsDir,
    `${options.unit.unit.replaceAll(':', '-')}-${randomUUID().slice(0, 8)}.md`,
  )
  fs.writeFileSync(promptFile, prompt, { mode: 0o600 })

  const home = path.join(context.tempRoot, 'home')
  const env = isolatedEnvironment(context, home)
  const sessionId = randomUUID()
  // No bare `--single`: grok 0.2.82 parses `-p, --single <PROMPT>` as a
  // value-taking option and exits 2 when the value is missing. Prompt
  // delivery stays `--prompt-file`, which implies single-turn headless mode.
  const argv = [
    '--no-plan',
    '--permission-mode',
    'dontAsk',
    '--tools',
    GROK_TOOLS.join(','),
    '--no-memory',
    '--no-subagents',
    '--disable-web-search',
    '--output-format',
    'streaming-json',
    '--model',
    policy.model,
    '--session-id',
    sessionId,
    '--cwd',
    context.snapshotRoot,
    '--prompt-file',
    promptFile,
  ]

  const result = await spawnGrokProcess({
    command,
    argv,
    cwd: context.snapshotRoot,
    env,
    timeoutMs: policy.timeoutMs,
    killGraceMs: policy.killGraceMs,
    maxStdoutBytes: policy.maxStdoutBytes,
    maxStderrBytes: policy.maxStderrBytes,
    secrets,
    runSignal: context.signal,
    phase,
  })
  classifyProcessResult(
    result,
    `grok ${options.kind} unit ${options.unit.unit}`,
    secrets,
    phase,
  )

  const stdoutResponse = parseStreamingStdout(result.stdout, context, phase, sessionId)

  // The real CLI keeps sessions under $HOME/.grok (XDG_DATA_HOME is ignored),
  // grouped by the encodeURIComponent form of the working directory, which
  // the adapter passes as --cwd. The end.sessionId validated above binds the
  // stdout stream to this exact session directory.
  const transcriptPath = path.join(
    home,
    '.grok',
    'sessions',
    encodeURIComponent(context.snapshotRoot),
    sessionId,
    'chat_history.jsonl',
  )
  let transcriptBytes: Buffer
  try {
    const stat = fs.lstatSync(transcriptPath)
    if (
      stat.isSymbolicLink() ||
      !stat.isFile() ||
      Number(stat.size) > policy.maxTranscriptBytes
    ) {
      throw new Error('unsafe transcript')
    }
    transcriptBytes = fs.readFileSync(transcriptPath)
  } catch {
    throw new AuditProviderError(
      'transcript-invalid',
      'the isolated session transcript is missing or unsafe',
      phase,
    )
  }
  let events: unknown[]
  try {
    const text = transcriptBytes.toString('utf8')
    const lines = text.split('\n').filter((line) => line.trim().length > 0)
    if (lines.length > policy.maxTranscriptEvents) throw new Error('too many events')
    events = lines.map((line) => JSON.parse(line))
  } catch {
    throw new AuditProviderError(
      'transcript-invalid',
      'the session transcript is not bounded JSONL',
      phase,
    )
  }

  // Parse and validate the final JSON block first so the transcript can be
  // checked against exactly the files the model claims to have reviewed.
  const outputValue = parseFinalJsonBlock(stdoutResponse, context, phase)
  let output: AuditProviderReviewUnitOutput | AuditProviderVerificationUnitOutput
  let claimedFiles: readonly AuditProviderSnapshotEntry[]
  if (options.kind === 'review') {
    output = validateAuditProviderReviewUnitOutput(outputValue, options.unit.files, policy)
    const entries: AuditProviderSnapshotEntry[] = []
    for (const receipt of output.receipts) {
      const entry = context.manifestEntry(receipt.path)
      if (entry === undefined) {
        throw new AuditProviderError(
          'missing-file-receipt',
          `review receipt references a file outside the snapshot: ${receipt.path}`,
          phase,
        )
      }
      entries.push(entry)
    }
    claimedFiles = entries
  } else {
    output = validateAuditProviderVerificationUnitOutput(
      outputValue,
      options.unit.candidates,
      policy,
    )
    claimedFiles = options.unit.files
  }

  const transcriptResponse = validateSessionTranscript(events, context, claimedFiles, phase)
  if (transcriptResponse !== stdoutResponse) {
    throw new AuditProviderError(
      'transcript-mismatch',
      'the streaming stdout terminal response differs from the session transcript',
      phase,
    )
  }

  return {
    output,
    processCount: 1,
    sessionIds: [sessionId],
    transcriptDigests: [auditProviderSha256(new Uint8Array(transcriptBytes))],
  }
}

// ---------------------------------------------------------------------------
// Deterministic synthesis
// ---------------------------------------------------------------------------

function grokSynthesize(
  context: AuditProviderContext,
  input: AuditProviderSynthesisInput,
): AuditProviderSynthesisOutput {
  const dispositions = new Map<
    string,
    { disposition: AuditProviderFinding['disposition']; rationale: string }
  >()
  for (const output of input.verificationOutputs) {
    for (const disposition of output.dispositions) {
      dispositions.set(disposition.fingerprint, {
        disposition: disposition.disposition,
        rationale: disposition.rationale,
      })
    }
  }
  const findings: AuditProviderFinding[] = input.candidates.map((candidate) => {
    const disposition = dispositions.get(candidate.fingerprint)
    if (disposition === undefined) {
      throw new AuditProviderError(
        'output-invalid',
        `candidate ${candidate.fingerprint} has no terminal validation disposition`,
        'synthesis',
      )
    }
    return {
      ...candidate,
      disposition: disposition.disposition,
      dispositionRationale: disposition.rationale,
    }
  })
  const files: AuditProviderFileOutcome[] = []
  for (const target of context.targets) {
    if (target.role !== 'review') continue
    let outcome: 'clean' | 'findings' = 'clean'
    for (const reviewOutput of input.reviewOutputs) {
      const receipt = reviewOutput.receipts.find((entry) => entry.path === target.path)
      if (receipt !== undefined) outcome = receipt.outcome
    }
    files.push({
      path: target.path,
      blob: target.blob,
      lines: target.lines,
      status: 'reviewed',
      outcome,
      findingFingerprints: findings
        .filter((finding) => finding.path === target.path)
        .map((finding) => finding.fingerprint),
    })
  }
  return { files, findings }
}

export function createGrokAuditProvider(): AuditProvider {
  return {
    name: 'grok',
    descriptor: {
      provider: 'grok',
      adapter: GROK_ADAPTER_ID,
      adapterVersion: GROK_ADAPTER_VERSION,
      rulesetId: GROK_RULESET_ID,
      promptBuiltinVersion: GROK_PROMPT_BUILTIN_VERSION,
      promptTemplateDigest: GROK_PROMPT_TEMPLATE_DIGEST,
      tools: [...GROK_TOOLS],
      permissionFlags: [...GROK_PERMISSION_FLAGS],
    },
    run(context: AuditProviderContext): Promise<AuditProviderResult> {
      return runAuditProviderPhases(context, {
        inventory: grokInventory,
        review: (ctx, unit) =>
          runGrokAnalysisUnit(ctx, { kind: 'review', unit }) as Promise<
            AuditProviderUnitExecution<AuditProviderReviewUnitOutput>
          >,
        verification: (ctx, unit) =>
          runGrokAnalysisUnit(ctx, { kind: 'verification', unit }) as Promise<
            AuditProviderUnitExecution<AuditProviderVerificationUnitOutput>
          >,
        synthesize: grokSynthesize,
      })
    },
  }
}
