import { randomUUID } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { git } from './scan.js'
import type {
  AttentionAction,
  AttentionActionRequest,
  AttentionConceptState,
  AttentionDiagnostic,
  AttentionEvent,
  AttentionItem,
  AttentionOutcome,
  AttentionPayload,
  AttentionState,
  ComputeStatusResult,
  ConceptStatusEntry,
} from './types.js'

const ATTENTION_FORMAT_VERSION = 1 as const
const ATTENTION_STATE_BYTES = 16 * 1024 * 1024
const ATTENTION_CONCEPT_LIMIT = 100_000
const ATTENTION_NOTE_LIMIT = 10_000
const MAX_SLUG_LENGTH = 512
const MAX_ID_LENGTH = 256
const MAX_SNOOZE_MS = 365 * 24 * 60 * 60 * 1000
const ATTENTION_LOCK_BYTES = 4 * 1024
const ATTENTION_LOCK_RETRY_MS = 5
const ATTENTION_LOCK_TIMEOUT_MS = 2_000

export const ATTENTION_EVENT_LIMIT = 10_000

const WORKFLOWS = new Set(['open', 'snoozed', 'done'])
const OUTCOMES = new Set<AttentionOutcome>(['acknowledged', 'understood', 'decided', 'not-relevant'])
const ACTIONS = new Set<AttentionAction>([...OUTCOMES, 'snooze', 'reopen'])
const EVENT_TYPES = new Set(['reviewed', 'snoozed', 'reopened', 'source-reopened'])
const SNAPSHOT_PATTERN = /^[a-f0-9]{64}$/
const STATE_FIELDS = new Set(['formatVersion', 'concepts', 'events'])
const CONCEPT_STATE_FIELDS = new Set([
  'snapshot', 'revision', 'workflow', 'firstSeenAt', 'snoozedUntil', 'lastReviewedAt', 'lastOutcome',
])
const EVENT_FIELDS = new Set(['id', 'slug', 'snapshot', 'type', 'at', 'outcome', 'note', 'until'])
const UNSUPPORTED_DIRECTORY_FSYNC = new Set(['EINVAL', 'ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EISDIR'])

export interface AttentionReconciliation {
  state: AttentionState
  changed: boolean
}

export interface AttentionLoadResult {
  state: AttentionState | null
  diagnostics: AttentionDiagnostic[]
}

export interface AttentionPayloadOptions {
  mode?: 'live' | 'static'
  /** `null` means persistence is invalid; omitted means a static initial view. */
  state?: AttentionState | null
  diagnostics?: AttentionDiagnostic[]
  changedPaths?: Record<string, string[]>
  now?: string
}

export class AttentionConflictError extends Error {
  override name = 'AttentionConflictError'
}

export class AttentionRequestError extends Error {
  override name = 'AttentionRequestError'
}

export class AttentionStateUnavailableError extends Error {
  override name = 'AttentionStateUnavailableError'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function hasOnlyFields(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key))
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value))
}

function requireTimestamp(value: string, label: string): number {
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed)) throw new Error(`${label} must be a valid timestamp`)
  return parsed
}

function cloneState(state: AttentionState): AttentionState {
  const concepts = Object.create(null) as Record<string, AttentionConceptState>
  for (const [slug, concept] of Object.entries(state.concepts)) {
    concepts[slug] = {
      snapshot: concept.snapshot,
      revision: concept.revision,
      workflow: concept.workflow,
      firstSeenAt: concept.firstSeenAt,
      ...(concept.snoozedUntil !== undefined ? { snoozedUntil: concept.snoozedUntil } : {}),
      ...(concept.lastReviewedAt !== undefined ? { lastReviewedAt: concept.lastReviewedAt } : {}),
      ...(concept.lastOutcome !== undefined ? { lastOutcome: concept.lastOutcome } : {}),
    }
  }
  return {
    formatVersion: ATTENTION_FORMAT_VERSION,
    concepts,
    events: state.events.map((event) => ({
      id: event.id,
      slug: event.slug,
      snapshot: event.snapshot,
      type: event.type,
      at: event.at,
      ...(event.outcome !== undefined ? { outcome: event.outcome } : {}),
      ...(event.note !== undefined ? { note: event.note } : {}),
      ...(event.until !== undefined ? { until: event.until } : {}),
    })),
  }
}

function appendEvent(state: AttentionState, event: Omit<AttentionEvent, 'id'>): void {
  if (state.events.length >= ATTENTION_EVENT_LIMIT) {
    throw new Error(`attention history capacity of ${ATTENTION_EVENT_LIMIT} events reached`)
  }
  state.events.push({ id: randomUUID(), ...event })
}

function nextRevision(revision: number): number {
  if (!Number.isSafeInteger(revision) || revision < 1 || revision >= Number.MAX_SAFE_INTEGER) {
    throw new AttentionStateUnavailableError('attention workflow revision cannot be advanced safely')
  }
  return revision + 1
}

export function emptyAttentionState(): AttentionState {
  return {
    formatVersion: ATTENTION_FORMAT_VERSION,
    concepts: Object.create(null) as Record<string, AttentionConceptState>,
    events: [],
  }
}

/** Reconcile machine-observed source versions with human workflow. Freshness
 * can choose the initial state, but it never closes existing human work. */
export function reconcileAttention(
  input: AttentionState,
  concepts: ConceptStatusEntry[],
  now = new Date().toISOString(),
): AttentionReconciliation {
  const nowMs = requireTimestamp(now, 'now')
  const state = cloneState(input)
  let changed = false

  for (const concept of concepts) {
    const existing = Object.hasOwn(state.concepts, concept.slug)
      ? state.concepts[concept.slug]
      : undefined
    if (!existing) {
      state.concepts[concept.slug] = {
        snapshot: concept.snapshot,
        revision: 1,
        workflow: concept.status === 'fresh' ? 'done' : 'open',
        firstSeenAt: now,
      }
      changed = true
      continue
    }

    if (existing.snapshot !== concept.snapshot) {
      state.concepts[concept.slug] = {
        snapshot: concept.snapshot,
        revision: nextRevision(existing.revision),
        workflow: 'open',
        firstSeenAt: now,
      }
      appendEvent(state, {
        slug: concept.slug,
        snapshot: concept.snapshot,
        type: 'source-reopened',
        at: now,
      })
      changed = true
      continue
    }

    if (
      existing.workflow === 'snoozed' &&
      (!existing.snoozedUntil || requireTimestamp(existing.snoozedUntil, 'snoozedUntil') <= nowMs)
    ) {
      state.concepts[concept.slug] = {
        ...existing,
        revision: nextRevision(existing.revision),
        workflow: 'open',
        snoozedUntil: undefined,
      }
      appendEvent(state, {
        slug: concept.slug,
        snapshot: concept.snapshot,
        type: 'reopened',
        at: now,
      })
      changed = true
    }
  }

  return { state, changed }
}

function normalizedNote(request: AttentionActionRequest): string | undefined {
  if (request.note === undefined) return undefined
  if (typeof request.note !== 'string') throw new AttentionRequestError('attention note must be a string')
  if (request.note.length > ATTENTION_NOTE_LIMIT) {
    throw new AttentionRequestError('attention note exceeds the 10,000 code-unit limit')
  }
  const note = request.note.trim()
  return note || undefined
}

/** Apply one explicit reader action. The current concept snapshot is supplied
 * by the caller so stale tabs cannot close a newer version. */
export function applyAttentionAction(
  input: AttentionState,
  concepts: ConceptStatusEntry[],
  request: AttentionActionRequest,
  now = new Date().toISOString(),
): AttentionState {
  const nowMs = requireTimestamp(now, 'now')
  if (!request || typeof request !== 'object') throw new AttentionRequestError('attention action must be an object')
  if (typeof request.slug !== 'string' || request.slug.length === 0 || request.slug.length > MAX_SLUG_LENGTH) {
    throw new AttentionRequestError('attention action has an invalid concept slug')
  }
  const concept = concepts.find((candidate) => candidate.slug === request.slug)
  if (!concept) throw new AttentionRequestError(`unknown concept: ${request.slug}`)
  if (typeof request.snapshot !== 'string' || request.snapshot !== concept.snapshot) {
    throw new AttentionConflictError('attention action snapshot does not match the current concept snapshot')
  }
  if (!ACTIONS.has(request.action)) {
    throw new AttentionRequestError(`unsupported attention action: ${String(request.action)}`)
  }
  const current = input.concepts[concept.slug]
  if (!current || current.snapshot !== concept.snapshot) {
    throw new AttentionConflictError('attention state is not reconciled to the current concept snapshot')
  }
  if (!Number.isSafeInteger(request.revision) || request.revision < 1) {
    throw new AttentionRequestError('attention action has an invalid workflow revision')
  }
  if (request.revision !== current.revision) {
    throw new AttentionConflictError('attention action workflow revision is stale')
  }
  if (input.events.length >= ATTENTION_EVENT_LIMIT) {
    throw new AttentionStateUnavailableError(
      `attention history capacity of ${ATTENTION_EVENT_LIMIT} events reached`,
    )
  }

  const note = normalizedNote(request)
  if ((request.action === 'understood' || request.action === 'decided') && !note) {
    throw new AttentionRequestError(
      `${request.action} requires a note explaining the understanding or decision`,
    )
  }

  const state = cloneState(input)
  if (request.action === 'snooze') {
    if (typeof request.until !== 'string') {
      throw new AttentionRequestError('snooze requires a future until timestamp')
    }
    let untilMs: number
    try {
      untilMs = requireTimestamp(request.until, 'snooze until')
    } catch (error) {
      throw new AttentionRequestError(error instanceof Error ? error.message : String(error))
    }
    if (untilMs <= nowMs) throw new AttentionRequestError('snooze until must be in the future')
    if (untilMs - nowMs > MAX_SNOOZE_MS) {
      throw new AttentionRequestError('snooze cannot exceed 365 days')
    }
    const until = new Date(untilMs).toISOString()
    state.concepts[concept.slug] = {
      ...current,
      revision: nextRevision(current.revision),
      workflow: 'snoozed',
      snoozedUntil: until,
    }
    appendEvent(state, {
      slug: concept.slug,
      snapshot: concept.snapshot,
      type: 'snoozed',
      at: now,
      ...(note ? { note } : {}),
      until,
    })
    return state
  }

  if (request.action === 'reopen') {
    state.concepts[concept.slug] = {
      ...current,
      revision: nextRevision(current.revision),
      workflow: 'open',
      snoozedUntil: undefined,
    }
    appendEvent(state, {
      slug: concept.slug,
      snapshot: concept.snapshot,
      type: 'reopened',
      at: now,
      ...(note ? { note } : {}),
    })
    return state
  }

  state.concepts[concept.slug] = {
    ...current,
    revision: nextRevision(current.revision),
    workflow: 'done',
    snoozedUntil: undefined,
    lastReviewedAt: now,
    lastOutcome: request.action,
  }
  appendEvent(state, {
    slug: concept.slug,
    snapshot: concept.snapshot,
    type: 'reviewed',
    at: now,
    outcome: request.action,
    ...(note ? { note } : {}),
  })
  return state
}

export function attentionStatePath(root: string): string {
  const raw = git(root, ['rev-parse', '--git-path', 'repo-atlas/attention-v1.json']).trim()
  return path.isAbsolute(raw) ? path.normalize(raw) : path.resolve(root, raw)
}

/** Best-effort mechanical evidence for a concept change. No prose is inferred:
 * the result is only paths Git can prove changed since the stamped anchor,
 * plus currently broken declared sources. */
export function conceptChangedPaths(root: string, concept: ConceptStatusEntry): string[] {
  const changed = new Set(concept.brokenSources)
  if (concept.sources.length === 0) return [...changed].sort()
  if (concept.anchor && /^[a-f0-9]{7,64}$/i.test(concept.anchor)) {
    try {
      const raw = git(root, [
        'diff', '--name-only', '--no-renames', '-z', concept.anchor, '--', ...concept.sources,
      ])
      for (const entry of raw.split('\0')) if (entry) changed.add(entry)
    } catch {
      // An expired/unavailable anchor leaves declared sources as the fallback evidence.
    }
  }
  try {
    const raw = git(root, ['ls-files', '--others', '--exclude-standard', '-z', '--', ...concept.sources])
    for (const entry of raw.split('\0')) if (entry) changed.add(entry)
  } catch {
    // Static/uninitialized repositories may not have an index yet.
  }
  return [...changed].sort()
}

function parseConceptState(value: unknown): value is AttentionConceptState {
  if (!isRecord(value)) return false
  if (!hasOnlyFields(value, CONCEPT_STATE_FIELDS)) return false
  if (typeof value.snapshot !== 'string' || !SNAPSHOT_PATTERN.test(value.snapshot)) return false
  if (!Number.isSafeInteger(value.revision) || (value.revision as number) < 1) return false
  if (typeof value.workflow !== 'string' || !WORKFLOWS.has(value.workflow)) return false
  if (!validTimestamp(value.firstSeenAt)) return false
  if (value.snoozedUntil !== undefined && !validTimestamp(value.snoozedUntil)) return false
  if (value.lastReviewedAt !== undefined && !validTimestamp(value.lastReviewedAt)) return false
  if (value.lastOutcome !== undefined && (
    typeof value.lastOutcome !== 'string' || !OUTCOMES.has(value.lastOutcome as AttentionOutcome)
  )) return false
  return true
}

function parseEvent(value: unknown): value is AttentionEvent {
  if (!isRecord(value)) return false
  if (!hasOnlyFields(value, EVENT_FIELDS)) return false
  if (typeof value.id !== 'string' || value.id.length === 0 || value.id.length > MAX_ID_LENGTH) return false
  if (typeof value.slug !== 'string' || value.slug.length === 0 || value.slug.length > MAX_SLUG_LENGTH) return false
  if (typeof value.snapshot !== 'string' || !SNAPSHOT_PATTERN.test(value.snapshot)) return false
  if (typeof value.type !== 'string' || !EVENT_TYPES.has(value.type)) return false
  if (!validTimestamp(value.at)) return false
  if (value.outcome !== undefined && (
    typeof value.outcome !== 'string' || !OUTCOMES.has(value.outcome as AttentionOutcome)
  )) return false
  if (value.note !== undefined && (
    typeof value.note !== 'string' || value.note.length > ATTENTION_NOTE_LIMIT
  )) return false
  if (value.until !== undefined && !validTimestamp(value.until)) return false
  return true
}

function parseState(value: unknown): AttentionState | null {
  if (!isRecord(value) || value.formatVersion !== ATTENTION_FORMAT_VERSION) return null
  if (!hasOnlyFields(value, STATE_FIELDS)) return null
  if (!isRecord(value.concepts) || !Array.isArray(value.events)) return null
  const conceptEntries = Object.entries(value.concepts)
  if (conceptEntries.length > ATTENTION_CONCEPT_LIMIT || value.events.length > ATTENTION_EVENT_LIMIT) return null
  for (const [slug, concept] of conceptEntries) {
    if (slug.length === 0 || slug.length > MAX_SLUG_LENGTH || !parseConceptState(concept)) return null
  }
  if (!value.events.every(parseEvent)) return null
  return value as unknown as AttentionState
}

function diagnostic(code: string, message: string): AttentionLoadResult {
  return { state: null, diagnostics: [{ code, message }] }
}

function safeStateDirectory(file: string, create: boolean): void {
  const directory = path.dirname(file)
  const stat = fs.lstatSync(directory, { throwIfNoEntry: false })
  if (stat) {
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new Error(`attention state directory is not a safe directory: ${directory}`)
    }
    return
  }
  if (create) {
    try {
      fs.mkdirSync(directory, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (!isRecord(error) || error.code !== 'EEXIST') throw error
      const created = fs.lstatSync(directory, { throwIfNoEntry: false })
      if (!created || created.isSymbolicLink() || !created.isDirectory()) throw error
    }
  }
}

interface AttentionLock {
  fd: number
  file: string
  device: number
  inode: number
}

function processExists(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return !isRecord(error) || error.code !== 'ESRCH'
  }
}

/** Reap only a lock whose same-host owner PID is provably gone. Unknown,
 * malformed, remote-host, and live locks fail closed. */
function reapStaleAttentionLock(file: string): boolean {
  const noFollow = fs.constants.O_NOFOLLOW ?? 0
  const nonBlocking = fs.constants.O_NONBLOCK ?? 0
  let fd: number | null = null
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow | nonBlocking)
    const opened = fs.fstatSync(fd)
    if (!opened.isFile() || opened.size > ATTENTION_LOCK_BYTES) return false
    const decoded = JSON.parse(fs.readFileSync(fd, 'utf8')) as unknown
    if (
      !isRecord(decoded) || decoded.hostname !== os.hostname() ||
      !Number.isSafeInteger(decoded.pid) || (decoded.pid as number) < 1 ||
      processExists(decoded.pid as number)
    ) return false
    fs.closeSync(fd)
    fd = null
    const current = fs.lstatSync(file, { throwIfNoEntry: false })
    if (
      !current || current.isSymbolicLink() || !current.isFile() ||
      current.dev !== opened.dev || current.ino !== opened.ino
    ) return false
    fs.unlinkSync(file)
    return true
  } catch {
    return false
  } finally {
    if (fd !== null) fs.closeSync(fd)
  }
}

function acquireAttentionLock(root: string): AttentionLock {
  const stateFile = attentionStatePath(root)
  safeStateDirectory(stateFile, true)
  const file = `${stateFile}.lock`
  const deadline = Date.now() + ATTENTION_LOCK_TIMEOUT_MS
  const waiter = new Int32Array(new SharedArrayBuffer(4))
  const noFollow = fs.constants.O_NOFOLLOW ?? 0

  while (true) {
    try {
      const fd = fs.openSync(
        file,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | noFollow,
        0o600,
      )
      try {
        fs.writeFileSync(fd, `${JSON.stringify({
          pid: process.pid,
          hostname: os.hostname(),
          token: randomUUID(),
        })}\n`, 'utf8')
        fs.fsyncSync(fd)
        const opened = fs.fstatSync(fd)
        return { fd, file, device: opened.dev, inode: opened.ino }
      } catch (error) {
        fs.closeSync(fd)
        try { fs.unlinkSync(file) } catch { /* best effort after failed creation */ }
        throw error
      }
    } catch (error) {
      if (!isRecord(error) || error.code !== 'EEXIST') throw error
      const existing = fs.lstatSync(file, { throwIfNoEntry: false })
      if (!existing) continue
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new AttentionConflictError('attention state lock must be a regular non-symlink file')
      }
      if (reapStaleAttentionLock(file)) continue
      if (Date.now() >= deadline) {
        throw new AttentionConflictError('attention state is busy in another process')
      }
      Atomics.wait(waiter, 0, 0, ATTENTION_LOCK_RETRY_MS)
    }
  }
}

function releaseAttentionLock(lock: AttentionLock): void {
  fs.closeSync(lock.fd)
  const current = fs.lstatSync(lock.file, { throwIfNoEntry: false })
  if (
    current && !current.isSymbolicLink() && current.isFile() &&
    current.dev === lock.device && current.ino === lock.inode
  ) fs.unlinkSync(lock.file)
}

function withAttentionLock<T>(root: string, operation: () => T): T {
  const lock = acquireAttentionLock(root)
  try {
    return operation()
  } finally {
    releaseAttentionLock(lock)
  }
}

export function loadAttentionState(root: string): AttentionLoadResult {
  const file = attentionStatePath(root)
  try {
    safeStateDirectory(file, false)
  } catch (error) {
    return diagnostic('unsafe-state-directory', error instanceof Error ? error.message : String(error))
  }
  const stat = fs.lstatSync(file, { throwIfNoEntry: false })
  if (!stat) return { state: emptyAttentionState(), diagnostics: [] }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    return diagnostic('unsafe-state-file', 'attention state must be a regular non-symlink file')
  }
  if (stat.size > ATTENTION_STATE_BYTES) {
    return diagnostic('state-too-large', `attention state exceeds ${ATTENTION_STATE_BYTES} bytes`)
  }

  let raw: string
  try {
    const noFollow = fs.constants.O_NOFOLLOW ?? 0
    const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow)
    try {
      const opened = fs.fstatSync(fd)
      if (!opened.isFile() || opened.size > ATTENTION_STATE_BYTES) {
        return diagnostic('unsafe-state-file', 'attention state changed while it was being opened')
      }
      const bounded = Buffer.alloc(Math.min(opened.size + 1, ATTENTION_STATE_BYTES + 1))
      let offset = 0
      while (offset < bounded.length) {
        const read = fs.readSync(fd, bounded, offset, bounded.length - offset, null)
        if (read === 0) break
        offset += read
      }
      if (offset > ATTENTION_STATE_BYTES) {
        return diagnostic('state-too-large', `attention state exceeds ${ATTENTION_STATE_BYTES} bytes`)
      }
      raw = bounded.subarray(0, offset).toString('utf8')
    } finally {
      fs.closeSync(fd)
    }
  } catch (error) {
    return diagnostic('unreadable-state', error instanceof Error ? error.message : String(error))
  }

  let decoded: unknown
  try {
    decoded = JSON.parse(raw)
  } catch {
    return diagnostic('invalid-json', 'attention state is not valid JSON')
  }
  const state = parseState(decoded)
  if (!state) return diagnostic('invalid-state', 'attention state does not match formatVersion 1')
  return { state: cloneState(state), diagnostics: [] }
}

function writeAttentionState(root: string, state: AttentionState): void {
  if (!parseState(state)) throw new Error('refusing to persist invalid attention state')
  const file = attentionStatePath(root)
  safeStateDirectory(file, true)

  const existing = fs.lstatSync(file, { throwIfNoEntry: false })
  if (existing) {
    if (existing.isSymbolicLink() || !existing.isFile()) {
      throw new Error('refusing to replace an unsafe attention state file')
    }
    const loaded = loadAttentionState(root)
    if (!loaded.state) throw new Error('refusing to overwrite an invalid attention state file')
  }

  const contents = `${JSON.stringify(state, null, 2)}\n`
  if (Buffer.byteLength(contents) > ATTENTION_STATE_BYTES) {
    throw new Error(`attention state exceeds ${ATTENTION_STATE_BYTES} bytes`)
  }
  const temporary = path.join(path.dirname(file), `.attention-v1.json.tmp-${process.pid}-${randomUUID()}`)
  let fd: number | null = null
  try {
    fd = fs.openSync(temporary, 'wx', 0o600)
    fs.writeFileSync(fd, contents, 'utf8')
    fs.fsyncSync(fd)
    fs.closeSync(fd)
    fd = null
    fs.renameSync(temporary, file)
    let directoryFd: number | null = null
    try {
      directoryFd = fs.openSync(path.dirname(file), fs.constants.O_RDONLY)
      fs.fsyncSync(directoryFd)
    } catch (error) {
      if (!isRecord(error) || !UNSUPPORTED_DIRECTORY_FSYNC.has(String(error.code))) throw error
      // Some platforms/filesystems explicitly do not support syncing a
      // directory handle. I/O and capacity failures still propagate.
    } finally {
      if (directoryFd !== null) fs.closeSync(directoryFd)
    }
  } catch (error) {
    if (fd !== null) fs.closeSync(fd)
    try {
      fs.unlinkSync(temporary)
    } catch {
      // The temporary may already have been renamed or never created.
    }
    throw error
  }
}

export function saveAttentionState(root: string, state: AttentionState): void {
  withAttentionLock(root, () => writeAttentionState(root, state))
}

/** Run one read-modify-write cycle under the worktree-local cross-process
 * lock. Higher-level state transitions use this primitive so an atomic rename
 * cannot hide a lost update from another Atlas process. */
export function updateAttentionState(
  root: string,
  update: (state: AttentionState) => AttentionState,
): AttentionState {
  return withAttentionLock(root, () => {
    const loaded = loadAttentionState(root)
    if (!loaded.state) {
      const reason = loaded.diagnostics.map((entry) => `${entry.code}: ${entry.message}`).join('; ')
      throw new AttentionStateUnavailableError(reason || 'attention state is unavailable')
    }
    const next = update(loaded.state)
    writeAttentionState(root, next)
    return cloneState(next)
  })
}

export function reconcileStoredAttention(
  root: string,
  concepts: ConceptStatusEntry[],
  now = new Date().toISOString(),
): AttentionLoadResult {
  return withAttentionLock(root, () => {
    const loaded = loadAttentionState(root)
    if (!loaded.state) return loaded
    const reconciled = reconcileAttention(loaded.state, concepts, now)
    if (reconciled.changed) writeAttentionState(root, reconciled.state)
    return { state: reconciled.state, diagnostics: [] }
  })
}

export function applyStoredAttentionAction(
  root: string,
  concepts: ConceptStatusEntry[],
  request: AttentionActionRequest,
  now = new Date().toISOString(),
): AttentionState {
  return updateAttentionState(root, (state) => {
    const reconciled = reconcileAttention(state, concepts, now).state
    return applyAttentionAction(reconciled, concepts, request, now)
  })
}

/** Build the viewer projection without conflating source health with human
 * workflow. A static build gets a useful read-only initial projection; a live
 * build supplies the reconciled clone-local state. */
export function buildAttentionPayload(
  status: ComputeStatusResult,
  options: AttentionPayloadOptions = {},
): AttentionPayload {
  const now = options.now ?? new Date().toISOString()
  requireTimestamp(now, 'now')
  const mode = options.mode ?? 'static'
  const invalid = options.state === null
  const sourceState = options.state ?? emptyAttentionState()
  const reconciled = reconcileAttention(sourceState, status.concepts, now).state
  const changedPaths = options.changedPaths ?? {}

  const items: AttentionItem[] = status.concepts.map((concept) => {
    const subject = reconciled.concepts[concept.slug]
    return {
      id: `concept:${concept.slug}:${concept.snapshot}`,
      slug: concept.slug,
      title: concept.title,
      audience: concept.audience,
      chapter: concept.chapter,
      conceptStatus: concept.status,
      workflow: subject.workflow,
      snapshot: concept.snapshot,
      revision: subject.revision,
      sources: [...concept.sources],
      brokenSources: [...concept.brokenSources],
      changedPaths: [...(changedPaths[concept.slug] ?? [])],
      stamped: concept.stamped,
      anchor: concept.anchor,
      firstSeenAt: subject.firstSeenAt,
      ...(subject.snoozedUntil ? { snoozedUntil: subject.snoozedUntil } : {}),
      ...(subject.lastReviewedAt ? { lastReviewedAt: subject.lastReviewedAt } : {}),
      ...(subject.lastOutcome ? { lastOutcome: subject.lastOutcome } : {}),
    }
  })
  const rank = { open: 0, snoozed: 1, done: 2 } as const
  items.sort((left, right) => rank[left.workflow] - rank[right.workflow])

  const documentEntries = status.entries.filter((entry) => entry.path !== '')
  const documents = {
    outdated: documentEntries.filter((entry) => entry.status === 'outdated').length,
    missing: documentEntries.filter((entry) => entry.status === 'missing').length,
    ignored: documentEntries.filter((entry) => entry.status === 'ignored').length,
    total: documentEntries.length,
  }
  const health = {
    documents,
    concepts: {
      fresh: status.concepts.filter((concept) => concept.status === 'fresh').length,
      outdated: status.concepts.filter((concept) => concept.status === 'outdated').length,
      brokenSource: status.concepts.filter((concept) => concept.status === 'broken-source').length,
      total: status.concepts.length,
    },
    brokenReferences: status.brokenRefs.length,
    orphans: status.orphans.length,
  }

  return {
    mode,
    state: invalid ? 'invalid' : 'ready',
    generatedAt: now,
    items,
    events: invalid ? [] : reconciled.events.map((event) => ({ ...event })),
    summary: {
      open: items.filter((item) => item.workflow === 'open').length,
      snoozed: items.filter((item) => item.workflow === 'snoozed').length,
      done: items.filter((item) => item.workflow === 'done').length,
      history: invalid ? 0 : reconciled.events.length,
    },
    health,
    diagnostics: (options.diagnostics ?? []).map((entry) => ({ ...entry })),
  }
}
