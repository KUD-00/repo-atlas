export interface AtlasConfig {
  formatVersion?: number
  exclude?: string[]
  output?: string
  /** Self-contained subtrees ("books"): the contents view roots at the nearest
   * one instead of the file's immediate parent. Repo root is the implicit fallback. */
  basePoints?: string[]
}

export interface ScanResult {
  files: Map<string, string>
  dirs: Map<string, string>
  ignored: Set<string>
}

export interface ParsedNote {
  hash: string | null
  anchor: string | null
  dirty: boolean
  stamped: string | null
  /** Dir notes only: explicit reading order — child NAMES, a partial list.
   * Listed children read first (in this order); the rest follow the default
   * heuristic. Names that no longer exist are reported as broken refs. */
  order: string[] | null
  body: string
}

export interface NoteRecord extends ParsedNote {
  type: PathType
  file: string
}

export type PathType = 'file' | 'dir'
export type EntryStatus = 'fresh' | 'outdated' | 'missing' | 'moved' | 'ignored'

export interface StatusDelta {
  added: number
  removed: number
  files: number
}

export interface StatusEntry {
  path: string
  type: PathType
  status: EntryStatus
  stamped?: string | null
  anchor?: string | null
  body?: string
  noteFile?: string
  movedFrom?: string
  similarity?: number | null
  expectedNoteFile?: string
  delta?: StatusDelta
  order?: string[] | null
}

export interface Orphan {
  path: string
  type: PathType
  noteFile: string
}

export interface BrokenRef {
  note: string
  noteFile: string
  ref: string
  suggestion: string | null
}

export interface MoveRecord {
  from: string
  to: string
  type: PathType
  similarity: number | null
  votes?: number
}

export interface ComputeStatusResult {
  entries: StatusEntry[]
  orphans: Orphan[]
  brokenRefs: BrokenRef[]
  concepts: ConceptStatusEntry[]
  audits: import('./audits.js').AuditStatusEntry[]
  readability: import('./readability.js').ReadabilityStatus | null
}

export type ConceptAudience = 'dev' | 'general'

/** Concept-page freshness. No 'missing' — concept pages only exist once a
 * human writes them; 'broken-source' means a listed source left the scan. */
export type ConceptState = 'fresh' | 'outdated' | 'broken-source'

/** A concept page: an explainer anchored to a SET of repo paths (`sources`)
 * instead of a single path. Lives in .atlas/concepts/<slug>.md. */
export interface ConceptPage {
  slug: string
  file: string
  title: string
  audience: ConceptAudience
  /** Repo paths (files or dirs) this explanation is written against. */
  sources: string[]
  /** Curriculum reading position (sidebar sort key); null = unordered, sorts last. */
  order: number | null
  /** Curriculum chapter (sidebar group heading); null = ungrouped. */
  chapter: string | null
  /** sha1 over the sources' scan hashes (in `sources` order) at stamp time. */
  sourcesHash: string | null
  anchor: string | null
  stamped: string | null
  body: string
}

export interface ConceptStatusEntry {
  slug: string
  title: string
  audience: ConceptAudience
  chapter: string | null
  status: ConceptState
  sources: string[]
  /** Sources that no longer resolve in the scan. */
  brokenSources: string[]
  stamped: string | null
  anchor: string | null
  file: string
  body: string
}

export interface ImportGraph {
  paths: string[]
  edges: [number, number][]
  packageRoots: string[]
}

export interface GlossaryEntry {
  term: string
  aliases: string[]
  def: string
  /** Canonical home for this concept, declared via `归属:`/`home:`. Either a repo
   * path, or `concept:<slug>` to point at a concept page (its expand target). */
  home?: string
  /** Display title of `home` when it is a `concept:<slug>` page — filled at build. */
  homeTitle?: string
  /** Repo paths of notes whose prose references this term/alias — filled at build time. */
  refs?: string[]
}

export interface TreeAgg {
  outdated: number
  missing: number
  ignored: number
  total: number
}

export interface TreeNode {
  name: string
  path: string
  type: PathType
  status: EntryStatus
  stamped: string | null
  /** Commit the note was stamped against — the base for "changes since" review. */
  anchor: string | null
  html: string | null
  source: string | null
  /** Dir nodes: explicit reading-order head (child names), for ①② badges. */
  order?: string[] | null
  children: TreeNode[]
  agg?: TreeAgg
}

/** Concept page as the viewer consumes it (rendered body, no note file path). */
export interface ConceptNode {
  slug: string
  title: string
  audience: ConceptAudience
  chapter: string | null
  status: ConceptState
  sources: string[]
  brokenSources: string[]
  stamped: string | null
  anchor: string | null
  html: string | null
  source: string | null
}

/** Page artifact as the viewer consumes it: `.md` arrives rendered (same
 * markdown pipeline as notes), `.json` arrives raw for a code-block view. */
export interface ArtifactNode {
  name: string
  kind: 'md' | 'json'
  html: string | null
  raw: string | null
}

export type SecurityFindingDisposition = 'open' | 'accepted-risk' | 'separate-design'

export interface AuditFinding {
  id?: string
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
  category: string
  title: string
  /** `file:line` / `file#symbol` — the viewer turns the path part into a code jump. */
  locations: string[]
  dataflow: string
  fix: string
  /** 'unverified' when the factcheck gate could not confirm it from source. */
  confidence?: string
  disposition: SecurityFindingDisposition
}

export type AuditDomain = 'security' | 'test'
export type TestAuditImpact = 'blocking' | 'warning' | 'advisory'
export type TestAuditCategory =
  | 'missing-invariant' | 'weak-assertion' | 'mock-only' | 'nondeterminism'
  | 'isolation-leak' | 'fixture-drift' | 'coverage-gap' | 'privileged-side-effect'

export interface TestAuditFinding {
  impact: TestAuditImpact
  category: TestAuditCategory
  title: string
  invariant: string
  evidence: string
  fix: string
  locations: string[]
  confidence?: string
}

export interface BaseAuditUnit {
  formatVersion: 1 | 2
  domain: AuditDomain
  slug: string
  title: string
  ruleset: string
  scannedAt: string
  scopeHash: string
  fileCount: number
  files: string[]
  hashes: Record<string, string> | null
  evidenceRefs: string[]
  droppedCount: number
  roundCount: number
  /** Scope bytes drifted since the audit (recomputed at load) → needs a re-audit. */
  stale: boolean
}

export interface SecurityAuditUnit extends BaseAuditUnit {
  domain: 'security'
  findings: AuditFinding[]
  conceptSlug?: string
}

export interface TestAuditUnit extends BaseAuditUnit {
  domain: 'test'
  findings: TestAuditFinding[]
}

/** Legacy alias: security portfolio units only during the domain migration. */
export type AuditUnit = SecurityAuditUnit

export type ReviewCoverageVerdict = 'complete' | 'incomplete' | 'invalid'
export type CoverageEvidenceStatus = 'fresh' | 'missing' | 'stale' | 'invalid'

export interface CoverageUnitRef {
  domain: AuditDomain
  slug: string
  title: string
}

export type CoverageClassification =
  | { kind: 'review'; domains: Partial<Record<AuditDomain, { unit: string }>> }
  | { kind: 'excluded'; ruleId: string; category: string; reason: string; owner?: string }
  | { kind: 'unclassified' }
  | { kind: 'conflict' }

export interface CoverageEntry {
  path: string
  blob?: string
  ruleIds: string[]
  classification: CoverageClassification
  evidence: Partial<Record<AuditDomain, { status: CoverageEvidenceStatus; ledgers: string[] }>>
}

export interface CoverageDiagnostic {
  code: string
  message: string
  path?: string
  slug?: string
}

export interface ReviewCoverageSummary {
  tracked: number
  securityRequired: number
  securityFresh: number
  securityMissing: number
  securityStale: number
  securityInvalid: number
  testRequired: number
  testFresh: number
  testMissing: number
  testStale: number
  testInvalid: number
  dualRequired: number
  excluded: number
  unclassified: number
  conflicted: number
  invalidLedgers: number
}

export interface ReviewCoverageReport {
  formatVersion: 1
  format: 'atlas-review-coverage-v1'
  verdict: ReviewCoverageVerdict
  policy: { format: string; hash: string }
  inventoryHash: string
  units: CoverageUnitRef[]
  summary: ReviewCoverageSummary
  entries: CoverageEntry[]
  invalidLedgerDetails: CoverageDiagnostic[]
  reportErrors: CoverageDiagnostic[]
}

export interface ReviewCoveragePortfolio {
  state: 'missing' | 'invalid' | 'current' | 'stale'
  report: ReviewCoverageReport | null
  errors: CoverageDiagnostic[]
  drift: { added: string[]; removed: string[]; changed: string[] }
}

export interface AtlasPayload {
  repoName: string
  commit: string | null
  generatedAt: string
  tree: TreeNode
  orphans: string[]
  graph: ImportGraph | null
  glossary: GlossaryEntry[]
  basePoints: string[]
  concepts: ConceptNode[]
  /** Pipeline-produced files attached to pages, keyed by page key
   * (repo path, or `concepts/<slug>` for concept pages). */
  artifacts: Record<string, ArtifactNode[]>
  /** Security-audit units from `.atlas/audits/`, freshness-checked at load. */
  audits: AuditUnit[]
  /** Test-audit units from `.atlas/audits/`, freshness-checked at load. */
  testAudits: TestAuditUnit[]
  /** Closed-world review coverage portfolio (missing when no report). */
  reviewCoverage: ReviewCoveragePortfolio
}

export interface ChatMessage {
  id: string
  role: 'user' | 'agent'
  text: string
  time: number
  context?: string | null
  replyTo?: string | null
  system?: boolean
  cancelled?: boolean
}

export interface ChatStatusEvent {
  type: 'status'
  connected: boolean
  working: boolean
}

export interface ChatProgressEvent {
  type: 'progress'
  text: string | null
}

export interface ChatCancelledEvent {
  type: 'cancelled'
  id: string
}

export type ChatPollResponse = ChatMessage | { type: 'timeout' }
