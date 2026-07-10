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
  /** Canonical home note for this concept (a repo path), declared via `归属:`/`home:`. */
  home?: string
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