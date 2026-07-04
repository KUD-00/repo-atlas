export interface AtlasConfig {
  formatVersion?: number
  exclude?: string[]
  output?: string
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
  html: string | null
  source: string | null
  /** Dir nodes: explicit reading-order head (child names), for ①② badges. */
  order?: string[] | null
  children: TreeNode[]
  agg?: TreeAgg
}

export interface AtlasPayload {
  repoName: string
  commit: string | null
  generatedAt: string
  tree: TreeNode
  orphans: string[]
  graph: ImportGraph | null
  glossary: GlossaryEntry[]
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