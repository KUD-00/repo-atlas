import { useEffect, useState, type ReactNode, type MouseEvent } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import type { EntryStatus, TreeNode } from '../src/types'

const ROW =
  'row flex items-center gap-1.5 py-0.5 pr-2 pl-0 rounded-md cursor-pointer select-none text-[0.82rem] whitespace-nowrap hover:bg-[#00000006]'
const EMPTY =
  'text-muted text-[0.9rem] mt-2 [&_code]:bg-[#00000009] [&_code]:py-[0.1em] [&_code]:px-[0.4em] [&_code]:rounded [&_code]:text-[0.85em]'

export function Collapse({ open, children }: { open: boolean; children: ReactNode }) {
  const [mounted, setMounted] = useState(open)
  const [expanded, setExpanded] = useState(open)
  useEffect(() => {
    if (open) setMounted(true)
    else setExpanded(false)
  }, [open])
  useEffect(() => {
    if (mounted && open) {
      const id = requestAnimationFrame(() => setExpanded(true))
      return () => cancelAnimationFrame(id)
    }
  }, [mounted, open])
  if (!mounted) return null
  return (
    <div
      className={'collapse' + (expanded ? ' open' : '')}
      onTransitionEnd={(e) => {
        if (e.target === e.currentTarget && !open) setMounted(false)
      }}
    >
      <div className="overflow-hidden min-h-0">{children}</div>
    </div>
  )
}

function dotClass(status: EntryStatus): string {
  const base = 'w-2 h-2 rounded-full shrink-0 '
  switch (status) {
    case 'fresh': return base + 'bg-fresh'
    case 'outdated': return base + 'bg-outdated'
    case 'missing': return base + 'bg-none border-[1.5px] border-missing'
    case 'ignored': return base + 'bg-missing opacity-[0.55]'
    default: return base
  }
}

function Dot({ status }: { status: EntryStatus }) {
  return <span className={dotClass(status)} />
}

function Row({
  node, depth, flat, expandable, open, selected, rank, onClick, onTwist,
}: {
  node: TreeNode
  depth: number
  flat?: boolean
  expandable?: boolean
  open?: boolean
  selected: boolean
  rank?: number
  onClick: () => void
  onTwist?: (e: MouseEvent) => void
}) {
  const { i18n } = useLingui()
  const ignored = node.status === 'ignored'
  return (
    <div
      className={
        ROW +
        (selected ? ' sel bg-[#3d6b5414]' : '') +
        (ignored ? ' ignored opacity-[0.45] hover:opacity-70' + (selected ? ' opacity-70' : '') : '')
      }
      style={{ paddingLeft: depth * 14 }}
      onClick={onClick}
    >
      <span
        className={
          'w-4 shrink-0 text-center text-muted text-[0.65rem] transition-transform duration-[160ms] ease-[ease]' +
          (open ? ' open rotate-90' : '')
        }
        onClick={onTwist}
      >
        {expandable ? '▸' : ''}
      </span>
      <Dot status={node.status} />
      <span className={'overflow-hidden text-ellipsis' + (node.type === 'dir' ? ' font-[550]' : '')}>
        {(flat ? node.path : node.name) + (node.type === 'dir' ? '/' : '')}
      </span>
      {rank !== undefined && (
        <span
          className="shrink-0 w-3.5 h-3.5 rounded-full ml-0.5 text-[0.6rem] leading-[14px] text-center text-accent bg-[#3d6b5414]"
          title={t(i18n)`pinned reading order`}
        >
          {rank}
        </span>
      )}
      {node.type === 'dir' && node.agg && node.agg.outdated > 0 && (
        <span className="ml-auto text-[0.65rem] px-1.5 rounded-full shrink-0 text-[#9a6a06] bg-[#d9930d1a]">
          {node.agg.outdated}
        </span>
      )}
      {node.type === 'dir' && node.agg && node.agg.missing > 0 && (
        <span className="ml-auto text-[0.65rem] px-1.5 rounded-full shrink-0 text-muted bg-[#00000008]">
          {node.agg.missing}
        </span>
      )}
    </div>
  )
}

function TreeNode({
  node, depth, selected, expanded, showIgnored, sortMode, rank, onSelect, onToggle,
}: {
  node: TreeNode
  depth: number
  selected: string
  expanded: Set<string>
  showIgnored: boolean
  sortMode: 'az' | 'read'
  rank?: number
  onSelect: (p: string) => void
  onToggle: (p: string) => void
}) {
  if (node.status === 'ignored' && !showIgnored) return null
  const expandable = node.children.some((c) => showIgnored || c.status !== 'ignored')
  const open = expanded.has(node.path)
  const rankOf = new Map((node.order ?? []).map((name, i) => [name, i + 1]))
  // children arrive reading-ordered from the build; a-z re-sorts for display only
  const shown = sortMode === 'az'
    ? [...node.children].sort((a, b) =>
        a.type !== b.type ? (a.type === 'dir' ? -1 : 1) : a.name < b.name ? -1 : 1)
    : node.children
  return (
    <>
      <Row
        node={node}
        depth={depth}
        expandable={expandable}
        open={open}
        rank={rank}
        selected={selected === node.path}
        onClick={() => {
          onSelect(node.path)
          if (node.type === 'dir') onToggle(node.path)
        }}
        onTwist={(e) => {
          e.stopPropagation()
          onToggle(node.path)
        }}
      />
      {expandable && (
        <Collapse open={open}>
          {shown.map((c) => (
            <TreeNode
              key={c.path}
              node={c}
              depth={depth + 1}
              selected={selected}
              expanded={expanded}
              showIgnored={showIgnored}
              sortMode={sortMode}
              rank={rankOf.get(c.name)}
              onSelect={onSelect}
              onToggle={onToggle}
            />
          ))}
        </Collapse>
      )}
    </>
  )
}

export function Tree({
  root, selected, expanded, query, statusFilter, showIgnored, sortMode, onSelect, onToggle,
}: {
  root: TreeNode
  selected: string
  expanded: Set<string>
  query: string
  statusFilter: string | null
  showIgnored: boolean
  sortMode: 'az' | 'read'
  onSelect: (p: string) => void
  onToggle: (p: string) => void
}) {
  if (!query && !statusFilter) {
    return (
      <TreeNode
        node={root}
        depth={0}
        selected={selected}
        expanded={expanded}
        showIgnored={showIgnored}
        sortMode={sortMode}
        onSelect={onSelect}
        onToggle={onToggle}
      />
    )
  }
  const matches: TreeNode[] = []
  ;(function walk(n: TreeNode) {
    const hit =
      (!query || n.path.toLowerCase().includes(query)) &&
      (statusFilter ? n.status === statusFilter : showIgnored || n.status !== 'ignored')
    if (hit && n.path !== '') matches.push(n)
    n.children.forEach(walk)
  })(root)
  const { i18n } = useLingui()
  if (!matches.length) {
    return <div className={EMPTY} style={{ padding: '8px 12px' }}>{t(i18n)`no matches`}</div>
  }
  return matches.map((n) => (
    <Row
      key={n.path}
      node={n}
      depth={0}
      flat
      expandable={false}
      selected={selected === n.path}
      onClick={() => onSelect(n.path)}
    />
  ))
}