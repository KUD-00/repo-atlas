import { useEffect, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { ArrowUpLeft, CornerDownRight } from 'lucide-react'
import type { TreeNode } from '../src/types'
import { ancestorsOf } from './lib'
import { Collapse } from './Tree'

/**
 * Nearest base point containing `path` — the "book" the reader is inside.
 * Base points come from config.json; repo root is the implicit fallback.
 */
export function baseFor(path: string, basePoints: string[]): string {
  let best = ''
  for (const bp of basePoints) {
    if ((path === bp || path.startsWith(bp + '/')) && bp.length > best.length) best = bp
  }
  return best
}

/** One row of the contents tree. Pure reading structure: names, reading-order
 * ranks and the current position — no maintenance status. */
function TocRow({
  node, depth, rank, current, expanded, onToggle,
}: {
  node: TreeNode
  depth: number
  rank?: number
  current: string
  expanded: Set<string>
  onToggle: (p: string) => void
}) {
  if (node.status === 'ignored') return null
  const isDir = node.type === 'dir'
  const kids = isDir ? node.children.filter((c) => c.status !== 'ignored') : []
  const open = expanded.has(node.path)
  const rankOf = new Map((node.order ?? []).map((name, i) => [name, i + 1]))
  return (
    <>
      <div
        className={'row toc-row' + (node.path === current ? ' sel' : '')}
        style={{ paddingLeft: depth * 14 }}
        onClick={() => (isDir ? onToggle(node.path) : (location.hash = '#' + encodeURI(node.path)))}
      >
        <span className={'twist' + (open ? ' open' : '')}>{kids.length > 0 ? '▸' : ''}</span>
        <span className={'name' + (isDir ? ' dir' : '')}>{node.name + (isDir ? '/' : '')}</span>
        {rank !== undefined && <span className="ord">{rank}</span>}
        {isDir && (
          <button
            className="toc-goto"
            onClick={(e) => {
              e.stopPropagation()
              location.hash = '#' + encodeURI(node.path)
            }}
          >
            <CornerDownRight />
          </button>
        )}
      </div>
      {kids.length > 0 && (
        <Collapse open={open}>
          {kids.map((c) => (
            <TocRow
              key={c.path}
              node={c}
              depth={depth + 1}
              rank={rankOf.get(c.name)}
              current={current}
              expanded={expanded}
              onToggle={onToggle}
            />
          ))}
        </Collapse>
      )}
    </>
  )
}

/**
 * Contents view of the panel: the reading tree of the "book" the current page
 * belongs to (nearest base point), current position expanded and highlighted.
 */
export function TocView({
  node, nodesByPath, basePoints, repoName,
}: {
  node: TreeNode
  nodesByPath: Map<string, TreeNode>
  basePoints: string[]
  repoName: string
}) {
  const { i18n } = useLingui()
  const base = baseFor(node.path, basePoints)
  const root = nodesByPath.get(base) ?? nodesByPath.get('')!
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set(ancestorsOf(node.path).concat(node.type === 'dir' ? [node.path] : [])),
  )
  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev)
      for (const p of ancestorsOf(node.path)) next.add(p)
      if (node.type === 'dir') next.add(node.path)
      return next
    })
  }, [node])
  useEffect(() => {
    document.querySelector('.toc-pane .toc-row.sel')?.scrollIntoView({ block: 'nearest' })
  }, [node, base])
  const toggle = (p: string) =>
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(p) ? next.delete(p) : next.add(p)
      return next
    })
  const rankOf = new Map((root.order ?? []).map((name, i) => [name, i + 1]))
  const parentBase = base ? baseFor(base.slice(0, base.lastIndexOf('/')), basePoints) : null
  return (
    <div className="toc-pane">
      {base !== '' && (
        <button
          className="toc-up"
          title={t(i18n)`up to the enclosing tree`}
          onClick={() => (location.hash = '#' + encodeURI(parentBase ?? ''))}
        >
          <ArrowUpLeft />
          {parentBase ? parentBase : repoName}
        </button>
      )}
      {root.children
        .filter((c) => c.status !== 'ignored')
        .map((c) => (
          <TocRow
            key={c.path}
            node={c}
            depth={0}
            rank={rankOf.get(c.name)}
            current={node.path}
            expanded={expanded}
            onToggle={toggle}
          />
        ))}
    </div>
  )
}
