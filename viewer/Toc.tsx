import { useEffect, useState } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import { ArrowUpLeft, ChevronRight, CornerDownRight } from 'lucide-react'
import type { TreeNode } from '../src/types'
import { ancestorsOf } from './lib'
import { Collapse } from './Tree'

const ROW =
  'row group flex items-center gap-1.5 py-0.5 pr-2 pl-0 rounded-md cursor-pointer select-none text-[0.82rem] whitespace-nowrap hover:bg-[#00000006]'

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
  const selected = node.path === current
  return (
    <>
      <div
        className={
          ROW +
          ' py-[3px] pr-2 pl-1.5' +
          (selected ? ' sel bg-[#3d6b5414]' : '')
        }
        style={{ paddingLeft: depth * 14 }}
        onClick={() => (isDir ? onToggle(node.path) : (location.hash = '#' + encodeURI(node.path)))}
      >
        <span
          className={
            'w-4 shrink-0 flex items-center justify-center text-muted transition-transform duration-[160ms] ease-[ease] [&_svg]:w-3.5 [&_svg]:h-3.5' +
            (open ? ' open rotate-90' : '')
          }
        >
          {kids.length > 0 ? <ChevronRight /> : null}
        </span>
        <span className={'overflow-hidden text-ellipsis' + (isDir ? ' font-[550]' : '')}>
          {node.name + (isDir ? '/' : '')}
        </span>
        {rank !== undefined && (
          <span className="shrink-0 w-3.5 h-3.5 rounded-full ml-0.5 text-[0.6rem] leading-[14px] text-center text-accent bg-[#3d6b5414]">
            {rank}
          </span>
        )}
        {isDir && (
          <button
            className="ml-auto border-none bg-transparent cursor-pointer text-muted py-0 px-1 opacity-0 shrink-0 flex items-center group-hover:opacity-100 hover:text-accent [&_svg]:w-[13px] [&_svg]:h-[13px]"
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
    document.querySelector('.toc-pane .row.sel')?.scrollIntoView({ block: 'nearest' })
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
    <div className="toc-pane p-2">
      {base !== '' && (
        <button
          className="flex items-center gap-1.5 w-full font-inherit text-[0.76rem] font-mono border-none border-b border-border bg-transparent cursor-pointer text-muted py-0.5 px-1.5 pb-2 mb-1.5 hover:text-accent [&_svg]:w-[13px] [&_svg]:h-[13px] [&_svg]:shrink-0"
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