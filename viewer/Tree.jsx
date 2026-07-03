/** Left-hand tree. Normal mode: collapsible hierarchy (children of collapsed
 * dirs are simply not rendered). Filter mode: flat list of matches. */

function Dot({ status }) {
  return <span className={'dot ' + status} />
}

function Row({ node, depth, flat, expandable, open, selected, onClick, onTwist }) {
  return (
    <div
      className={'row' + (selected ? ' sel' : '')}
      style={{ paddingLeft: depth * 14 }}
      onClick={onClick}
    >
      <span className="twist" onClick={onTwist}>
        {expandable ? (open ? '▾' : '▸') : ''}
      </span>
      <Dot status={node.status} />
      <span className={'name' + (node.type === 'dir' ? ' dir' : '')}>
        {(flat ? node.path : node.name) + (node.type === 'dir' ? '/' : '')}
      </span>
      {node.type === 'dir' && node.agg.outdated > 0 && (
        <span className="badge warn">{node.agg.outdated}</span>
      )}
      {node.type === 'dir' && node.agg.missing > 0 && (
        <span className="badge">{node.agg.missing}</span>
      )}
    </div>
  )
}

function TreeNode({ node, depth, selected, expanded, onSelect, onToggle }) {
  const expandable = node.children.length > 0
  const open = expanded.has(node.path)
  return (
    <>
      <Row
        node={node}
        depth={depth}
        expandable={expandable}
        open={open}
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
      {open &&
        node.children.map((c) => (
          <TreeNode
            key={c.path}
            node={c}
            depth={depth + 1}
            selected={selected}
            expanded={expanded}
            onSelect={onSelect}
            onToggle={onToggle}
          />
        ))}
    </>
  )
}

export function Tree({ root, selected, expanded, query, statusFilter, onSelect, onToggle }) {
  if (!query && !statusFilter) {
    return (
      <TreeNode
        node={root}
        depth={0}
        selected={selected}
        expanded={expanded}
        onSelect={onSelect}
        onToggle={onToggle}
      />
    )
  }
  const matches = []
  ;(function walk(n) {
    const hit =
      (!query || n.path.toLowerCase().includes(query)) &&
      (!statusFilter || n.status === statusFilter)
    if (hit && n.path !== '') matches.push(n)
    n.children.forEach(walk)
  })(root)
  if (!matches.length) return <div className="empty" style={{ padding: '8px 12px' }}>no matches</div>
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
