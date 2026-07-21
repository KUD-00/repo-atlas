import { auditLocationJumpDetail } from '../src/audit-location'

const CHIP =
  'inline-flex items-center gap-1 text-[0.68rem] font-semibold py-px px-[7px] rounded-md border whitespace-nowrap'

/** Shared source-location control for security and test findings. */
export function AuditLocation({ loc }: { loc: string }) {
  const target = auditLocationJumpDetail(loc)
  if (!target) {
    return (
      <span className={CHIP + ' text-muted bg-panel border-border font-mono font-normal'}>{loc}</span>
    )
  }
  return (
    <button
      type="button"
      className={
        CHIP +
        ' font-mono font-normal text-accent bg-[#3d6b540d] border-[#3d6b5426] cursor-pointer hover:bg-[#3d6b541f] focus:outline-none focus-visible:border-accent focus-visible:ring-2 focus-visible:ring-accent/30'
      }
      title={loc}
      onClick={() =>
        window.dispatchEvent(
          new CustomEvent('atlas-code-jump', {
            detail: { path: target.path, line: target.line, endLine: target.endLine },
          }),
        )
      }
    >
      {loc}
    </button>
  )
}
