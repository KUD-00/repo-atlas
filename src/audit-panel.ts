/**
 * Pure panel-open policy for audit routes.
 * Keeps desktop Code/Concepts open by default; Security/Tests start closed
 * and only auto-close once when first entered from a non-audit primary view.
 */

import type { PrimaryView } from './audit-routes.js'

/** Compact is always closed; desktop audit entry is closed; Code/Concepts open. */
export function initialPanelOpen(compact: boolean, primaryView: PrimaryView): boolean {
  if (compact) return false
  return primaryView === 'code' || primaryView === 'concepts'
}

/**
 * Close the generic code panel only when entering Security/Tests from
 * Code/Concepts. Staying in or moving between audits must not re-close an
 * explicitly reopened panel; leaving an audit never closes.
 */
export function shouldClosePanelOnPrimaryTransition(
  previous: PrimaryView,
  next: PrimaryView,
): boolean {
  const fromBrowse = previous === 'code' || previous === 'concepts'
  const toAudit = next === 'security' || next === 'tests'
  return fromBrowse && toAudit
}
