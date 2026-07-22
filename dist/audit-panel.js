/**
 * Pure panel-open policy for audit routes.
 * Keeps desktop Code/Concepts open by default; operational views start closed
 * and only auto-close once when first entered from a browse primary view.
 */
/** Compact is always closed; operational entry is closed; Code/Concepts open. */
export function initialPanelOpen(compact, primaryView) {
    if (compact)
        return false;
    return primaryView === 'code' || primaryView === 'concepts';
}
/**
 * Close the generic code panel only when entering an operational view from
 * Code/Concepts. Staying in or moving between operations must not re-close an
 * explicitly reopened panel; leaving an audit never closes.
 */
export function shouldClosePanelOnPrimaryTransition(previous, next) {
    const fromBrowse = previous === 'code' || previous === 'concepts';
    const toOperational = next === 'attention' || next === 'security' || next === 'tests';
    return fromBrowse && toOperational;
}
