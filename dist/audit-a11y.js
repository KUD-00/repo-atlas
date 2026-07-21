/**
 * Viewer accessibility contracts for compact sidebar chrome and audit panes.
 * Pure helpers so the contracts stay unit-testable without mounting React.
 */
/** Compact drawer aside: closed → inert + aria-hidden (out of a11y/keyboard tree). */
export function compactSidebarA11y(sideOpen) {
    if (sideOpen)
        return {};
    return { inert: true, 'aria-hidden': true };
}
/**
 * Restore focus to the compact header expand control after the drawer closes
 * (overlay click, collapse button, or route onSelect). Desktop is excluded.
 */
export function shouldRestoreCompactSidebarFocus(compact, wasOpen, isOpen) {
    return compact && wasOpen && !isOpen;
}
/** Stable, domain-scoped ids for a unit section toggle + findings panel. */
export function auditUnitSectionIds(domain, slug) {
    const safe = slug.replace(/[^a-zA-Z0-9_-]+/gu, '-').replace(/^-+|-+$/gu, '') || 'unit';
    return {
        toggleId: `audit-${domain}-unit-${safe}-toggle`,
        panelId: `audit-${domain}-unit-${safe}-panel`,
    };
}
export function auditUnitToggleProps(open, panelId) {
    return { 'aria-expanded': open, 'aria-controls': panelId };
}
/** Keep the panel mounted with `hidden` rather than unmounting, for stable ids. */
export function auditUnitPanelProps(open) {
    return { hidden: !open };
}
/** aria-pressed for severity / impact / category / stale filter chips. */
export function auditFilterChipAriaPressed(selected) {
    return selected;
}
