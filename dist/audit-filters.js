/**
 * Visible filter chip keys: available counts union currently selected values,
 * listed in a caller-supplied canonical order (severity/impact enums, or a
 * pre-sorted open category list). Selected-only keys stay visible at count 0
 * so the chip remains clickable to clear after the focused unit changes.
 */
export function visibleFilterOptions(available, selected, order) {
    const avail = new Set(available);
    const sel = new Set(selected);
    return order.filter((key) => avail.has(key) || sel.has(key));
}
