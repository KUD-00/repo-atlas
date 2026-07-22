export function attentionActionConflictNotice(message, slug, attention) {
    const winner = attention.items.find((item) => item.slug === slug);
    return {
        message,
        slug,
        title: winner?.title ?? slug,
        ...(winner ? { workflow: winner.workflow } : {}),
        ...(winner?.lastOutcome ? { outcome: winner.lastOutcome } : {}),
    };
}
export function attentionConflictNoticeProps() {
    return { role: 'alert', 'aria-live': 'assertive' };
}
export function conceptAttentionNoticeKind(item) {
    if (item.workflow !== 'done')
        return 'pending';
    return item.lastOutcome === undefined ? 'baseline' : 'reviewed';
}
/** Separate explicit human receipts from the quiet done state used when a
 * concept was already fresh at first observation. */
export function attentionItemBuckets(items) {
    return {
        open: items.filter((item) => item.workflow === 'open'),
        snoozed: items.filter((item) => item.workflow === 'snoozed'),
        reviewed: items.filter((item) => item.workflow === 'done' && item.lastOutcome !== undefined),
        baselines: items.filter((item) => item.workflow === 'done' && item.lastOutcome === undefined),
    };
}
