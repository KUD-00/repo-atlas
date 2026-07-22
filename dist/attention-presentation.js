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
