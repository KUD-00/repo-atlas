import type { AttentionOutcome, AttentionWorkflow } from './types.js'

/** Separate explicit human receipts from the quiet done state used when a
 * concept was already fresh at first observation. */
export function attentionItemBuckets<
  T extends { workflow: AttentionWorkflow; lastOutcome?: AttentionOutcome },
>(items: ReadonlyArray<T>): {
  open: T[]
  snoozed: T[]
  reviewed: T[]
  baselines: T[]
} {
  return {
    open: items.filter((item) => item.workflow === 'open'),
    snoozed: items.filter((item) => item.workflow === 'snoozed'),
    reviewed: items.filter((item) => item.workflow === 'done' && item.lastOutcome !== undefined),
    baselines: items.filter((item) => item.workflow === 'done' && item.lastOutcome === undefined),
  }
}
