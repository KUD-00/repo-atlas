import type { AttentionOutcome, AttentionPayload, AttentionWorkflow } from './types.js'

export type ConceptAttentionNoticeKind = 'pending' | 'baseline' | 'reviewed'

export interface AttentionActionConflictNotice {
  message: string
  slug: string
  title: string
  workflow?: AttentionWorkflow
  outcome?: AttentionOutcome
}

export function attentionActionConflictNotice(
  message: string,
  slug: string,
  attention: Pick<AttentionPayload, 'items'>,
): AttentionActionConflictNotice {
  const winner = attention.items.find((item) => item.slug === slug)
  return {
    message,
    slug,
    title: winner?.title ?? slug,
    ...(winner ? { workflow: winner.workflow } : {}),
    ...(winner?.lastOutcome ? { outcome: winner.lastOutcome } : {}),
  }
}

export function attentionConflictNoticeProps(): {
  role: 'alert'
  'aria-live': 'assertive'
} {
  return { role: 'alert', 'aria-live': 'assertive' }
}

export function conceptAttentionNoticeKind(
  item: { workflow: AttentionWorkflow; lastOutcome?: AttentionOutcome },
): ConceptAttentionNoticeKind {
  if (item.workflow !== 'done') return 'pending'
  return item.lastOutcome === undefined ? 'baseline' : 'reviewed'
}

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
