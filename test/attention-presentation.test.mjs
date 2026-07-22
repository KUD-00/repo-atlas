import assert from 'node:assert/strict'
import test from 'node:test'

import {
  attentionActionConflictNotice,
  attentionConflictNoticeProps,
  attentionItemBuckets,
  conceptAttentionNoticeKind,
} from '../dist/attention-presentation.js'

test('attention presentation never labels a quiet fresh baseline as reviewed', () => {
  const open = { slug: 'open', workflow: 'open' }
  const snoozed = { slug: 'snoozed', workflow: 'snoozed' }
  const baseline = { slug: 'baseline', workflow: 'done' }
  const reviewed = { slug: 'reviewed', workflow: 'done', lastOutcome: 'understood' }

  const buckets = attentionItemBuckets([baseline, open, reviewed, snoozed])

  assert.deepEqual(buckets.open, [open])
  assert.deepEqual(buckets.snoozed, [snoozed])
  assert.deepEqual(buckets.reviewed, [reviewed])
  assert.deepEqual(buckets.baselines, [baseline])
})

test('concept attention notices distinguish quiet baselines from review receipts', () => {
  assert.equal(conceptAttentionNoticeKind({ workflow: 'open' }), 'pending')
  assert.equal(conceptAttentionNoticeKind({ workflow: 'snoozed' }), 'pending')
  assert.equal(conceptAttentionNoticeKind({ workflow: 'done' }), 'baseline')
  assert.equal(
    conceptAttentionNoticeKind({ workflow: 'done', lastOutcome: 'understood' }),
    'reviewed',
  )
})

test('stale-action conflicts retain a page-level accessible notice with the winning outcome', () => {
  const notice = attentionActionConflictNotice(
    'attention action workflow revision is stale',
    'runtime',
    {
      items: [{
        slug: 'runtime',
        title: 'Runtime',
        workflow: 'done',
        lastOutcome: 'understood',
      }],
    },
  )

  assert.deepEqual(notice, {
    message: 'attention action workflow revision is stale',
    slug: 'runtime',
    title: 'Runtime',
    workflow: 'done',
    outcome: 'understood',
  })
  assert.deepEqual(attentionConflictNoticeProps(), {
    role: 'alert',
    'aria-live': 'assertive',
  })
})
