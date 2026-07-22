import assert from 'node:assert/strict'
import test from 'node:test'

import { attentionItemBuckets } from '../dist/attention-presentation.js'

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
