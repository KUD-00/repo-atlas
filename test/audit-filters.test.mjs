import assert from 'node:assert/strict'
import test from 'node:test'

import { visibleFilterOptions } from '../dist/audit-filters.js'

test('visibleFilterOptions unions available with selected in canonical order', () => {
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
  const IMPACT_ORDER = ['blocking', 'warning', 'advisory']

  // Selected-only values stay visible even when the focused unit has count 0.
  assert.deepEqual(
    visibleFilterOptions(['high', 'info'], ['critical', 'high'], SEV_ORDER),
    ['critical', 'high', 'info'],
  )
  assert.deepEqual(
    visibleFilterOptions(['warning'], ['blocking', 'advisory'], IMPACT_ORDER),
    ['blocking', 'warning', 'advisory'],
  )

  // Selected that never appear in order are ignored (order is the source of truth).
  assert.deepEqual(
    visibleFilterOptions(['high'], ['unknown', 'high'], SEV_ORDER),
    ['high'],
  )

  // Empty selection → available only, still ordered.
  assert.deepEqual(
    visibleFilterOptions(['info', 'critical'], [], SEV_ORDER),
    ['critical', 'info'],
  )

  // Empty available with active selection → selected chips only.
  assert.deepEqual(
    visibleFilterOptions([], ['medium', 'low'], SEV_ORDER),
    ['medium', 'low'],
  )

  // Open-ended category keys: supply sorted union as the canonical order.
  const available = ['weak-assertion', 'missing-invariant']
  const selected = ['coverage-gap', 'missing-invariant']
  const categoryOrder = [...new Set([...available, ...selected])].sort()
  assert.deepEqual(
    visibleFilterOptions(available, selected, categoryOrder),
    ['coverage-gap', 'missing-invariant', 'weak-assertion'],
  )
})
