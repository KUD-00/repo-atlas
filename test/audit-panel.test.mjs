import assert from 'node:assert/strict'
import test from 'node:test'

import {
  initialPanelOpen,
  shouldClosePanelOnPrimaryTransition,
} from '../dist/audit-panel.js'

test('direct audit entry starts with the code panel closed', () => {
  assert.equal(initialPanelOpen(false, 'security'), false)
  assert.equal(initialPanelOpen(false, 'tests'), false)
  assert.equal(initialPanelOpen(false, 'code'), true)
  assert.equal(initialPanelOpen(false, 'attention'), false)
})

test('compact always starts with the code panel closed', () => {
  assert.equal(initialPanelOpen(true, 'code'), false)
})

test('entering an audit closes an unrelated panel only once', () => {
  assert.equal(shouldClosePanelOnPrimaryTransition('code', 'security'), true)
  assert.equal(shouldClosePanelOnPrimaryTransition('concepts', 'tests'), true)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'security'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'tests'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('tests', 'security'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'code'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('tests', 'code'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('code', 'attention'), true)
  assert.equal(shouldClosePanelOnPrimaryTransition('concepts', 'attention'), true)
  assert.equal(shouldClosePanelOnPrimaryTransition('attention', 'security'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('security', 'attention'), false)
  assert.equal(shouldClosePanelOnPrimaryTransition('attention', 'code'), false)
})
