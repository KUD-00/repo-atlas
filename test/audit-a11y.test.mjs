import assert from 'node:assert/strict'
import test from 'node:test'

import {
  auditFilterChipAriaPressed,
  auditUnitPanelProps,
  auditUnitSectionIds,
  auditUnitToggleProps,
  compactSidebarA11y,
  shouldRestoreCompactSidebarFocus,
} from '../dist/audit-a11y.js'

test('compact sidebar closed is inert and aria-hidden; open is not', () => {
  assert.deepEqual(compactSidebarA11y(false), { inert: true, 'aria-hidden': true })
  assert.deepEqual(compactSidebarA11y(true), {})
})

test('compact sidebar focus restores only on compact open→closed transition', () => {
  assert.equal(shouldRestoreCompactSidebarFocus(true, true, false), true)
  // still open, still closed, or re-open — no restore
  assert.equal(shouldRestoreCompactSidebarFocus(true, true, true), false)
  assert.equal(shouldRestoreCompactSidebarFocus(true, false, false), false)
  assert.equal(shouldRestoreCompactSidebarFocus(true, false, true), false)
  // desktop never restores to the compact header expand control
  assert.equal(shouldRestoreCompactSidebarFocus(false, true, false), false)
  assert.equal(shouldRestoreCompactSidebarFocus(false, true, true), false)
})

test('audit unit section ids are stable and domain-scoped', () => {
  assert.deepEqual(auditUnitSectionIds('security', 'runtime-auth'), {
    toggleId: 'audit-security-unit-runtime-auth-toggle',
    panelId: 'audit-security-unit-runtime-auth-panel',
  })
  assert.deepEqual(auditUnitSectionIds('test', 'auth-suite'), {
    toggleId: 'audit-test-unit-auth-suite-toggle',
    panelId: 'audit-test-unit-auth-suite-panel',
  })
  // unsafe characters are normalized so ids stay valid
  const legacy = auditUnitSectionIds('security', 'Legacy_Name')
  assert.match(legacy.toggleId, /^audit-security-unit-/)
  assert.match(legacy.panelId, /^audit-security-unit-/)
  assert.equal(legacy.toggleId.includes(' '), false)
})

test('audit unit toggle and panel expose expanded/controls/hidden contract', () => {
  const ids = auditUnitSectionIds('security', 'runtime-auth')
  assert.deepEqual(auditUnitToggleProps(true, ids.panelId), {
    'aria-expanded': true,
    'aria-controls': ids.panelId,
  })
  assert.deepEqual(auditUnitToggleProps(false, ids.panelId), {
    'aria-expanded': false,
    'aria-controls': ids.panelId,
  })
  assert.deepEqual(auditUnitPanelProps(true), { hidden: false })
  assert.deepEqual(auditUnitPanelProps(false), { hidden: true })
})

test('audit filter chips expose aria-pressed matching selection state', () => {
  assert.equal(auditFilterChipAriaPressed(true), true)
  assert.equal(auditFilterChipAriaPressed(false), false)
  // severity / impact / category / stale all use the same pressed contract
  const selected = new Set(['high', 'blocking', 'missing-invariant'])
  for (const key of ['high', 'medium', 'blocking', 'advisory', 'missing-invariant', 'coverage-gap']) {
    assert.equal(auditFilterChipAriaPressed(selected.has(key)), selected.has(key))
  }
  assert.equal(auditFilterChipAriaPressed(false), false) // stale off
  assert.equal(auditFilterChipAriaPressed(true), true) // stale on
})
