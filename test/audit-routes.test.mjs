import assert from 'node:assert/strict'
import test from 'node:test'

import {
  auditRoute,
  isConceptsViewRoute,
  isNamespacedOrPathRoute,
  isValidAuditUnitRoute,
  parseAuditRoute,
  primaryViewForRoute,
} from '../dist/audit-routes.js'

test('audit route helpers parse namespaced security and test routes', () => {
  assert.deepEqual(parseAuditRoute('audit:security'), { domain: 'security', slug: null })
  assert.deepEqual(parseAuditRoute('audit:test/test-runtime'), { domain: 'test', slug: 'test-runtime' })
  assert.deepEqual(parseAuditRoute('audit:security/runtime-auth'), { domain: 'security', slug: 'runtime-auth' })
  assert.equal(parseAuditRoute('security'), null)
  assert.equal(parseAuditRoute('audit:ops'), null)
  assert.equal(parseAuditRoute('audit:security/Bad Slug'), null)
  assert.equal(parseAuditRoute('audit:security/'), null)
  assert.equal(parseAuditRoute('audit:test/Upper'), null)
  assert.equal(parseAuditRoute(''), null)

  assert.equal(auditRoute('security'), 'audit:security')
  assert.equal(auditRoute('test'), 'audit:test')
  assert.equal(auditRoute('security', 'runtime-auth'), 'audit:security/runtime-auth')
  assert.throws(() => auditRoute('security', 'Bad Slug'), /invalid audit slug/i)
  assert.throws(() => auditRoute('test', 'has_underscore'), /invalid audit slug/i)
  assert.throws(() => auditRoute('security', ''), /invalid audit slug/i)
})

test('audit route primary view treats bare security as code and concepts/view as concepts', () => {
  assert.equal(primaryViewForRoute('security', () => true), 'code')
  assert.equal(primaryViewForRoute('security', () => false), 'code')
  assert.equal(primaryViewForRoute('src/a.ts', () => true), 'code')
  assert.equal(primaryViewForRoute('audit:security', () => false), 'security')
  assert.equal(primaryViewForRoute('audit:security/runtime-auth', () => false), 'security')
  assert.equal(primaryViewForRoute('audit:test', () => false), 'tests')
  assert.equal(primaryViewForRoute('audit:test/test-runtime', () => false), 'tests')
  assert.equal(primaryViewForRoute('concept:auth', () => false), 'concepts')
  assert.equal(primaryViewForRoute('view:concepts', () => false), 'concepts')
  assert.equal(isConceptsViewRoute('view:concepts'), true)
  assert.equal(isConceptsViewRoute('concept:auth'), false)
})

test('audit route reserved namespaces win over colliding repository paths', () => {
  const empty = { security: [], tests: [] }
  const alwaysPath = () => true
  const neverPath = () => false

  // Namespaced routes stay domain views even when a same-named file exists.
  assert.equal(primaryViewForRoute('audit:security', alwaysPath), 'security')
  assert.equal(primaryViewForRoute('audit:test', alwaysPath), 'tests')
  assert.equal(primaryViewForRoute('view:concepts', alwaysPath), 'concepts')
  assert.equal(primaryViewForRoute('concept:auth', alwaysPath), 'concepts')
  assert.equal(isNamespacedOrPathRoute('audit:security', alwaysPath, empty, () => false), true)
  assert.equal(isNamespacedOrPathRoute('audit:test', alwaysPath, empty, () => false), true)
  assert.equal(isNamespacedOrPathRoute('view:concepts', alwaysPath, empty, () => false), true)
  assert.equal(isNamespacedOrPathRoute('concept:auth', alwaysPath, empty, () => true), true)

  // Bare security keeps real repo-path priority for Code, never Security.
  assert.equal(primaryViewForRoute('security', alwaysPath), 'code')
  assert.equal(isNamespacedOrPathRoute('security', alwaysPath, empty, () => false), true)
  assert.equal(isNamespacedOrPathRoute('security', neverPath, empty, () => false), false)

  // Malformed audit:* stays reserved — never falls through to a colliding Code path.
  assert.equal(isNamespacedOrPathRoute('audit:ops', alwaysPath, empty, () => false), false)
  assert.equal(isNamespacedOrPathRoute('audit:security/Bad', alwaysPath, empty, () => false), false)
  assert.equal(isNamespacedOrPathRoute('audit:security/', alwaysPath, empty, () => false), false)
  assert.equal(isNamespacedOrPathRoute('audit:test/Upper', alwaysPath, empty, () => false), false)
})

test('audit route unit deep-links require a portfolio slug; homes are always valid', () => {
  const security = [{ slug: 'runtime-auth' }, { slug: 'Legacy_Name' }]
  const tests = [{ slug: 'test-runtime' }]

  assert.equal(isValidAuditUnitRoute('security', null, security), true)
  assert.equal(isValidAuditUnitRoute('test', null, tests), true)
  assert.equal(isValidAuditUnitRoute('security', null, []), true)
  assert.equal(isValidAuditUnitRoute('test', null, []), true)
  assert.equal(isValidAuditUnitRoute('security', 'runtime-auth', security), true)
  assert.equal(isValidAuditUnitRoute('security', 'missing', security), false)
  assert.equal(isValidAuditUnitRoute('test', 'test-runtime', tests), true)
  // legacy v1 non-kebab slugs may still appear in the portfolio but have no unit deep-link
  assert.equal(parseAuditRoute('audit:security/Legacy_Name'), null)
  assert.equal(isValidAuditUnitRoute('security', 'Legacy_Name', security), true)
})
