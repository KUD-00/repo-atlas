import assert from 'node:assert/strict'
import test from 'node:test'

import {
  auditRoute,
  auditUnitRoute,
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

test('audit unit route returns deep-link only for kebab slugs; null for unrouteable legacy', () => {
  assert.equal(auditUnitRoute('security', 'runtime-auth'), 'audit:security/runtime-auth')
  assert.equal(auditUnitRoute('test', 'test-runtime'), 'audit:test/test-runtime')
  assert.equal(auditUnitRoute('security', 'a'), 'audit:security/a')
  // legacy v1 non-kebab / invalid deep-link slugs must not throw
  assert.equal(auditUnitRoute('security', 'Legacy_Name'), null)
  assert.equal(auditUnitRoute('security', 'Bad Slug'), null)
  assert.equal(auditUnitRoute('test', 'has_underscore'), null)
  assert.equal(auditUnitRoute('security', ''), null)
  assert.equal(auditUnitRoute('security', 'Upper'), null)
})

import {
  auditUnitsForRoute,
  primaryNavRoute,
  rememberPrimaryRoutes,
  securityUnitForConcept,
} from '../dist/audit-routes.js'

test('audit route unit selection focuses one unit or returns the full portfolio', () => {
  const units = [{ slug: 'alpha' }, { slug: 'beta' }, { slug: 'gamma' }]
  assert.deepEqual(auditUnitsForRoute(units, null).map((u) => u.slug), ['alpha', 'beta', 'gamma'])
  assert.deepEqual(auditUnitsForRoute(units, 'beta').map((u) => u.slug), ['beta'])
  assert.deepEqual(auditUnitsForRoute(units, 'missing'), [])
  assert.deepEqual(auditUnitsForRoute([], null), [])
})

test('audit route concept association uses conceptSlug for v2 and slug only for v1', () => {
  const units = [
    { formatVersion: 1, domain: 'security', slug: 'auth', title: 'v1', findings: [] },
    {
      formatVersion: 2,
      domain: 'security',
      slug: 'security-auth',
      conceptSlug: 'auth',
      title: 'v2-linked',
      findings: [],
    },
    {
      formatVersion: 2,
      domain: 'security',
      slug: 'other',
      title: 'v2-unlinked',
      findings: [],
    },
    {
      formatVersion: 2,
      domain: 'security',
      slug: 'auth',
      title: 'v2-same-slug-no-concept',
      findings: [],
    },
  ]
  // v2 with explicit conceptSlug wins association for "auth"
  assert.equal(securityUnitForConcept('auth', units)?.title, 'v2-linked')
  // legacy v1 slug fallback when no v2 conceptSlug match
  assert.equal(
    securityUnitForConcept('auth', units.filter((u) => u.formatVersion === 1))?.title,
    'v1',
  )
  // v2 unit with matching slug but no conceptSlug must NOT associate
  assert.equal(
    securityUnitForConcept(
      'auth',
      units.filter((u) => u.slug === 'auth' && u.formatVersion === 2),
    ),
    undefined,
  )
  // test-shaped records must never be considered (caller passes security portfolio only;
  // helper still ignores domain !== security if mixed by mistake)
  assert.equal(
    securityUnitForConcept('auth', [
      { formatVersion: 2, domain: 'test', slug: 'auth', conceptSlug: 'auth', title: 'test-unit', findings: [] },
      { formatVersion: 1, domain: 'security', slug: 'auth', title: 'v1', findings: [] },
    ])?.title,
    'v1',
  )
})

test('audit route helpers remain presentation-neutral; assurance lives in audit-assurance', async () => {
  const routes = await import('../dist/audit-routes.js')
  assert.equal(
    Object.prototype.hasOwnProperty.call(routes, 'isCleanAuditUnit'),
    false,
  )
  assert.equal(typeof routes.isCleanAuditUnit, 'undefined')

  // Route helpers stay structural: namespaces, deep-links, selection — not risk labels.
  assert.equal(routes.auditRoute('security'), 'audit:security')
  assert.equal(routes.primaryViewForRoute('audit:security'), 'security')
  assert.deepEqual(routes.auditUnitsForRoute([{ slug: 'a' }, { slug: 'b' }], 'b'), [
    { slug: 'b' },
  ])

  const assurance = await import('../dist/audit-assurance.js')
  assert.equal(typeof assurance.domainAssurance, 'function')
  assert.equal(typeof assurance.domainNavSuffix, 'function')
  assert.equal(typeof assurance.auditUnitRows, 'function')
  assert.equal(typeof assurance.auditActionQueue, 'function')
  assert.equal(typeof assurance.auditFilesForUnit, 'function')
  assert.equal(typeof assurance.recentAuditUnits, 'function')
})

test('audit route primary nav remembers code/concepts and homes security/tests', () => {
  let mem = { code: '', concepts: 'view:concepts' }
  mem = rememberPrimaryRoutes(mem, 'src/a.ts')
  assert.deepEqual(mem, { code: 'src/a.ts', concepts: 'view:concepts' })
  mem = rememberPrimaryRoutes(mem, 'concept:auth')
  assert.deepEqual(mem, { code: 'src/a.ts', concepts: 'concept:auth' })
  mem = rememberPrimaryRoutes(mem, 'view:concepts')
  assert.deepEqual(mem, { code: 'src/a.ts', concepts: 'view:concepts' })
  // security/tests do not clobber code/concepts memory
  mem = rememberPrimaryRoutes(mem, 'audit:security/runtime-auth')
  assert.deepEqual(mem, { code: 'src/a.ts', concepts: 'view:concepts' })
  mem = rememberPrimaryRoutes(mem, 'audit:test')
  assert.deepEqual(mem, { code: 'src/a.ts', concepts: 'view:concepts' })

  assert.equal(primaryNavRoute('code', mem), 'src/a.ts')
  assert.equal(primaryNavRoute('concepts', mem), 'view:concepts')
  assert.equal(primaryNavRoute('security', mem), 'audit:security')
  assert.equal(primaryNavRoute('tests', mem), 'audit:test')
})
