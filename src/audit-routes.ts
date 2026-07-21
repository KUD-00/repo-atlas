import type { AuditDomain } from './types.js'

export type PrimaryView = 'code' | 'concepts' | 'security' | 'tests'

const SLUG_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u
const AUDIT_ROUTE_RE = /^audit:(security|test)(?:\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?))?$/u

export function auditRoute(domain: AuditDomain, slug?: string): string {
  if (slug !== undefined && !SLUG_RE.test(slug)) {
    throw new Error('invalid audit slug')
  }
  return `audit:${domain}${slug ? `/${slug}` : ''}`
}

export function parseAuditRoute(route: string): { domain: AuditDomain; slug: string | null } | null {
  const match = AUDIT_ROUTE_RE.exec(route)
  if (!match) return null
  return { domain: match[1] as AuditDomain, slug: match[2] ?? null }
}

export function isConceptsViewRoute(route: string): boolean {
  return route === 'view:concepts'
}

/** Derive the sidebar primary view from a hash route. Bare `security` is always code. */
export function primaryViewForRoute(
  route: string,
  _hasPath: (path: string) => boolean = () => false,
): PrimaryView {
  if (isConceptsViewRoute(route) || route.startsWith('concept:')) return 'concepts'
  const audit = parseAuditRoute(route)
  if (audit?.domain === 'security') return 'security'
  if (audit?.domain === 'test') return 'tests'
  return 'code'
}

/** Portfolio homes (slug null) are always valid — including empty portfolios.
 * Unit deep-links require the slug to exist in the domain portfolio. */
export function isValidAuditUnitRoute(
  domain: AuditDomain,
  slug: string | null,
  portfolio: ReadonlyArray<{ slug: string }>,
): boolean {
  if (slug === null) return true
  return portfolio.some((unit) => unit.slug === slug)
}

/**
 * Namespace-first route acceptance (print scopes handled by the caller).
 * `audit:*`, `view:concepts`, and `concept:*` always win over a same-named
 * repository path. Bare paths (including `security`) use hasPath only.
 */
export function isNamespacedOrPathRoute(
  route: string,
  hasPath: (path: string) => boolean,
  portfolios: {
    security: ReadonlyArray<{ slug: string }>
    tests: ReadonlyArray<{ slug: string }>
  },
  hasConcept: (slug: string) => boolean,
): boolean {
  if (isConceptsViewRoute(route)) return true
  if (route.startsWith('concept:')) return hasConcept(route.slice('concept:'.length))
  const audit = parseAuditRoute(route)
  if (audit) {
    const portfolio = audit.domain === 'security' ? portfolios.security : portfolios.tests
    return isValidAuditUnitRoute(audit.domain, audit.slug, portfolio)
  }
  // Reserved namespace: malformed audit:* never falls through to a path match.
  if (route.startsWith('audit:')) return false
  return hasPath(route)
}
