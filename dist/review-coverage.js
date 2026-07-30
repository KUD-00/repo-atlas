import path from 'node:path';
import { loadAuditExactEvidence, } from './audits.js';
import { classifyAuditInventory, loadAuditReviewPolicy, readAuditTrackedInventory, } from './audit-policy.js';
import { canonicalJson, readBoundedAuditJsonDocument, withAnchoredAuditFileIdentity, withAnchoredAuditRootIdentity, } from './audit-core.js';
import { atlasDir } from './scan.js';
import { reviewCoverageInventoryHash } from './review-coverage-hash.js';
import { missingReviewCoverage } from './review-coverage-portfolio.js';
export { missingReviewCoverage } from './review-coverage-portfolio.js';
/**
 * Strict fail-closed loader for `.atlas/review-coverage.json`.
 *
 * Task 2: structural validation only (shape, summary arithmetic, unit ownership).
 * Task 3 will revalidate Git inventory blobs and ledger freshness through the
 * internal seam below `loadReviewCoverage` without changing the public API.
 */
const COVERAGE_REL = '.atlas/review-coverage.json';
const SELF_PATH = COVERAGE_REL;
const GENERATED_PROOF = 'GENERATED-PROOF';
const FORMAT = 'atlas-review-coverage-v1';
const MAX_REPORT_BYTES = 32 * 1024 * 1024;
const MAX_ENTRIES = 1_000_000;
const MAX_DIAGNOSTICS = 100_000;
const MAX_UNITS = 100_000;
const TOP_LEVEL_KEYS = [
    'formatVersion',
    'format',
    'verdict',
    'policy',
    'inventoryHash',
    'units',
    'summary',
    'entries',
    'invalidLedgerDetails',
    'reportErrors',
];
const SUMMARY_KEYS = [
    'tracked',
    'securityRequired',
    'securityFresh',
    'securityMissing',
    'securityStale',
    'securityInvalid',
    'testRequired',
    'testFresh',
    'testMissing',
    'testStale',
    'testInvalid',
    'dualRequired',
    'excluded',
    'unclassified',
    'conflicted',
    'invalidLedgers',
];
const VERDICTS = new Set(['complete', 'incomplete', 'invalid']);
const EVIDENCE_STATUSES = new Set(['fresh', 'missing', 'stale', 'invalid']);
const UNIT_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;
const SHA1_RE = /^[0-9a-f]{40}$/u;
const SHA256_RE = /^[0-9a-f]{64}$/u;
const emptyDrift = () => ({
    added: [],
    removed: [],
    changed: [],
});
function diagnostic(code, message, extra = {}) {
    const out = { code, message };
    if (extra.path !== undefined)
        out.path = extra.path;
    if (extra.slug !== undefined)
        out.slug = extra.slug;
    return out;
}
function missingPortfolio() {
    return missingReviewCoverage();
}
function invalidPortfolio(errors) {
    return { state: 'invalid', report: null, errors, drift: emptyDrift() };
}
export function reviewCoveragePath(root) {
    return path.join(atlasDir(root), 'review-coverage.json');
}
function validRepoPath(repoPath) {
    return !!repoPath &&
        !path.isAbsolute(repoPath) &&
        !repoPath.includes('\\') &&
        !repoPath.includes('\0') &&
        path.posix.normalize(repoPath) === repoPath &&
        repoPath !== '.' &&
        !repoPath.startsWith('./') &&
        !repoPath.startsWith('../') &&
        !repoPath.includes('/../') &&
        !repoPath.includes('/./');
}
function isPlainObject(value) {
    return !!value && typeof value === 'object' && !Array.isArray(value);
}
function exactKeys(value, keys) {
    const actual = Object.keys(value);
    if (actual.length !== keys.length)
        return false;
    return keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}
function nonnegativeInteger(value) {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function nonemptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}
function parseDiagnostic(value, label) {
    if (!isPlainObject(value))
        return `${label} entries must be objects`;
    const keys = Object.keys(value);
    for (const key of keys) {
        if (key !== 'code' && key !== 'message' && key !== 'path' && key !== 'slug') {
            return `${label} entries have unknown fields`;
        }
    }
    if (typeof value.code !== 'string' || value.code.length === 0)
        return `${label} code must be a nonempty string`;
    if (typeof value.message !== 'string' || value.message.length === 0)
        return `${label} message must be a nonempty string`;
    if (value.path !== undefined && (typeof value.path !== 'string' || !validRepoPath(value.path))) {
        return `${label} path must be a normalized repository-relative path`;
    }
    if (value.slug !== undefined && (typeof value.slug !== 'string' || !UNIT_SLUG_RE.test(value.slug))) {
        return `${label} slug must be a route-safe unit slug`;
    }
    const out = {
        code: value.code,
        message: value.message,
    };
    if (typeof value.path === 'string')
        out.path = value.path;
    if (typeof value.slug === 'string')
        out.slug = value.slug;
    return out;
}
function parseDiagnostics(value, label) {
    if (!Array.isArray(value))
        return `${label} must be an array`;
    if (value.length > MAX_DIAGNOSTICS)
        return `${label} exceeds the ${MAX_DIAGNOSTICS} diagnostic limit`;
    const out = [];
    for (let i = 0; i < value.length; i++) {
        const parsed = parseDiagnostic(value[i], label);
        if (typeof parsed === 'string')
            return parsed;
        out.push(parsed);
    }
    return out;
}
function parseUnit(value) {
    if (!isPlainObject(value))
        return 'units entries must be objects';
    if (!exactKeys(value, ['domain', 'slug', 'title']))
        return 'units entries must have exact domain, slug, and title fields';
    if (value.domain !== 'security' && value.domain !== 'test')
        return 'units domain must be security or test';
    if (typeof value.slug !== 'string' || !UNIT_SLUG_RE.test(value.slug)) {
        return 'units slug must be lowercase kebab-case for namespaced routes';
    }
    if (!nonemptyString(value.title))
        return 'units title must be a nonempty string';
    return {
        domain: value.domain,
        slug: value.slug,
        title: value.title,
    };
}
function parseUnits(value) {
    if (!Array.isArray(value))
        return 'units must be an array';
    if (value.length > MAX_UNITS)
        return `units exceeds the ${MAX_UNITS} unit limit`;
    const out = [];
    const seen = new Set();
    for (const item of value) {
        const parsed = parseUnit(item);
        if (typeof parsed === 'string')
            return parsed;
        const key = `${parsed.domain}:${parsed.slug}`;
        if (seen.has(key))
            return `duplicate unit ${key}`;
        seen.add(key);
        out.push(parsed);
    }
    return out;
}
function parseSummary(value) {
    if (!isPlainObject(value))
        return 'summary must be an object';
    if (!exactKeys(value, SUMMARY_KEYS))
        return 'summary must have exact known identity fields';
    const out = {};
    for (const key of SUMMARY_KEYS) {
        const count = nonnegativeInteger(value[key]);
        if (count === null)
            return `summary.${key} must be a finite nonnegative integer`;
        out[key] = count;
    }
    return out;
}
function parseEvidenceStatus(value) {
    return typeof value === 'string' && EVIDENCE_STATUSES.has(value)
        ? value
        : null;
}
function parseDomainEvidence(value, domain) {
    if (!isPlainObject(value))
        return `evidence.${domain} must be an object`;
    if (!exactKeys(value, ['status', 'ledgers']))
        return `evidence.${domain} must have exact status and ledgers fields`;
    const status = parseEvidenceStatus(value.status);
    if (!status)
        return `evidence.${domain}.status is unknown`;
    if (!Array.isArray(value.ledgers) || !value.ledgers.every((item) => typeof item === 'string')) {
        return `evidence.${domain}.ledgers must be an array of strings`;
    }
    if (value.ledgers.some((slug) => !UNIT_SLUG_RE.test(slug))) {
        return `evidence.${domain}.ledgers must contain route-safe unit slugs`;
    }
    if (new Set(value.ledgers).size !== value.ledgers.length) {
        return `evidence.${domain}.ledgers must be unique`;
    }
    return { status, ledgers: [...value.ledgers] };
}
function parseEvidence(value) {
    if (!isPlainObject(value))
        return 'evidence must be an object';
    const out = {};
    for (const key of Object.keys(value)) {
        if (key !== 'security' && key !== 'test')
            return `evidence has unknown domain ${key}`;
        const domain = key;
        const parsed = parseDomainEvidence(value[key], domain);
        if (typeof parsed === 'string')
            return parsed;
        out[domain] = parsed;
    }
    return out;
}
function parseReviewDomains(value) {
    if (!isPlainObject(value))
        return 'review classification domains must be an object';
    const keys = Object.keys(value);
    if (keys.length === 0)
        return 'review classification must name at least one domain';
    const out = {};
    for (const key of keys) {
        if (key !== 'security' && key !== 'test')
            return `review classification has unknown domain ${key}`;
        const domain = key;
        const ref = value[key];
        if (!isPlainObject(ref) || !exactKeys(ref, ['unit'])) {
            return `review classification.${domain} must have exact unit field`;
        }
        if (typeof ref.unit !== 'string' || !UNIT_SLUG_RE.test(ref.unit)) {
            return `review classification.${domain}.unit must be a route-safe unit slug`;
        }
        out[domain] = { unit: ref.unit };
    }
    return out;
}
function parseClassification(value) {
    if (!isPlainObject(value) || typeof value.kind !== 'string')
        return 'classification must be an object with a kind';
    if (value.kind === 'review') {
        if (!exactKeys(value, ['kind', 'domains']))
            return 'review classification must have exact kind and domains fields';
        const domains = parseReviewDomains(value.domains);
        if (typeof domains === 'string')
            return domains;
        return { kind: 'review', domains };
    }
    if (value.kind === 'excluded') {
        const keys = Object.keys(value);
        for (const key of keys) {
            if (key !== 'kind' && key !== 'ruleId' && key !== 'category' && key !== 'reason' && key !== 'owner') {
                return 'excluded classification has unknown fields';
            }
        }
        if (!nonemptyString(value.ruleId) || !nonemptyString(value.category) || !nonemptyString(value.reason)) {
            return 'excluded classification requires nonempty ruleId, category, and reason';
        }
        if (value.owner !== undefined && !nonemptyString(value.owner)) {
            return 'excluded classification owner must be a nonempty string when present';
        }
        const out = {
            kind: 'excluded',
            ruleId: value.ruleId,
            category: value.category,
            reason: value.reason,
        };
        if (typeof value.owner === 'string')
            out.owner = value.owner;
        return out;
    }
    if (value.kind === 'unclassified') {
        if (!exactKeys(value, ['kind']))
            return 'unclassified classification must have exact kind field';
        return { kind: 'unclassified' };
    }
    if (value.kind === 'conflict') {
        if (!exactKeys(value, ['kind']))
            return 'conflict classification must have exact kind field';
        return { kind: 'conflict' };
    }
    return `classification kind ${String(value.kind)} is unknown`;
}
function parseEntry(value) {
    if (!isPlainObject(value))
        return 'entries must be objects';
    const keys = Object.keys(value);
    for (const key of keys) {
        if (key !== 'path' && key !== 'blob' && key !== 'ruleIds' && key !== 'classification' && key !== 'evidence') {
            return 'entries have unknown fields';
        }
    }
    if (typeof value.path !== 'string' || !validRepoPath(value.path)) {
        return 'entry path must be a unique normalized repository-relative path';
    }
    if (value.blob !== undefined) {
        if (typeof value.blob !== 'string' || !SHA1_RE.test(value.blob)) {
            return `entry blob must be a lowercase 40-hex git blob id (${value.path})`;
        }
    }
    else if (value.path !== SELF_PATH) {
        return `entry blob is required except for the generated-proof self path (${value.path})`;
    }
    if (!Array.isArray(value.ruleIds) ||
        !value.ruleIds.every((item) => nonemptyString(item))) {
        return `entry ruleIds must be a string array (${value.path})`;
    }
    const classification = parseClassification(value.classification);
    if (typeof classification === 'string')
        return `${classification} (${value.path})`;
    if (value.ruleIds.length === 0 &&
        classification.kind !== 'unclassified' &&
        classification.kind !== 'conflict') {
        return `review and excluded entry ruleIds must be nonempty (${value.path})`;
    }
    const evidence = parseEvidence(value.evidence);
    if (typeof evidence === 'string')
        return `${evidence} (${value.path})`;
    // Non-review classifications carry no domain evidence.
    if (classification.kind !== 'review') {
        if (Object.keys(evidence).length > 0) {
            return `excluded, unclassified, and conflict entries carry no domain evidence (${value.path})`;
        }
    }
    else {
        const requiredDomains = Object.keys(classification.domains);
        for (const domain of requiredDomains) {
            if (!evidence[domain]) {
                return `missing required domain evidence for ${domain} (${value.path})`;
            }
        }
        for (const domain of Object.keys(evidence)) {
            if (!classification.domains[domain]) {
                return `evidence domain ${domain} is not required by classification (${value.path})`;
            }
        }
    }
    const entry = {
        path: value.path,
        ruleIds: [...value.ruleIds],
        classification,
        evidence,
    };
    if (typeof value.blob === 'string')
        entry.blob = value.blob;
    return entry;
}
function parseEntries(value) {
    if (!Array.isArray(value))
        return 'entries must be an array';
    if (value.length > MAX_ENTRIES)
        return `entries exceeds the ${MAX_ENTRIES} entry limit`;
    const out = [];
    const seen = new Set();
    for (const item of value) {
        const parsed = parseEntry(item);
        if (typeof parsed === 'string')
            return parsed;
        if (seen.has(parsed.path))
            return `duplicate path ${parsed.path}`;
        seen.add(parsed.path);
        out.push(parsed);
    }
    return out;
}
function recomputeSummary(entries, invalidLedgerDetails) {
    let securityRequired = 0;
    let securityFresh = 0;
    let securityMissing = 0;
    let securityStale = 0;
    let securityInvalid = 0;
    let testRequired = 0;
    let testFresh = 0;
    let testMissing = 0;
    let testStale = 0;
    let testInvalid = 0;
    let dualRequired = 0;
    let excluded = 0;
    let unclassified = 0;
    let conflicted = 0;
    for (const entry of entries) {
        const kind = entry.classification.kind;
        if (kind === 'excluded') {
            excluded += 1;
            continue;
        }
        if (kind === 'unclassified') {
            unclassified += 1;
            continue;
        }
        if (kind === 'conflict') {
            conflicted += 1;
            continue;
        }
        const domains = entry.classification.domains;
        const hasSecurity = Boolean(domains.security);
        const hasTest = Boolean(domains.test);
        if (hasSecurity && hasTest)
            dualRequired += 1;
        if (hasSecurity) {
            securityRequired += 1;
            const status = entry.evidence.security?.status;
            if (status === 'fresh')
                securityFresh += 1;
            else if (status === 'missing')
                securityMissing += 1;
            else if (status === 'stale')
                securityStale += 1;
            else if (status === 'invalid')
                securityInvalid += 1;
        }
        if (hasTest) {
            testRequired += 1;
            const status = entry.evidence.test?.status;
            if (status === 'fresh')
                testFresh += 1;
            else if (status === 'missing')
                testMissing += 1;
            else if (status === 'stale')
                testStale += 1;
            else if (status === 'invalid')
                testInvalid += 1;
        }
    }
    return {
        tracked: entries.length,
        securityRequired,
        securityFresh,
        securityMissing,
        securityStale,
        securityInvalid,
        testRequired,
        testFresh,
        testMissing,
        testStale,
        testInvalid,
        dualRequired,
        excluded,
        unclassified,
        conflicted,
        invalidLedgers: invalidLedgerDetails.length,
    };
}
function summaryMatches(actual, expected) {
    return SUMMARY_KEYS.every((key) => actual[key] === expected[key]);
}
function summaryIdentitiesHold(summary) {
    return summary.securityFresh + summary.securityMissing + summary.securityStale + summary.securityInvalid === summary.securityRequired &&
        summary.testFresh + summary.testMissing + summary.testStale + summary.testInvalid === summary.testRequired;
}
function gapCount(summary) {
    return summary.securityMissing +
        summary.securityStale +
        summary.securityInvalid +
        summary.testMissing +
        summary.testStale +
        summary.testInvalid +
        summary.unclassified +
        summary.conflicted +
        summary.invalidLedgers;
}
function unitOwnershipErrors(entries, units) {
    const byDomainSlug = new Map();
    const domainsBySlug = new Map();
    for (const unit of units) {
        byDomainSlug.set(`${unit.domain}:${unit.slug}`, unit);
        const domains = domainsBySlug.get(unit.slug);
        if (domains === undefined) {
            domainsBySlug.set(unit.slug, new Set([unit.domain]));
        }
        else {
            domains.add(unit.domain);
        }
    }
    const errors = [];
    for (const entry of entries) {
        if (entry.classification.kind !== 'review')
            continue;
        for (const domain of Object.keys(entry.classification.domains)) {
            const unitSlug = entry.classification.domains[domain]?.unit;
            if (!unitSlug)
                continue;
            const registered = byDomainSlug.get(`${domain}:${unitSlug}`);
            if (!registered) {
                // Same slug registered under another domain is still wrong ownership.
                const registeredDomains = domainsBySlug.get(unitSlug);
                let crossDomain;
                if (registeredDomains !== undefined) {
                    for (const candidate of registeredDomains) {
                        if (candidate !== domain) {
                            crossDomain = candidate;
                            break;
                        }
                    }
                }
                if (crossDomain !== undefined) {
                    errors.push(diagnostic('unit-ownership', `review domain ${domain} names cross-domain unit ${unitSlug} registered under ${crossDomain}`, { path: entry.path, slug: unitSlug }));
                }
                else {
                    errors.push(diagnostic('unit-ownership', `review domain ${domain} names unregistered unit ${unitSlug}`, { path: entry.path, slug: unitSlug }));
                }
            }
        }
    }
    return errors;
}
function parsePolicy(value) {
    if (!isPlainObject(value))
        return 'policy must be an object';
    if (!exactKeys(value, ['format', 'hash']))
        return 'policy must have exact format and hash fields';
    if (!nonemptyString(value.format))
        return 'policy.format must be a nonempty string';
    if (typeof value.hash !== 'string' || !SHA256_RE.test(value.hash)) {
        return 'policy.hash must be a lowercase 64-hex sha256';
    }
    return { format: value.format, hash: value.hash };
}
function parseStructure(raw) {
    if (!isPlainObject(raw)) {
        return { ok: false, errors: [diagnostic('malformed-report', 'coverage report must be a JSON object')] };
    }
    if (!exactKeys(raw, TOP_LEVEL_KEYS)) {
        return {
            ok: false,
            errors: [diagnostic('malformed-report', 'coverage report must have exact known top-level fields')],
        };
    }
    if (raw.formatVersion !== 1) {
        return {
            ok: false,
            errors: [diagnostic('unsupported-version', `formatVersion ${String(raw.formatVersion)} is unsupported (known: 1)`)],
        };
    }
    if (raw.format !== FORMAT) {
        return {
            ok: false,
            errors: [diagnostic('unsupported-format', `format must be ${FORMAT}`)],
        };
    }
    if (typeof raw.verdict !== 'string' || !VERDICTS.has(raw.verdict)) {
        return {
            ok: false,
            errors: [diagnostic('malformed-report', 'verdict must be complete, incomplete, or invalid')],
        };
    }
    const verdict = raw.verdict;
    const policy = parsePolicy(raw.policy);
    if (typeof policy === 'string') {
        return { ok: false, errors: [diagnostic('malformed-report', policy)] };
    }
    if (typeof raw.inventoryHash !== 'string' || !SHA256_RE.test(raw.inventoryHash)) {
        return {
            ok: false,
            errors: [diagnostic('malformed-report', 'inventoryHash must be a lowercase 64-hex sha256')],
        };
    }
    // Parse reportErrors early, but still structurally validate the complete
    // body before surfacing a declared invalid report's own diagnostics.
    const reportErrors = parseDiagnostics(raw.reportErrors, 'reportErrors');
    if (typeof reportErrors === 'string') {
        return { ok: false, errors: [diagnostic('malformed-report', reportErrors)] };
    }
    if (verdict === 'invalid' && reportErrors.length === 0) {
        return {
            ok: false,
            errors: [diagnostic('invalid-verdict', 'invalid verdict requires at least one reportErrors item')],
        };
    }
    if (verdict !== 'invalid' && reportErrors.length > 0) {
        return {
            ok: false,
            errors: [diagnostic('invalid-verdict', 'complete and incomplete verdicts require an empty reportErrors array')],
        };
    }
    const units = parseUnits(raw.units);
    if (typeof units === 'string') {
        return { ok: false, errors: [diagnostic('malformed-report', units)] };
    }
    const summary = parseSummary(raw.summary);
    if (typeof summary === 'string') {
        return { ok: false, errors: [diagnostic('summary-mismatch', summary)] };
    }
    const entries = parseEntries(raw.entries);
    if (typeof entries === 'string') {
        const code = /duplicate path|unsafe|normalized|path/i.test(entries) ? 'invalid-path' : 'malformed-report';
        return { ok: false, errors: [diagnostic(code, entries)] };
    }
    const invalidLedgerDetails = parseDiagnostics(raw.invalidLedgerDetails, 'invalidLedgerDetails');
    if (typeof invalidLedgerDetails === 'string') {
        return { ok: false, errors: [diagnostic('malformed-report', invalidLedgerDetails)] };
    }
    const expectedSummary = recomputeSummary(entries, invalidLedgerDetails);
    if (!summaryMatches(summary, expectedSummary) || !summaryIdentitiesHold(summary)) {
        return {
            ok: false,
            errors: [diagnostic('summary-mismatch', 'summary identities do not match recomputed coverage totals')],
        };
    }
    const ownership = unitOwnershipErrors(entries, units);
    if (ownership.length) {
        return { ok: false, errors: ownership };
    }
    if (verdict === 'invalid') {
        // Structurally valid invalid bodies are never projected or revalidated as
        // fresh; only their declared diagnostics leave this parser.
        return {
            ok: false,
            declaredInvalid: true,
            errors: reportErrors.map((error) => diagnostic(error.code || 'report-error', error.message || 'coverage report declared invalid', { path: error.path, slug: error.slug })),
        };
    }
    const gaps = gapCount(summary);
    if (verdict === 'complete' && gaps !== 0) {
        return {
            ok: false,
            errors: [diagnostic('invalid-verdict', 'complete verdict requires zero missing, stale, invalid, unclassified, conflicted, and invalid ledgers')],
        };
    }
    if (verdict === 'incomplete' && gaps === 0) {
        return {
            ok: false,
            errors: [diagnostic('invalid-verdict', 'incomplete verdict requires at least one explicit gap')],
        };
    }
    const report = {
        formatVersion: 1,
        format: FORMAT,
        verdict,
        policy,
        inventoryHash: raw.inventoryHash,
        units,
        summary,
        entries,
        invalidLedgerDetails,
        reportErrors,
    };
    return { ok: true, report };
}
function inventoryHashFrom(hashes) {
    return reviewCoverageInventoryHash([...hashes.entries()].map(([repoPath, blob]) => ({
        marker: repoPath === SELF_PATH ? GENERATED_PROOF : blob,
        path: repoPath,
    })));
}
function readTrackedInventory(root) {
    const inventory = readAuditTrackedInventory(root);
    if (inventory.objectFormat === 'sha256') {
        return [diagnostic('unsupported-object-format', 'atlas-review-coverage-v1 supports only SHA-1 Git repositories')];
    }
    if (inventory.objectFormat !== 'sha1') {
        return inventory.diagnostics.length > 0
            ? inventory.diagnostics
            : [diagnostic('git-error', 'failed to read a supported tracked Git inventory')];
    }
    const fatalDiagnostics = inventory.diagnostics.filter((entry) => entry.code !== 'tracked-deletion');
    if (fatalDiagnostics.length > 0) {
        return fatalDiagnostics.map((entry) => entry.code === 'unsafe-worktree-file'
            ? { ...entry, code: 'unreadable-path' }
            : entry);
    }
    const hashes = new Map();
    for (const file of inventory.files) {
        if (file.deleted)
            continue;
        if (file.currentBlob === null || file.currentBlob.length !== 40) {
            return [diagnostic('malformed-inventory', `tracked path has no readable SHA-1 worktree blob: ${file.path}`, { path: file.path })];
        }
        hashes.set(file.path, file.currentBlob);
    }
    return { inventory, hashes };
}
function sameStringSet(actual, expected) {
    if (actual.length !== expected.length)
        return false;
    const values = new Set(actual);
    return values.size === actual.length &&
        expected.every((value) => values.has(value));
}
function policyClassificationErrors(report, inventory, policy) {
    const classified = classifyAuditInventory(inventory.files, policy);
    if (classified.diagnostics.length > 0) {
        return classified.diagnostics;
    }
    const expectedByPath = new Map(classified.files.map((file) => [file.path, file]));
    const errors = [];
    for (const entry of report.entries) {
        const expected = expectedByPath.get(entry.path);
        if (expected === undefined ||
            !sameStringSet(entry.ruleIds, expected.ruleIds) ||
            canonicalJson(entry.classification) !==
                canonicalJson(expected.classification)) {
            errors.push(diagnostic('policy-classification-mismatch', `coverage classification does not match the current strict policy for ` +
                `${JSON.stringify(entry.path)}`, { path: entry.path }));
        }
    }
    if (report.entries.length !== expectedByPath.size) {
        errors.push(diagnostic('policy-classification-mismatch', 'coverage classification path set does not match the current tracked inventory'));
    }
    const expectedUnits = new Map(policy.units.map((unit) => [
        `${unit.domain}:${unit.slug}`,
        unit.title,
    ]));
    const actualUnits = new Map(report.units.map((unit) => [
        `${unit.domain}:${unit.slug}`,
        unit.title,
    ]));
    if (actualUnits.size !== expectedUnits.size ||
        [...expectedUnits].some(([key, title]) => actualUnits.get(key) !== title)) {
        errors.push(diagnostic('policy-classification-mismatch', 'coverage unit identities and titles do not match the current strict policy'));
    }
    return errors;
}
function selfEntryErrors(report) {
    const self = report.entries.find((entry) => entry.path === SELF_PATH);
    if (!self)
        return [];
    const errors = [];
    if (self.blob !== undefined) {
        errors.push(diagnostic('generated-proof', 'generated-proof self entry must omit its blob field', { path: SELF_PATH }));
    }
    const classification = self.classification;
    if (classification.kind !== 'excluded' ||
        classification.ruleId !== 'generated-proof' ||
        classification.category !== 'generated-proof') {
        errors.push(diagnostic('generated-proof', 'exact .atlas/review-coverage.json entry must be the reserved generated-proof exclusion', { path: SELF_PATH }));
    }
    return errors;
}
function inventoryDrift(report, current) {
    const reported = new Map(report.entries.map((entry) => [entry.path, entry]));
    const added = [];
    const removed = [];
    const changed = [];
    for (const repoPath of current.keys()) {
        if (!reported.has(repoPath))
            added.push(repoPath);
    }
    for (const entry of report.entries) {
        if (!current.has(entry.path)) {
            removed.push(entry.path);
            continue;
        }
        if (entry.path === SELF_PATH)
            continue;
        const blob = current.get(entry.path);
        if (entry.blob !== blob)
            changed.push(entry.path);
    }
    added.sort();
    removed.sort();
    changed.sort();
    return { added, removed, changed };
}
function freshEvidenceErrors(report, current, exactEvidence, acceptedRulesets) {
    const unitsByKey = new Map();
    const domainsBySlug = new Map();
    for (const unit of exactEvidence.units) {
        const key = `${unit.domain}:${unit.slug}`;
        const indexed = {
            unit,
            receiptsByPath: new Map(unit.receipts.map((receipt) => [receipt.path, receipt])),
        };
        const existing = unitsByKey.get(key);
        if (existing === undefined)
            unitsByKey.set(key, [indexed]);
        else
            existing.push(indexed);
        const domains = domainsBySlug.get(unit.slug);
        if (domains === undefined) {
            domainsBySlug.set(unit.slug, new Set([unit.domain]));
        }
        else {
            domains.add(unit.domain);
        }
    }
    const acceptedRulesetSet = acceptedRulesets === null
        ? null
        : new Set(acceptedRulesets);
    const errors = [];
    const assignedUnits = new Set();
    for (const entry of report.entries) {
        if (entry.classification.kind === 'review') {
            for (const domain of Object.keys(entry.classification.domains)) {
                const unitSlug = entry.classification.domains[domain]?.unit;
                if (unitSlug)
                    assignedUnits.add(`${domain}:${unitSlug}`);
            }
        }
        for (const domain of Object.keys(entry.evidence)) {
            const claim = entry.evidence[domain];
            if (!claim)
                continue;
            if (claim.status === 'missing') {
                if (claim.ledgers.length !== 0) {
                    errors.push(diagnostic('evidence-ledgers', `missing ${domain} evidence requires an empty ledger list`, { path: entry.path }));
                }
                continue;
            }
            if (claim.status !== 'fresh')
                continue;
            if (claim.ledgers.length === 0) {
                errors.push(diagnostic('evidence-ledgers', `fresh ${domain} evidence requires a nonempty ledger list`, { path: entry.path }));
                continue;
            }
            const assignedSlug = entry.classification.kind === 'review'
                ? entry.classification.domains[domain]?.unit
                : undefined;
            if (assignedSlug === undefined ||
                claim.ledgers.some((slug) => slug !== assignedSlug)) {
                errors.push(diagnostic('wrong-unit-ledger', `fresh ${domain} evidence must name only the policy-assigned unit`, { path: entry.path, slug: assignedSlug }));
                continue;
            }
            const currentBlob = current.get(entry.path);
            const reportBlob = entry.blob;
            if (!currentBlob || !reportBlob || currentBlob !== reportBlob) {
                errors.push(diagnostic('fresh-evidence', `fresh ${domain} claim requires the report blob to match the current inventory blob`, { path: entry.path }));
                continue;
            }
            let matched = false;
            for (const slug of claim.ledgers) {
                const units = unitsByKey.get(`${domain}:${slug}`) ?? [];
                if (units.length === 0) {
                    const registeredDomains = domainsBySlug.get(slug);
                    let crossDomain;
                    if (registeredDomains !== undefined) {
                        for (const candidate of registeredDomains) {
                            if (candidate !== domain) {
                                crossDomain = candidate;
                                break;
                            }
                        }
                    }
                    if (crossDomain !== undefined) {
                        errors.push(diagnostic('cross-domain-ledger', `fresh ${domain} evidence names cross-domain ledger ${slug}`, { path: entry.path, slug }));
                    }
                    else {
                        errors.push(diagnostic('unknown-ledger', `fresh ${domain} evidence names unknown ledger ${slug}`, { path: entry.path, slug }));
                    }
                    continue;
                }
                if (units.length !== 1) {
                    errors.push(diagnostic('ambiguous-ledger', `fresh ${domain} evidence names more than one ledger for ${slug}`, { path: entry.path, slug }));
                    continue;
                }
                const indexed = units[0];
                const unit = indexed.unit;
                const receipt = indexed.receiptsByPath.get(entry.path);
                const accepted = acceptedRulesetSet === null
                    ? unit.version === 2
                    : (unit.ruleset !== null &&
                        acceptedRulesetSet.has(unit.ruleset) &&
                        (unit.version !== 3 ||
                            (unit.rulesetDigest !== null &&
                                /^sha256:[0-9a-f]{64}$/u.test(unit.rulesetDigest))));
                if (unit.version !== 1 &&
                    accepted &&
                    receipt !== undefined &&
                    receipt.reviewed &&
                    receipt.fullRead &&
                    receipt.blob === reportBlob) {
                    matched = true;
                }
            }
            if (!matched) {
                errors.push(diagnostic('fresh-evidence', `fresh ${domain} claim has no accepted current same-domain exact ` +
                    'full-read receipt for the assigned unit and blob', { path: entry.path }));
            }
        }
    }
    // Every registered unit must be assigned to at least one classified path.
    for (const unit of report.units) {
        const key = `${unit.domain}:${unit.slug}`;
        if (!assignedUnits.has(key)) {
            errors.push(diagnostic('unit-assignment', `registered unit ${key} is not assigned to any classified path`, { slug: unit.slug }));
        }
    }
    return errors;
}
/**
 * Task 3: revalidate inventory freshness and ledger evidence against Git and
 * audit portfolios. Structural success is not enough for `current`.
 */
function revalidateAgainstRepository(root, report, _portfolios) {
    const inventory = readTrackedInventory(root);
    if (Array.isArray(inventory)) {
        return invalidPortfolio(inventory);
    }
    const selfErrors = selfEntryErrors(report);
    if (selfErrors.length) {
        return invalidPortfolio(selfErrors);
    }
    const drift = inventoryDrift(report, inventory.hashes);
    const hasDrift = drift.added.length > 0 || drift.removed.length > 0 || drift.changed.length > 0;
    const expectedHash = inventoryHashFrom(inventory.hashes);
    if (!hasDrift && report.inventoryHash !== expectedHash) {
        return invalidPortfolio([diagnostic('inventory-hash', 'coverage inventoryHash does not match the current tracked inventory')]);
    }
    if (hasDrift) {
        // Ordinary path/blob drift: expose the report as stale. Do not trust the
        // embedded verdict for "current", but keep the body for gap inspection.
        return {
            state: 'stale',
            report,
            errors: [diagnostic('inventory-drift', 'coverage inventory has added, removed, or changed tracked paths')],
            drift,
        };
    }
    if (report.policy.format !== 'atlas-review-policy-v1') {
        return invalidPortfolio([diagnostic('unsupported-policy-format', `coverage policy format ${JSON.stringify(report.policy.format)} is unsupported`)]);
    }
    const policy = loadAuditReviewPolicy(root);
    if (policy.policy === null || policy.policyHash === null) {
        return invalidPortfolio(policy.diagnostics);
    }
    if (policy.policyHash !== report.policy.hash) {
        return invalidPortfolio([diagnostic('policy-drift', 'coverage report policy hash does not match the current parsed review policy')]);
    }
    const classificationErrors = policyClassificationErrors(report, inventory.inventory, policy.policy);
    if (classificationErrors.length > 0) {
        return invalidPortfolio(classificationErrors);
    }
    const exactEvidence = loadAuditExactEvidence(root);
    if (exactEvidence.invalidLedgers.length > 0) {
        return invalidPortfolio(exactEvidence.invalidLedgers);
    }
    if (exactEvidence.invalidClaimedPaths.length > 0) {
        return invalidPortfolio(exactEvidence.invalidClaimedPaths.map((claim) => diagnostic('invalid-evidence-path', `invalid audit ledger claimed path ${JSON.stringify(claim.path)}`, { slug: claim.slug ?? undefined })));
    }
    for (const unit of exactEvidence.units) {
        if (unit.invalidClaimedPaths.length > 0) {
            return invalidPortfolio(unit.invalidClaimedPaths.map((repoPath) => diagnostic('invalid-evidence-path', `audit ledger contains invalid claimed path ${JSON.stringify(repoPath)}`, { slug: unit.slug })));
        }
    }
    const evidenceErrors = freshEvidenceErrors(report, inventory.hashes, exactEvidence, policy.policy.securityDecisions.acceptedRulesets);
    if (evidenceErrors.length) {
        return invalidPortfolio(evidenceErrors);
    }
    return {
        state: 'current',
        report,
        errors: [],
        drift: emptyDrift(),
    };
}
function loadReviewCoverageAnchored(root, portfolios) {
    try {
        return withAnchoredAuditFileIdentity(root, COVERAGE_REL, () => {
            let raw;
            try {
                raw = readBoundedAuditJsonDocument(root, COVERAGE_REL, MAX_REPORT_BYTES).value;
            }
            catch (error) {
                const message = error instanceof Error
                    ? error.message
                    : String(error);
                const code = /exceeds the \d+-byte limit/iu.test(message)
                    ? 'report-too-large'
                    : /missing|safe regular|symlink|outside|changed while/iu.test(message)
                        ? 'unsafe-path'
                        : 'malformed-json';
                return invalidPortfolio([diagnostic(code, `coverage report could not be parsed: ${message}`, { path: COVERAGE_REL })]);
            }
            const parsed = parseStructure(raw);
            if (!parsed.ok) {
                return invalidPortfolio(parsed.errors);
            }
            // Structural layer passed. Task 3 overlays Git inventory + ledger
            // revalidation while the report and .atlas parent identities remain
            // retained.
            return revalidateAgainstRepository(root, parsed.report, portfolios);
        });
    }
    catch (error) {
        if (error !== null &&
            typeof error === 'object' &&
            'code' in error &&
            String(error.code) === 'ENOENT') {
            return missingPortfolio();
        }
        const message = error instanceof Error ? error.message : String(error);
        const code = /exceeds.*byte (?:bound|limit)|byte (?:bound|limit).*exceed/iu
            .test(message)
            ? 'report-too-large'
            : 'unsafe-path';
        return invalidPortfolio([diagnostic(code, `coverage report identity could not be retained: ${message}`, { path: COVERAGE_REL })]);
    }
}
export function loadReviewCoverage(root, portfolios) {
    try {
        return withAnchoredAuditRootIdentity(root, (anchoredRoot) => loadReviewCoverageAnchored(anchoredRoot, portfolios));
    }
    catch (error) {
        return invalidPortfolio([diagnostic('root-identity', `coverage reader could not retain one repository root identity: ${error instanceof Error ? error.message : String(error)}`)]);
    }
}
