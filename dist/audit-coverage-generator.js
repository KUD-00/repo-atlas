import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { AUDIT_LIMITS, anchoredAuditRootPath, atomicWriteAuditFile, canonicalJson, normalizeAuditRepoPath, readBoundedAuditBytes, withAnchoredAuditSupportSnapshot, withAuditLock, } from './audit-core.js';
import { buildAuditDecisionIndex, loadAuditDecisionLedgers, reduceAuditDecisionState, } from './audit-decisions.js';
import { loadAuditObservationHistory, loadAuditObservations, } from './audit-v3.js';
import { loadAuditExactEvidence } from './audits.js';
import { AUDIT_MATCH_OPERATION_LIMIT, classifyAuditInventory, loadAuditReviewPolicy, normalizeAuditReviewPolicy, readAuditTrackedInventory, } from './audit-policy.js';
import { reviewCoverageInventoryHash } from './review-coverage-hash.js';
const COVERAGE_PATH = '.atlas/review-coverage.json';
const MAX_COVERAGE_UPDATE_WRITES = 3;
const GENERATED_PROOF = 'GENERATED-PROOF';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const DOMAINS = ['security', 'test'];
const picomatch = createRequire(import.meta.url)('picomatch');
function createHistoricalMatcher(pattern) {
    return picomatch(pattern, { dot: true });
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function diagnostic(code, message, extra = {}) {
    return {
        code,
        message,
        ...(extra.path === undefined ? {} : { path: extra.path }),
        ...(extra.slug === undefined ? {} : { slug: extra.slug }),
    };
}
function sortDiagnostics(values) {
    return [...values].sort((left, right) => compareText(left.path ?? '', right.path ?? '') ||
        compareText(left.slug ?? '', right.slug ?? '') ||
        compareText(left.code, right.code) ||
        compareText(left.message, right.message));
}
function uniqueDiagnostics(values) {
    const seen = new Set();
    return sortDiagnostics(values).filter((value) => {
        const key = canonicalJson(value);
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
function inventoryHash(files) {
    return reviewCoverageInventoryHash(files.map((file) => ({
        marker: file.path === COVERAGE_PATH
            ? GENERATED_PROOF
            : file.currentBlob ?? file.indexBlob,
        path: file.path,
    })));
}
function emptySummary() {
    return {
        tracked: 0,
        securityRequired: 0,
        securityFresh: 0,
        securityMissing: 0,
        securityStale: 0,
        securityInvalid: 0,
        testRequired: 0,
        testFresh: 0,
        testMissing: 0,
        testStale: 0,
        testInvalid: 0,
        dualRequired: 0,
        excluded: 0,
        unclassified: 0,
        conflicted: 0,
        invalidLedgers: 0,
    };
}
function summarize(entries, invalidLedgers) {
    const summary = emptySummary();
    summary.tracked = entries.length;
    summary.invalidLedgers = invalidLedgers.length;
    for (const entry of entries) {
        if (entry.classification.kind === 'excluded') {
            summary.excluded += 1;
            continue;
        }
        if (entry.classification.kind === 'unclassified') {
            summary.unclassified += 1;
            continue;
        }
        if (entry.classification.kind === 'conflict') {
            summary.conflicted += 1;
            continue;
        }
        const security = entry.classification.domains.security !== undefined;
        const test = entry.classification.domains.test !== undefined;
        if (security && test)
            summary.dualRequired += 1;
        for (const domain of DOMAINS) {
            if (entry.classification.domains[domain] === undefined)
                continue;
            const status = entry.evidence[domain]?.status;
            if (domain === 'security') {
                summary.securityRequired += 1;
                if (status === 'fresh')
                    summary.securityFresh += 1;
                else if (status === 'stale')
                    summary.securityStale += 1;
                else if (status === 'invalid')
                    summary.securityInvalid += 1;
                else
                    summary.securityMissing += 1;
            }
            else {
                summary.testRequired += 1;
                if (status === 'fresh')
                    summary.testFresh += 1;
                else if (status === 'stale')
                    summary.testStale += 1;
                else if (status === 'invalid')
                    summary.testInvalid += 1;
                else
                    summary.testMissing += 1;
            }
        }
    }
    return summary;
}
function hasCoverageGap(summary) {
    return (summary.securityMissing +
        summary.securityStale +
        summary.securityInvalid +
        summary.testMissing +
        summary.testStale +
        summary.testInvalid +
        summary.unclassified +
        summary.conflicted +
        summary.invalidLedgers) > 0;
}
function evidenceKey(domain, slug) {
    return `${domain}:${slug}`;
}
function validateEvidenceUnit(unit) {
    const errors = [];
    const paths = new Set();
    for (const receipt of unit.receipts) {
        try {
            normalizeAuditRepoPath(receipt.path);
        }
        catch {
            errors.push(diagnostic('invalid-evidence-path', `exact evidence ${unit.domain}:${unit.slug} claims an invalid path`, { slug: unit.slug }));
            continue;
        }
        if (paths.has(receipt.path)) {
            errors.push(diagnostic('duplicate-evidence-path', `exact evidence ${unit.domain}:${unit.slug} claims ${receipt.path} more than once`, { path: receipt.path, slug: unit.slug }));
        }
        paths.add(receipt.path);
        if (receipt.blob !== null &&
            !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(receipt.blob)) {
            errors.push(diagnostic('invalid-evidence-blob', `exact evidence has an invalid Git blob for ${receipt.path}`, { path: receipt.path, slug: unit.slug }));
        }
        if (receipt.fullRead && (!receipt.reviewed || receipt.blob === null)) {
            errors.push(diagnostic('inconsistent-full-read', `full-read evidence requires a reviewed exact blob for ${receipt.path}`, { path: receipt.path, slug: unit.slug }));
        }
        if (unit.version === 1 && receipt.fullRead) {
            errors.push(diagnostic('forged-v1-full-read', `V1 ledger ${unit.slug} cannot claim schema-owned full-read evidence`, { path: receipt.path, slug: unit.slug }));
        }
    }
    for (const claimedPath of unit.invalidClaimedPaths) {
        errors.push(diagnostic('invalid-evidence-path', `ledger ${unit.slug} contains invalid claimed path ${JSON.stringify(claimedPath)}`, { slug: unit.slug }));
    }
    return errors;
}
function acceptedEvidenceUnit(policy, unit) {
    if (unit.ruleset === null ||
        !policy.securityDecisions.acceptedRulesets.includes(unit.ruleset)) {
        return false;
    }
    if (unit.version === 3) {
        return (unit.rulesetDigest !== null &&
            SHA256_RE.test(unit.rulesetDigest));
    }
    return true;
}
function joinEvidence(file, domain, unitSlug, unitsByKey, policy, fatalErrors) {
    const units = unitsByKey.get(evidenceKey(domain, unitSlug)) ?? [];
    if (units.length > 1) {
        fatalErrors.push(diagnostic('ambiguous-evidence-unit', `multiple exact-evidence ledgers claim assigned unit ${domain}:${unitSlug}`, { path: file.path, slug: unitSlug }));
        return { status: 'invalid', ledgers: [unitSlug] };
    }
    const indexed = units[0];
    if (indexed === undefined || !acceptedEvidenceUnit(policy, indexed.unit)) {
        return { status: 'missing', ledgers: [] };
    }
    const unit = indexed.unit;
    const receipt = indexed.receiptsByPath.get(file.path);
    if (receipt === undefined ||
        !receipt.reviewed ||
        !receipt.fullRead ||
        receipt.blob === null) {
        return { status: 'missing', ledgers: [] };
    }
    if (file.deleted ||
        file.currentBlob === null ||
        receipt.blob !== file.currentBlob) {
        return { status: 'stale', ledgers: [unit.slug] };
    }
    return { status: 'fresh', ledgers: [unit.slug] };
}
function normalizedUnits(policy) {
    return policy.units.map((unit) => ({
        domain: unit.domain,
        slug: unit.slug,
        title: unit.title,
    })).sort((left, right) => compareText(left.domain, right.domain) ||
        compareText(left.slug, right.slug));
}
function snapshotCoveragePublicData(value, pointer = '/input', depth = 0, budget = { items: 0, text: 0 }) {
    if (depth > 128) {
        throw new Error(`${pointer} exceeds the public input depth limit`);
    }
    if (value === null || typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'string') {
        if (value.length > AUDIT_LIMITS.textCodeUnits ||
            value.includes('\0') ||
            /[\uD800-\uDFFF]/u.test(value)) {
            throw new Error(`${pointer} must be bounded text without NUL or lone surrogates`);
        }
        budget.text += value.length;
        if (budget.text > AUDIT_LIMITS.textTotalCodeUnits) {
            throw new Error('coverage public input exceeds the aggregate text limit');
        }
        return value;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value) ||
            (Number.isInteger(value) && !Number.isSafeInteger(value))) {
            throw new Error(`${pointer} must be a finite safe JSON number`);
        }
        return value;
    }
    if ((typeof value === 'object' && value !== null) ||
        typeof value === 'function') {
        if (utilTypes.isProxy(value)) {
            throw new Error(`${pointer} must not contain Proxy objects`);
        }
    }
    if (Array.isArray(value)) {
        if (Object.getPrototypeOf(value) !== Array.prototype) {
            throw new Error(`${pointer} must be a plain array`);
        }
        const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
        if (!lengthDescriptor ||
            !('value' in lengthDescriptor) ||
            typeof lengthDescriptor.value !== 'number' ||
            !Number.isSafeInteger(lengthDescriptor.value) ||
            lengthDescriptor.value < 0 ||
            lengthDescriptor.value > AUDIT_LIMITS.collectionItems) {
            throw new Error(`${pointer} has an invalid or excessive array length`);
        }
        const ownKeys = Reflect.ownKeys(value);
        if (ownKeys.length !== lengthDescriptor.value + 1 ||
            ownKeys.some((key) => {
                if (key === 'length')
                    return false;
                if (typeof key !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(key)) {
                    return true;
                }
                const index = Number(key);
                return !Number.isSafeInteger(index) ||
                    index < 0 ||
                    index >= lengthDescriptor.value;
            })) {
            throw new Error(`${pointer} must be a dense array without extra properties`);
        }
        const output = [];
        for (let index = 0; index < lengthDescriptor.value; index += 1) {
            budget.items += 1;
            if (budget.items > AUDIT_LIMITS.collectionItems) {
                throw new Error('coverage public input exceeds the item limit');
            }
            const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
            if (!descriptor ||
                !descriptor.enumerable ||
                !('value' in descriptor)) {
                throw new Error(`${pointer}/${index} must be an enumerable data property`);
            }
            output.push(snapshotCoveragePublicData(descriptor.value, `${pointer}/${index}`, depth + 1, budget));
        }
        return output;
    }
    if (typeof value !== 'object' ||
        value === null ||
        Object.getPrototypeOf(value) !== Object.prototype) {
        throw new Error(`${pointer} must contain only plain JSON data`);
    }
    const ownKeys = Reflect.ownKeys(value);
    if (ownKeys.some((key) => typeof key !== 'string')) {
        throw new Error(`${pointer} must not contain symbol properties`);
    }
    const output = {};
    for (const key of ownKeys) {
        if (key === '__proto__' || key === 'prototype' || key === 'constructor') {
            throw new Error(`${pointer}/${key} is a prohibited prototype key`);
        }
        if (key.length > AUDIT_LIMITS.textCodeUnits ||
            /[\uD800-\uDFFF]/u.test(key)) {
            throw new Error(`${pointer} contains an invalid property key`);
        }
        budget.text += key.length;
        if (budget.text > AUDIT_LIMITS.textTotalCodeUnits) {
            throw new Error('coverage public input exceeds the aggregate text limit');
        }
        budget.items += 1;
        if (budget.items > AUDIT_LIMITS.collectionItems) {
            throw new Error('coverage public input exceeds the item limit');
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor ||
            !descriptor.enumerable ||
            !('value' in descriptor)) {
            throw new Error(`${pointer}/${key} must be an enumerable data property`);
        }
        output[key] = snapshotCoveragePublicData(descriptor.value, `${pointer}/${key}`, depth + 1, budget);
    }
    return output;
}
class CoverageInputValidationError extends Error {
}
function invalidCoverageInput(pointer, message) {
    throw new CoverageInputValidationError(`${pointer} ${message}`);
}
function coverageRecord(value, pointer) {
    if (value === null ||
        typeof value !== 'object' ||
        Array.isArray(value)) {
        invalidCoverageInput(pointer, 'must be a plain object');
    }
    return value;
}
function exactCoverageKeys(value, required, optional, pointer) {
    const actual = Object.keys(value);
    const allowed = new Set([...required, ...optional]);
    if (actual.some((key) => !allowed.has(key)) ||
        required.some((key) => !Object.hasOwn(value, key))) {
        invalidCoverageInput(pointer, 'has unknown or missing fields');
    }
}
function coverageArray(value, pointer) {
    if (!Array.isArray(value)) {
        invalidCoverageInput(pointer, 'must be an array');
    }
    return value;
}
function coverageText(value, pointer, options = {}) {
    if (typeof value !== 'string' ||
        value.length === 0 ||
        value.length > AUDIT_LIMITS.textCodeUnits ||
        value.includes('\0') ||
        value.trim().length === 0) {
        invalidCoverageInput(pointer, 'must be nonempty bounded text without NUL');
    }
    if (options.routeSlug === true &&
        !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(value)) {
        invalidCoverageInput(pointer, 'must be a route-safe lowercase slug');
    }
    if (options.ruleset === true &&
        !/^[a-z0-9][a-z0-9._/@+-]{0,127}$/u.test(value)) {
        invalidCoverageInput(pointer, 'must be a canonical ruleset ID');
    }
    return value;
}
function coverageRepoPath(value, pointer) {
    if (typeof value !== 'string') {
        invalidCoverageInput(pointer, 'must be a repository path');
    }
    let normalized;
    try {
        normalized = normalizeAuditRepoPath(value);
    }
    catch {
        invalidCoverageInput(pointer, 'must be a normalized repository path');
    }
    if (normalized.normalize('NFC') !== normalized) {
        invalidCoverageInput(pointer, 'must use NFC normalization');
    }
    return normalized;
}
function parseCoverageDiagnostic(value, pointer) {
    const row = coverageRecord(value, pointer);
    exactCoverageKeys(row, ['code', 'message'], ['path', 'slug'], pointer);
    const parsed = {
        code: coverageText(row.code, `${pointer}/code`),
        message: coverageText(row.message, `${pointer}/message`),
    };
    if (Object.hasOwn(row, 'path')) {
        parsed.path = coverageRepoPath(row.path, `${pointer}/path`);
    }
    if (Object.hasOwn(row, 'slug')) {
        parsed.slug = coverageText(row.slug, `${pointer}/slug`, { routeSlug: true });
    }
    return parsed;
}
function parseCoverageDiagnostics(value, pointer) {
    return coverageArray(value, pointer).map((item, index) => parseCoverageDiagnostic(item, `${pointer}/${index}`));
}
function parseExactEvidenceReceipt(value, pointer, version) {
    const row = coverageRecord(value, pointer);
    exactCoverageKeys(row, ['path', 'blob', 'reviewed', 'fullRead'], [], pointer);
    const repoPath = coverageRepoPath(row.path, `${pointer}/path`);
    if (typeof row.reviewed !== 'boolean' || typeof row.fullRead !== 'boolean') {
        invalidCoverageInput(pointer, 'reviewed and fullRead must be booleans');
    }
    let blob;
    if (row.blob === null) {
        blob = null;
    }
    else if (typeof row.blob === 'string' &&
        ((version === 2 && /^[0-9a-f]{40}$/u.test(row.blob)) ||
            (version === 3 && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u.test(row.blob)))) {
        blob = row.blob;
    }
    else {
        invalidCoverageInput(`${pointer}/blob`, `has an invalid V${version} exact Git object shape`);
    }
    if (version === 1 &&
        (blob !== null || row.reviewed !== false || row.fullRead !== false)) {
        invalidCoverageInput(pointer, 'V1 cannot claim exact or full-read evidence');
    }
    if (version === 2 &&
        (blob === null || row.reviewed !== true || row.fullRead !== true)) {
        invalidCoverageInput(pointer, 'V2 requires its complete exact hash attestation');
    }
    if (row.fullRead && (!row.reviewed || blob === null)) {
        invalidCoverageInput(pointer, 'fullRead requires a reviewed exact blob');
    }
    return {
        path: repoPath,
        blob,
        reviewed: row.reviewed,
        fullRead: row.fullRead,
    };
}
function parseExactEvidenceUnit(value, pointer) {
    const row = coverageRecord(value, pointer);
    exactCoverageKeys(row, [
        'version',
        'domain',
        'slug',
        'ruleset',
        'rulesetDigest',
        'semanticStatus',
        'stale',
        'receipts',
        'invalidClaimedPaths',
        'sourcePath',
    ], [], pointer);
    if (row.version !== 1 && row.version !== 2 && row.version !== 3) {
        invalidCoverageInput(`${pointer}/version`, 'must be 1, 2, or 3');
    }
    const version = row.version;
    if (row.domain !== 'security' && row.domain !== 'test') {
        invalidCoverageInput(`${pointer}/domain`, 'must be security or test');
    }
    const domain = row.domain;
    const slug = coverageText(row.slug, `${pointer}/slug`, { routeSlug: true });
    let ruleset;
    if (row.ruleset === null)
        ruleset = null;
    else {
        ruleset = coverageText(row.ruleset, `${pointer}/ruleset`, { ruleset: true });
    }
    let rulesetDigest;
    if (row.rulesetDigest === null)
        rulesetDigest = null;
    else if (typeof row.rulesetDigest === 'string' &&
        SHA256_RE.test(row.rulesetDigest)) {
        rulesetDigest = row.rulesetDigest;
    }
    else {
        invalidCoverageInput(`${pointer}/rulesetDigest`, 'must be null or a sha256 digest');
    }
    if ((ruleset === null) !== (rulesetDigest === null && row.version === 3) &&
        row.version === 3) {
        invalidCoverageInput(pointer, 'V3 ruleset and rulesetDigest must both be null or both be present');
    }
    if (row.version !== 3 && rulesetDigest !== null) {
        invalidCoverageInput(pointer, 'V1/V2 rulesetDigest must be null');
    }
    if (row.semanticStatus !== 'covered' &&
        row.semanticStatus !== 'unknown' &&
        row.semanticStatus !== 'gap') {
        invalidCoverageInput(`${pointer}/semanticStatus`, 'must be covered, unknown, or gap');
    }
    if (typeof row.stale !== 'boolean') {
        invalidCoverageInput(`${pointer}/stale`, 'must be a boolean');
    }
    const receipts = coverageArray(row.receipts, `${pointer}/receipts`)
        .map((receipt, index) => parseExactEvidenceReceipt(receipt, `${pointer}/receipts/${index}`, version));
    const receiptPaths = new Set();
    for (const receipt of receipts) {
        if (receiptPaths.has(receipt.path)) {
            invalidCoverageInput(pointer, `contains duplicate receipt path ${receipt.path}`);
        }
        receiptPaths.add(receipt.path);
    }
    const invalidClaimedPaths = coverageArray(row.invalidClaimedPaths, `${pointer}/invalidClaimedPaths`).map((candidate, index) => coverageText(candidate, `${pointer}/invalidClaimedPaths/${index}`));
    if (new Set(invalidClaimedPaths).size !== invalidClaimedPaths.length) {
        invalidCoverageInput(pointer, 'contains duplicate invalid claimed paths');
    }
    return {
        version,
        domain,
        slug,
        ruleset,
        rulesetDigest,
        semanticStatus: row.semanticStatus,
        stale: row.stale,
        receipts,
        invalidClaimedPaths,
        sourcePath: coverageRepoPath(row.sourcePath, `${pointer}/sourcePath`),
    };
}
function parseExactEvidenceLoad(value, pointer) {
    const row = coverageRecord(value, pointer);
    exactCoverageKeys(row, ['units', 'invalidLedgers', 'invalidClaimedPaths'], [], pointer);
    const units = coverageArray(row.units, `${pointer}/units`)
        .map((unit, index) => parseExactEvidenceUnit(unit, `${pointer}/units/${index}`));
    const unitIds = new Set();
    for (const unit of units) {
        const key = evidenceKey(unit.domain, unit.slug);
        if (unitIds.has(key)) {
            invalidCoverageInput(pointer, `contains duplicate unit identity ${key}`);
        }
        unitIds.add(key);
    }
    const invalidLedgers = parseCoverageDiagnostics(row.invalidLedgers, `${pointer}/invalidLedgers`);
    const invalidClaimedPaths = coverageArray(row.invalidClaimedPaths, `${pointer}/invalidClaimedPaths`).map((value, index) => {
        const claimPointer = `${pointer}/invalidClaimedPaths/${index}`;
        const claim = coverageRecord(value, claimPointer);
        exactCoverageKeys(claim, ['path', 'domain', 'slug', 'sourcePath'], [], claimPointer);
        const claimedPath = coverageText(claim.path, `${claimPointer}/path`);
        if (claim.domain !== null &&
            claim.domain !== 'security' &&
            claim.domain !== 'test') {
            invalidCoverageInput(`${claimPointer}/domain`, 'must be null, security, or test');
        }
        const domain = claim.domain;
        let slug;
        if (claim.slug === null)
            slug = null;
        else {
            slug = coverageText(claim.slug, `${claimPointer}/slug`, { routeSlug: true });
        }
        return {
            path: claimedPath,
            domain,
            slug,
            sourcePath: coverageRepoPath(claim.sourcePath, `${claimPointer}/sourcePath`),
        };
    });
    const claimIds = new Set();
    for (const claim of invalidClaimedPaths) {
        const key = canonicalJson(claim);
        if (claimIds.has(key)) {
            invalidCoverageInput(pointer, 'contains duplicate invalid claimed path rows');
        }
        claimIds.add(key);
    }
    return { units, invalidLedgers, invalidClaimedPaths };
}
function normalizedCoverageInput(unsafeInput) {
    let snapshot;
    try {
        snapshot = snapshotCoveragePublicData(unsafeInput);
    }
    catch (error) {
        return {
            input: null,
            safeInventoryFiles: [],
            error: diagnostic('invalid-coverage-input', error instanceof Error ? error.message : String(error)),
        };
    }
    if (snapshot === null ||
        typeof snapshot !== 'object' ||
        Array.isArray(snapshot)) {
        return {
            input: null,
            safeInventoryFiles: [],
            error: diagnostic('invalid-coverage-input', 'coverage input must be a plain object'),
        };
    }
    const row = snapshot;
    let safeInventoryFiles = [];
    try {
        const evidenceField = Object.hasOwn(row, 'exactEvidence')
            ? 'exactEvidence'
            : Object.hasOwn(row, 'evidence')
                ? 'evidence'
                : null;
        if (evidenceField === null ||
            (Object.hasOwn(row, 'exactEvidence') && Object.hasOwn(row, 'evidence'))) {
            invalidCoverageInput('/input', 'must contain exactly one of exactEvidence or evidence');
        }
        exactCoverageKeys(row, ['policy', 'policyHash', 'inventory', 'classification', evidenceField], [], '/input');
        coverageRecord(row.policy, '/input/policy');
        if (typeof row.policyHash !== 'string') {
            invalidCoverageInput('/input/policyHash', 'must be text');
        }
        const inventoryRow = coverageRecord(row.inventory, '/input/inventory');
        exactCoverageKeys(inventoryRow, ['objectFormat', 'files', 'diagnostics'], [], '/input/inventory');
        if (inventoryRow.objectFormat !== 'sha1' &&
            inventoryRow.objectFormat !== 'sha256' &&
            inventoryRow.objectFormat !== null) {
            invalidCoverageInput('/input/inventory/objectFormat', 'must be sha1, sha256, or null');
        }
        const inventoryFiles = coverageArray(inventoryRow.files, '/input/inventory/files');
        const inventoryProbe = classifyAuditInventory(inventoryFiles, null);
        const invalidInventoryDiagnostics = inventoryProbe.diagnostics.filter((entry) => entry.code !== 'missing-review-policy' &&
            entry.code !== 'tracked-deletion');
        if (invalidInventoryDiagnostics.length > 0) {
            invalidCoverageInput('/input/inventory/files', invalidInventoryDiagnostics[0].message);
        }
        safeInventoryFiles = inventoryProbe.files.map((file) => ({
            path: file.path,
            indexBlob: file.indexBlob,
            currentBlob: file.currentBlob,
            indexMode: file.indexMode,
            currentMode: file.currentMode,
            deleted: file.deleted,
        }));
        const expectedBlobLength = inventoryRow.objectFormat === 'sha1'
            ? 40
            : inventoryRow.objectFormat === 'sha256'
                ? 64
                : null;
        if (expectedBlobLength !== null &&
            safeInventoryFiles.some((file) => file.indexBlob.length !== expectedBlobLength ||
                (file.currentBlob !== null &&
                    file.currentBlob.length !== expectedBlobLength))) {
            invalidCoverageInput('/input/inventory/files', 'Git object IDs do not match inventory objectFormat');
        }
        const inventoryDiagnostics = parseCoverageDiagnostics(inventoryRow.diagnostics, '/input/inventory/diagnostics');
        const classificationRow = coverageRecord(row.classification, '/input/classification');
        exactCoverageKeys(classificationRow, ['files', 'diagnostics'], [], '/input/classification');
        coverageArray(classificationRow.files, '/input/classification/files');
        const classificationDiagnostics = parseCoverageDiagnostics(classificationRow.diagnostics, '/input/classification/diagnostics');
        const exactEvidence = parseExactEvidenceLoad(row[evidenceField], `/input/${evidenceField}`);
        const normalized = {
            policy: row.policy,
            policyHash: row.policyHash,
            inventory: {
                objectFormat: inventoryRow.objectFormat,
                files: safeInventoryFiles,
                diagnostics: inventoryDiagnostics,
            },
            classification: {
                files: classificationRow.files,
                diagnostics: classificationDiagnostics,
            },
            exactEvidence,
        };
        return { input: normalized, safeInventoryFiles, error: null };
    }
    catch (error) {
        return {
            input: null,
            safeInventoryFiles: [],
            error: diagnostic('invalid-coverage-input', error instanceof Error ? error.message : String(error)),
        };
    }
}
export function buildAuditCoverageReport(unsafeInput) {
    const normalizedInput = normalizedCoverageInput(unsafeInput);
    if (normalizedInput.input === null) {
        return placeholderInvalidReport(normalizedInput.safeInventoryFiles, [normalizedInput.error ?? diagnostic('invalid-coverage-input', 'coverage input is invalid')]);
    }
    const input = normalizedInput.input;
    if (input.inventory.objectFormat !== 'sha1') {
        const objectFormatError = input.inventory.objectFormat === 'sha256'
            ? diagnostic('unsupported-object-format', 'atlas-review-coverage-v1 supports only SHA-1 Git repositories')
            : diagnostic('invalid-object-format', 'coverage inventory is missing a supported Git object format');
        return placeholderInvalidReport([], [...input.inventory.diagnostics, objectFormatError]);
    }
    let normalizedPolicy;
    try {
        normalizedPolicy = normalizeAuditReviewPolicy(input.policy);
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return placeholderInvalidReport(input.inventory.files, [diagnostic('invalid-public-policy', `coverage policy input is invalid: ${message}`)]);
    }
    const policy = normalizedPolicy.policy;
    const trustedClassification = classifyAuditInventory(input.inventory.files, policy);
    const exactEvidence = input.exactEvidence ?? input.evidence ?? {
        units: [],
        invalidLedgers: [],
        invalidClaimedPaths: [],
    };
    const fatalErrors = [
        ...input.inventory.diagnostics,
        ...trustedClassification.diagnostics,
    ];
    if (!/^[0-9a-f]{64}$/.test(input.policyHash) ||
        input.policyHash !== normalizedPolicy.policyHash) {
        fatalErrors.push(diagnostic('invalid-policy-hash', 'review policy hash must equal the canonical parsed policy SHA-256'));
    }
    try {
        if (canonicalJson(input.classification.files) !==
            canonicalJson(trustedClassification.files)) {
            fatalErrors.push(diagnostic('forged-classification', 'supplied classification differs from strict policy recomputation'));
        }
    }
    catch {
        fatalErrors.push(diagnostic('forged-classification', 'supplied classification is not plain canonical data'));
    }
    const unitsByKey = new Map();
    for (const unit of exactEvidence.units) {
        fatalErrors.push(...validateEvidenceUnit(unit));
        const key = evidenceKey(unit.domain, unit.slug);
        const indexed = {
            unit,
            receiptsByPath: new Map(unit.receipts.map((receipt) => [receipt.path, receipt])),
        };
        const existing = unitsByKey.get(key);
        if (existing === undefined)
            unitsByKey.set(key, [indexed]);
        else
            existing.push(indexed);
    }
    for (const claim of exactEvidence.invalidClaimedPaths ?? []) {
        fatalErrors.push(diagnostic('invalid-evidence-path', `invalid audit ledger ${claim.sourcePath} claimed path ` +
            `${JSON.stringify(claim.path)}`, {
            ...(claim.slug === null ? {} : { slug: claim.slug }),
        }));
    }
    const historicalGlobCount = policy.historicalUnitAssignments.reduce((count, assignment) => count + assignment.include.length, 0);
    const receiptCount = exactEvidence.units.reduce((count, unit) => count + unit.receipts.length, 0);
    const historicalReceiptMatchOperations = BigInt(historicalGlobCount) * BigInt(receiptCount);
    const historicalReceiptResourceLimited = historicalReceiptMatchOperations > AUDIT_MATCH_OPERATION_LIMIT;
    if (historicalReceiptResourceLimited) {
        fatalErrors.push(diagnostic('historical-receipt-resource-limit', `historical receipt overlap requires ` +
            `${historicalReceiptMatchOperations.toString()} worst-case match ` +
            `operations; limit is ${AUDIT_MATCH_OPERATION_LIMIT.toString()}`));
    }
    else {
        const compiledHistoricalAssignments = policy.historicalUnitAssignments.map((assignment) => ({
            assignment,
            // Patterns were normalized by the strict policy parser.
            matches: assignment.include.map((pattern) => createHistoricalMatcher(pattern)),
        }));
        for (const candidate of compiledHistoricalAssignments) {
            for (const unit of exactEvidence.units) {
                for (const receipt of unit.receipts) {
                    if (!candidate.matches.some((matches) => matches(receipt.path))) {
                        continue;
                    }
                    fatalErrors.push(diagnostic('historical-active-receipt-overlap', `historical assignment ${candidate.assignment.id} matches active exact ` +
                        `receipt ${JSON.stringify(receipt.path)}`, { path: receipt.path, slug: unit.slug }));
                }
            }
        }
    }
    const classifiedByPath = new Map(trustedClassification.files.map((file) => [file.path, file]));
    const entries = [];
    for (const file of [...trustedClassification.files]
        .sort((left, right) => compareText(left.path, right.path))) {
        if (file.deleted || file.currentBlob === null) {
            fatalErrors.push(diagnostic('tracked-deletion', `tracked path is deleted from the worktree: ${JSON.stringify(file.path)}`, { path: file.path }));
        }
        if (file.path === COVERAGE_PATH) {
            const classified = classifiedByPath.get(file.path);
            if (classified === undefined ||
                classified.ruleIds.length !== 1 ||
                classified.ruleIds[0] !== 'generated-proof' ||
                classified.classification.kind !== 'excluded' ||
                classified.classification.ruleId !== 'generated-proof' ||
                classified.classification.category !== 'generated-proof') {
                fatalErrors.push(diagnostic('invalid-generated-proof', 'tracked .atlas/review-coverage.json requires the exact reserved ' +
                    'generated-proof policy classification', { path: COVERAGE_PATH }));
                entries.push({
                    path: file.path,
                    ruleIds: classified?.ruleIds ?? [],
                    classification: { kind: 'conflict' },
                    evidence: {},
                });
            }
            else {
                entries.push({
                    path: file.path,
                    ruleIds: [...classified.ruleIds],
                    classification: classified.classification,
                    evidence: {},
                });
            }
            continue;
        }
        const classified = classifiedByPath.get(file.path);
        if (classified === undefined) {
            fatalErrors.push(diagnostic('missing-classification', `tracked path has no classification result: ${JSON.stringify(file.path)}`, { path: file.path }));
            entries.push({
                path: file.path,
                blob: file.currentBlob ?? file.indexBlob,
                ruleIds: [],
                classification: { kind: 'conflict' },
                evidence: {},
            });
            continue;
        }
        const evidence = {};
        if (classified.classification.kind === 'review') {
            for (const domain of DOMAINS) {
                const assignment = classified.classification.domains[domain];
                if (assignment === undefined)
                    continue;
                evidence[domain] = historicalReceiptResourceLimited
                    ? { status: 'invalid', ledgers: [] }
                    : joinEvidence(file, domain, assignment.unit, unitsByKey, policy, fatalErrors);
            }
        }
        entries.push({
            path: file.path,
            blob: file.currentBlob ?? file.indexBlob,
            ruleIds: [...classified.ruleIds].sort(compareText),
            classification: classified.classification,
            evidence,
        });
    }
    for (const entry of entries) {
        if (entry.classification.kind === 'unclassified' ||
            entry.classification.kind === 'conflict') {
            fatalErrors.push(diagnostic('invalid-classification', `tracked path is ${entry.classification.kind}: ${JSON.stringify(entry.path)}`, { path: entry.path }));
        }
        if (entry.classification.kind !== 'review' &&
            Object.keys(entry.evidence).length > 0) {
            fatalErrors.push(diagnostic('inconsistent-evidence-join', `non-review path carries domain evidence: ${JSON.stringify(entry.path)}`, { path: entry.path }));
        }
    }
    const invalidLedgerDetails = uniqueDiagnostics(exactEvidence.invalidLedgers);
    if (invalidLedgerDetails.length > 0) {
        fatalErrors.push(diagnostic('invalid-audit-ledgers', `${invalidLedgerDetails.length} invalid audit ledger diagnostic(s) ` +
            'prevent trusted coverage generation'));
    }
    const summary = summarize(entries, invalidLedgerDetails);
    const reportErrors = uniqueDiagnostics(fatalErrors);
    const verdict = reportErrors.length > 0
        ? 'invalid'
        : hasCoverageGap(summary)
            ? 'incomplete'
            : 'complete';
    return {
        formatVersion: 1,
        format: 'atlas-review-coverage-v1',
        verdict,
        policy: {
            format: policy.format,
            hash: normalizedPolicy.policyHash,
        },
        inventoryHash: inventoryHash(trustedClassification.files),
        units: normalizedUnits(policy),
        summary,
        entries,
        invalidLedgerDetails,
        reportErrors,
    };
}
/**
 * A blocking finding used to produce NO diagnostic at all.
 *
 * `runtimeAssuranceAllows` would fail the coverage area while every printed line
 * was an unrelated coverage gap, so the reason the gate was red never appeared in
 * its own output. Observed on a real repository: 153 decisions had been silently
 * invalidated by a stale `reviewContext.policyDigest` — the reducer knew
 * (`derivation: 'carry-invalidated'`) and the projection dropped it, so the state
 * read as an indistinguishable `open` and diagnosing it took hours.
 *
 * One line per derivation, not per finding: the count is the signal, and a
 * per-finding list would bury it under a thousand coverage gaps.
 */
function blockingFindingDiagnostics(assurance) {
    const byDerivation = new Map();
    for (const finding of assurance.lifecycle.findings) {
        if (!finding.blocking)
            continue;
        const key = finding.derivation ?? 'unknown';
        byDerivation.set(key, (byDerivation.get(key) ?? 0) + 1);
    }
    return [...byDerivation.entries()]
        .sort(([left], [right]) => compareText(left, right))
        .map(([derivation, count]) => diagnostic('blocking-findings', `${String(count)} finding(s) block coverage with derivation "${derivation}"` +
        (derivation === 'carry-invalidated'
            ? ' — their decisions exist but no longer apply; the usual cause is a' +
                ' reviewContext policyDigest or ruleset that no longer matches the' +
                ' current policy. Re-record them against the current policy.'
            : derivation === 'implicit-open'
                ? ' — never dispositioned. Record a decision with `audit decision set`.'
                : '')));
}
function lifecycleAssurance(root, policy) {
    const observations = loadAuditObservations(root);
    const histories = loadAuditObservationHistory(root);
    const decisions = loadAuditDecisionLedgers(root);
    const diagnostics = [
        ...observations.diagnostics,
        ...histories.diagnostics,
        ...decisions.diagnostics,
    ].map((entry) => {
        let repoPath;
        try {
            repoPath = normalizeAuditRepoPath(entry.path);
        }
        catch {
            repoPath = undefined;
        }
        return diagnostic(entry.code, entry.message, repoPath === undefined ? {} : { path: repoPath });
    });
    if (diagnostics.length > 0) {
        return { findings: [], diagnostics: uniqueDiagnostics(diagnostics) };
    }
    try {
        const index = buildAuditDecisionIndex(observations.observations, histories.histories, decisions.ledgers);
        const state = reduceAuditDecisionState(index, policy.securityDecisions, new Date().toISOString());
        const findings = [...state.findings.entries()]
            .map(([findingId, finding]) => ({
            findingId,
            disposition: finding.disposition,
            blocking: finding.blocking,
            lifecycle: finding.lifecycle,
            expiryState: finding.expiryState,
            // WHY a finding is blocking, not just that it is. The reducer already
            // distinguishes a never-dispositioned finding from one whose decision was
            // invalidated (`carry-invalidated` — a stale reviewContext policyDigest or
            // ruleset, or an expired acceptance), but this projection dropped the
            // field, so both surfaced as an indistinguishable `open`. Diagnosing 153
            // silently invalidated decisions in a real repository took hours that this
            // one word would have saved.
            derivation: finding.derivation,
        }))
            .sort((left, right) => compareText(left.findingId, right.findingId));
        return { findings, diagnostics: [] };
    }
    catch (error) {
        return {
            findings: [],
            diagnostics: [diagnostic('audit-lifecycle-invalid', `audit lifecycle assurance could not be reduced: ${error instanceof Error ? error.message : String(error)}`)],
        };
    }
}
function runtimeAssurance(root, policy, evidence) {
    const units = [...evidence.units].sort((left, right) => compareText(left.domain, right.domain) ||
        compareText(left.slug, right.slug) ||
        compareText(left.sourcePath, right.sourcePath));
    return {
        semantic: units.map((unit) => ({
            domain: unit.domain,
            slug: unit.slug,
            status: unit.semanticStatus ?? 'unknown',
        })),
        rulesets: units.map((unit) => ({
            domain: unit.domain,
            slug: unit.slug,
            ruleset: unit.ruleset,
            rulesetDigest: unit.rulesetDigest,
            accepted: acceptedEvidenceUnit(policy, unit),
        })),
        lifecycle: lifecycleAssurance(root, policy),
    };
}
function gapDiagnostics(report) {
    const errors = [];
    for (const entry of report.entries) {
        if (entry.classification.kind !== 'review')
            continue;
        for (const domain of DOMAINS) {
            const status = entry.evidence[domain]?.status;
            if (status !== undefined && status !== 'fresh') {
                errors.push(diagnostic('coverage-gap', `${domain} exact evidence is ${status} for ${JSON.stringify(entry.path)}`, { path: entry.path }));
            }
        }
    }
    return errors;
}
function canonicalCoverageBytes(report) {
    return `${canonicalJson(report)}\n`;
}
function placeholderInvalidReport(files, errors) {
    const representableFiles = files.filter((file) => file.path === COVERAGE_PATH ||
        /^[0-9a-f]{40}$/u.test(file.currentBlob ?? file.indexBlob));
    const entries = [...representableFiles]
        .sort((left, right) => compareText(left.path, right.path))
        .map((file) => file.path === COVERAGE_PATH
        ? {
            path: file.path,
            ruleIds: [],
            classification: { kind: 'conflict' },
            evidence: {},
        }
        : {
            path: file.path,
            blob: file.currentBlob ?? file.indexBlob,
            ruleIds: [],
            classification: { kind: 'conflict' },
            evidence: {},
        });
    const reportErrors = uniqueDiagnostics(errors.length > 0
        ? errors
        : [diagnostic('invalid-coverage-input', 'coverage input is invalid')]);
    return {
        formatVersion: 1,
        format: 'atlas-review-coverage-v1',
        verdict: 'invalid',
        policy: {
            format: 'atlas-review-policy-v1',
            hash: '0'.repeat(64),
        },
        inventoryHash: inventoryHash(representableFiles),
        units: [],
        summary: summarize(entries, []),
        entries,
        invalidLedgerDetails: [],
        reportErrors,
    };
}
function prepareCoverage(root) {
    const inventory = readAuditTrackedInventory(root);
    if (inventory.objectFormat !== 'sha1') {
        const objectFormatError = inventory.objectFormat === 'sha256'
            ? diagnostic('unsupported-object-format', 'atlas-review-coverage-v1 supports only SHA-1 Git repositories')
            : diagnostic('invalid-object-format', 'coverage inventory is missing a supported Git object format');
        const report = placeholderInvalidReport([], [...inventory.diagnostics, objectFormatError]);
        return {
            report,
            bytes: canonicalCoverageBytes(report),
            assurance: {
                semantic: [],
                rulesets: [],
                lifecycle: { findings: [], diagnostics: [] },
            },
            diagnostics: report.reportErrors,
            writeForbiddenObjectFormat: true,
        };
    }
    const policyLoad = loadAuditReviewPolicy(root);
    if (policyLoad.policy === null || policyLoad.policyHash === null) {
        const report = placeholderInvalidReport(inventory.files, [...policyLoad.diagnostics, ...inventory.diagnostics]);
        return {
            report,
            bytes: canonicalCoverageBytes(report),
            assurance: {
                semantic: [],
                rulesets: [],
                lifecycle: { findings: [], diagnostics: [] },
            },
            diagnostics: report.reportErrors,
            writeForbiddenObjectFormat: false,
        };
    }
    const classification = classifyAuditInventory(inventory.files, policyLoad.policy);
    const exactEvidence = loadAuditExactEvidence(root);
    const report = buildAuditCoverageReport({
        policy: policyLoad.policy,
        policyHash: policyLoad.policyHash,
        inventory,
        classification,
        exactEvidence,
    });
    const assurance = runtimeAssurance(root, policyLoad.policy, exactEvidence);
    const diagnostics = uniqueDiagnostics([
        ...report.reportErrors,
        ...report.invalidLedgerDetails,
        ...gapDiagnostics(report),
        ...assurance.lifecycle.diagnostics,
        ...blockingFindingDiagnostics(assurance),
    ]);
    return {
        report,
        bytes: canonicalCoverageBytes(report),
        assurance,
        diagnostics,
        writeForbiddenObjectFormat: false,
    };
}
function prepareCoverageSnapshot(root) {
    let prepared = null;
    try {
        const value = withAnchoredAuditSupportSnapshot(root, () => {
            prepared = prepareCoverage(root);
            const existing = prepared.writeForbiddenObjectFormat
                ? { bytes: null, error: null }
                : readCommittedCoverageBytes(root);
            return { prepared, existing };
        });
        return { ok: true, value };
    }
    catch (error) {
        return { ok: false, prepared, error };
    }
}
function snapshotFailureResult(prepared, error, wrote = false) {
    const snapshotError = diagnostic('coverage-snapshot-invalid', `coverage inputs changed or could not be retained as one snapshot: ${error instanceof Error ? error.message : String(error)} — a build or generator writing during the read is the usual cause; re-run ` +
        `once nothing else is writing to the tree`);
    const fallback = prepared ?? (() => {
        const report = placeholderInvalidReport([], [snapshotError]);
        return {
            report,
            bytes: canonicalCoverageBytes(report),
            assurance: {
                semantic: [],
                rulesets: [],
                lifecycle: { findings: [], diagnostics: [] },
            },
            diagnostics: report.reportErrors,
            writeForbiddenObjectFormat: false,
        };
    })();
    return {
        ok: false,
        current: false,
        wrote,
        bytes: fallback.bytes,
        report: fallback.report,
        diagnostics: uniqueDiagnostics([
            ...fallback.diagnostics,
            snapshotError,
        ]),
        runtimeAssurance: fallback.assurance,
    };
}
function readCommittedCoverageBytes(root) {
    const absolute = path.join(root, ...COVERAGE_PATH.split('/'));
    let stat;
    try {
        stat = fs.lstatSync(absolute);
    }
    catch (error) {
        if (error.code === 'ENOENT') {
            return {
                bytes: null,
                error: diagnostic('coverage-report-missing', 'committed coverage report is missing', { path: COVERAGE_PATH }),
            };
        }
        return {
            bytes: null,
            error: diagnostic('coverage-report-unreadable', 'committed coverage report is unreadable', { path: COVERAGE_PATH }),
        };
    }
    if (!stat.isFile() || stat.isSymbolicLink()) {
        return {
            bytes: null,
            error: diagnostic('coverage-report-unsafe', 'committed coverage report is not a safe regular file', { path: COVERAGE_PATH }),
        };
    }
    try {
        return {
            bytes: Buffer.from(readBoundedAuditBytes(root, COVERAGE_PATH)).toString('utf8'),
            error: null,
        };
    }
    catch (error) {
        return {
            bytes: null,
            error: diagnostic('coverage-report-unreadable', `committed coverage report could not be read safely: ${error instanceof Error ? error.message : String(error)}`, { path: COVERAGE_PATH }),
        };
    }
}
function verdictAllowed(report, allowIncomplete) {
    return (report.verdict === 'complete' ||
        (report.verdict === 'incomplete' && allowIncomplete));
}
function runtimeAssuranceAllows(assurance) {
    return (assurance.lifecycle.diagnostics.length === 0 &&
        !assurance.lifecycle.findings.some((finding) => finding.blocking));
}
function updateAuditCoverageUnlocked(root, options = {}) {
    let wrote = false;
    let writeCount = 0;
    while (true) {
        const snapshot = prepareCoverageSnapshot(root);
        if (!snapshot.ok) {
            return snapshotFailureResult(snapshot.prepared, snapshot.error, wrote);
        }
        const { prepared, existing } = snapshot.value;
        if (prepared.writeForbiddenObjectFormat) {
            return {
                ok: false,
                current: false,
                wrote,
                bytes: prepared.bytes,
                report: prepared.report,
                diagnostics: prepared.diagnostics,
                runtimeAssurance: prepared.assurance,
            };
        }
        if (existing.bytes === prepared.bytes) {
            return {
                ok: verdictAllowed(prepared.report, options.allowIncomplete === true) &&
                    runtimeAssuranceAllows(prepared.assurance),
                current: true,
                wrote,
                bytes: prepared.bytes,
                report: prepared.report,
                diagnostics: prepared.diagnostics,
                runtimeAssurance: prepared.assurance,
            };
        }
        if (writeCount >= MAX_COVERAGE_UPDATE_WRITES) {
            const convergenceError = diagnostic('coverage-update-did-not-converge', `coverage inputs changed across ${MAX_COVERAGE_UPDATE_WRITES} consecutive atomic writes`, { path: COVERAGE_PATH });
            return {
                ok: false,
                current: false,
                wrote,
                bytes: prepared.bytes,
                report: prepared.report,
                diagnostics: uniqueDiagnostics([
                    ...prepared.diagnostics,
                    convergenceError,
                ]),
                runtimeAssurance: prepared.assurance,
            };
        }
        try {
            atomicWriteAuditFile(root, COVERAGE_PATH, prepared.bytes);
            wrote = true;
            writeCount += 1;
        }
        catch (error) {
            const writeError = diagnostic('coverage-write-failed', `coverage report could not be replaced atomically: ${error instanceof Error ? error.message : String(error)}`, { path: COVERAGE_PATH });
            return {
                ok: false,
                current: false,
                wrote,
                bytes: prepared.bytes,
                report: prepared.report,
                diagnostics: uniqueDiagnostics([
                    ...prepared.diagnostics,
                    writeError,
                ]),
                runtimeAssurance: prepared.assurance,
            };
        }
    }
}
export function updateAuditCoverage(root, options = {}) {
    return withAuditLock(root, () => updateAuditCoverageUnlocked(anchoredAuditRootPath(root), options));
}
function checkAuditCoverageUnlocked(root, options = {}) {
    const snapshot = prepareCoverageSnapshot(root);
    if (!snapshot.ok) {
        return snapshotFailureResult(snapshot.prepared, snapshot.error);
    }
    const { prepared, existing } = snapshot.value;
    const current = !prepared.writeForbiddenObjectFormat &&
        existing.bytes === prepared.bytes;
    const byteErrors = [];
    if (!prepared.writeForbiddenObjectFormat && !current) {
        if (existing.error !== null)
            byteErrors.push(existing.error);
        else {
            byteErrors.push(diagnostic('coverage-byte-drift', 'committed coverage bytes are not the exact canonical generated bytes — ' +
                'run `repo-atlas audit coverage update` and commit the result', { path: COVERAGE_PATH }));
        }
    }
    const diagnostics = uniqueDiagnostics([
        ...prepared.diagnostics,
        ...byteErrors,
    ]);
    return {
        ok: current &&
            verdictAllowed(prepared.report, options.allowIncomplete === true) &&
            runtimeAssuranceAllows(prepared.assurance),
        current,
        wrote: false,
        bytes: prepared.bytes,
        report: prepared.report,
        diagnostics,
        runtimeAssurance: prepared.assurance,
    };
}
export function checkAuditCoverage(root, options = {}) {
    return withAuditLock(root, () => checkAuditCoverageUnlocked(anchoredAuditRootPath(root), options));
}
