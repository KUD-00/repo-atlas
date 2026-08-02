import { createHash } from 'node:crypto';
import path from 'node:path';
import { types as utilTypes } from 'node:util';
import { AUDIT_LIMITS, canonicalJson, normalizeAuditRepoPath, readBoundedAuditBytes, readBoundedAuditJson, readBoundedAuditJsonDocument, withAnchoredAuditSupportSnapshot, } from './audit-core.js';
import { computeAuditCanonicalDigest, computeAtlasFindingId, computeAtlasFingerprint, computeAtlasObservationId, computeAtlasOccurrenceId, computeSemanticScopeIdentityDigest, isStrictRfc3339Timestamp, prepareAuditObservationPublication, publishAuditObservation, } from './audit-v3.js';
const ADAPTER_NAME = 'repo-atlas/codex-security-v1';
const ADAPTER_VERSION = '0.1.0';
const CONTRACT_NAMESPACE = 'codex-security/1.0';
const MANIFEST_NAMESPACE = 'codex-security.scan-manifest/1.0';
const FINDINGS_NAMESPACE = 'codex-security.findings/1.0';
const COVERAGE_NAMESPACE = 'codex-security.coverage/1.0';
const UNAVAILABLE_EXACT_REASON = 'Codex Security 1.0 did not supply exact per-file blob receipts.';
const CONTRACT_DOCUMENTS = [
    'codex-security.scan-manifest/1.0',
    'codex-security.findings/1.0',
    'codex-security.coverage/1.0',
];
const MAX_ARTIFACTS = 10_000;
const MAX_FINDINGS = 10_000;
const MAX_CODE_EVIDENCE = 32;
const MAX_BUNDLE_BYTES = AUDIT_LIMITS.jsonBytes;
const RAW_SHA256_RE = /^[0-9a-f]{64}$/u;
const SNAPSHOT_RE = /^codex-security-snapshot\/v1:(sha256:[0-9a-f]{64})$/u;
const SOURCE_SLUG_RE = /^[a-z0-9][a-z0-9._/-]*$/u;
const SOURCE_FINDING_ID_RE = /^csf_[0-9a-f]{24}$/u;
const SOURCE_OCCURRENCE_ID_RE = /^occ_[0-9a-f]{24}$/u;
const SOURCE_FINGERPRINT_RE = /^codex-security\/v1:sha256:[0-9a-f]{64}$/u;
const REPOSITORY_ID_RE = /^repo_[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?$/u;
const WRITEUP_RE = /^findings\/([a-z0-9][a-z0-9._-]*)\/\1\.md$/u;
const URL_SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.-]*:/u;
const PYTHON_WHITESPACE_RE = /^[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]*$/u;
const TEXT_LIMIT = 256 * 1024;
function invalid(pointer, message) {
    throw new Error(`Codex Security bundle${pointer.length === 0 ? '' : ` ${pointer}`}: ${message}`);
}
function utf16Compare(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function sha256(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}
function pointerToken(value) {
    return value.replace(/~/gu, '~0').replace(/\//gu, '~1');
}
function childPointer(pointer, key) {
    return `${pointer}/${pointerToken(String(key))}`;
}
function recordAt(value, pointer) {
    if (value === null ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        Object.getPrototypeOf(value) !== Object.prototype) {
        invalid(pointer, 'expected an object');
    }
    return value;
}
function arrayAt(value, pointer) {
    if (!Array.isArray(value))
        invalid(pointer, 'expected an array');
    return value;
}
function stringAt(value, pointer, options = {}) {
    const nonempty = options.nonempty ?? true;
    if (typeof value !== 'string' ||
        (nonempty && value.length === 0) ||
        value.length > TEXT_LIMIT ||
        (options.pattern !== undefined && !options.pattern.test(value))) {
        invalid(pointer, 'expected a valid bounded string');
    }
    return value;
}
function optionalStringAt(record, key, pointer, options) {
    if (!Object.hasOwn(record, key))
        return undefined;
    return stringAt(record[key], childPointer(pointer, key), options);
}
function numberAt(value, pointer) {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
        invalid(pointer, 'expected a finite number');
    }
    return value;
}
function positiveIntegerAt(value, pointer) {
    if (!Number.isSafeInteger(value) || Number(value) < 1) {
        invalid(pointer, 'expected a positive safe integer');
    }
    return Number(value);
}
function enumAt(value, allowed, pointer) {
    if (typeof value !== 'string' ||
        !allowed.includes(value)) {
        invalid(pointer, `expected one of ${allowed.join(', ')}`);
    }
    return value;
}
function stringArrayAt(value, pointer, options = {}) {
    const rows = arrayAt(value, pointer);
    const strings = rows.map((row, index) => stringAt(row, childPointer(pointer, index), { nonempty: options.nonemptyItems ?? true }));
    if (options.unique === true &&
        new Set(strings).size !== strings.length) {
        invalid(pointer, 'contains duplicate strings');
    }
    return strings;
}
function optionalStringArrayAt(record, key, pointer) {
    if (!Object.hasOwn(record, key))
        return undefined;
    return stringArrayAt(record[key], childPointer(pointer, key), {
        nonemptyItems: true,
    });
}
function requireTimestamp(value, pointer) {
    const timestamp = stringAt(value, pointer);
    if (!isStrictRfc3339Timestamp(timestamp)) {
        invalid(pointer, 'expected a valid RFC 3339 date-time');
    }
    return timestamp;
}
function safeBundlePath(value, pointer) {
    const candidate = stringAt(value, pointer);
    let normalized;
    try {
        normalized = normalizeAuditRepoPath(candidate);
    }
    catch {
        invalid(pointer, 'expected a safe scan-relative POSIX path');
    }
    if (normalized.split('/').some((segment) => segment.includes(':'))) {
        invalid(pointer, 'expected a safe scan-relative POSIX path');
    }
    return normalized;
}
function safeRepositoryPath(value, pointer) {
    return safeBundlePath(value, pointer);
}
function sameJson(left, right) {
    return canonicalJson(left) === canonicalJson(right);
}
function ownDataRecord(value, pointer) {
    if (utilTypes.isProxy(value))
        invalid(pointer, 'Proxy objects are forbidden');
    if (value === null ||
        typeof value !== 'object' ||
        Array.isArray(value)) {
        invalid(pointer, 'expected a plain data object');
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        invalid(pointer, 'expected a plain data object');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!descriptor.enumerable || !('value' in descriptor)) {
            invalid(childPointer(pointer, key), 'accessors are forbidden');
        }
    }
    return Object.fromEntries(Object.entries(descriptors).map(([key, descriptor]) => [
        key,
        descriptor.value,
    ]));
}
function snapshotImportOptions(options) {
    const record = ownDataRecord(options, '/options');
    const allowed = new Set([
        'bundlePath',
        'unitSlug',
        'unitTitle',
        'conceptSlug',
        'apply',
    ]);
    for (const key of Object.keys(record)) {
        if (!allowed.has(key))
            invalid(`/options/${key}`, 'unknown import option');
    }
    const bundlePath = stringAt(record.bundlePath, '/options/bundlePath');
    const unitSlug = stringAt(record.unitSlug, '/options/unitSlug');
    const unitTitle = record.unitTitle === undefined
        ? undefined
        : stringAt(record.unitTitle, '/options/unitTitle');
    const conceptSlug = record.conceptSlug === undefined
        ? undefined
        : stringAt(record.conceptSlug, '/options/conceptSlug');
    if (record.apply !== undefined &&
        typeof record.apply !== 'boolean') {
        invalid('/options/apply', 'expected a boolean');
    }
    return {
        bundlePath,
        unitSlug,
        ...(unitTitle === undefined ? {} : { unitTitle }),
        ...(conceptSlug === undefined ? {} : { conceptSlug }),
        apply: record.apply === true,
    };
}
function localBundleRoot(repositoryRoot, bundlePath) {
    if (URL_SCHEME_RE.test(bundlePath) ||
        bundlePath.startsWith('//') ||
        bundlePath.includes('\0')) {
        throw new Error('Codex Security bundlePath must be a local filesystem path');
    }
    return path.isAbsolute(bundlePath)
        ? path.resolve(bundlePath)
        : path.resolve(repositoryRoot, bundlePath);
}
function validateProducer(producer, pointer) {
    stringAt(producer.name, `${pointer}/name`);
    stringAt(producer.version, `${pointer}/version`);
}
function validateTarget(target, pointer) {
    const kind = enumAt(target.kind, ['git_revision', 'git_worktree', 'git_diff', 'directory_snapshot'], `${pointer}/kind`);
    stringAt(target.targetId, `${pointer}/targetId`);
    stringAt(target.displayName, `${pointer}/displayName`);
    optionalStringAt(target, 'remote', pointer);
    for (const key of ['revision', 'baseRevision', 'headRevision']) {
        optionalStringAt(target, key, pointer, { nonempty: false });
    }
    const snapshotDigest = optionalStringAt(target, 'snapshotDigest', pointer);
    if (snapshotDigest !== undefined &&
        !SNAPSHOT_RE.test(snapshotDigest)) {
        invalid(`${pointer}/snapshotDigest`, 'expected a Codex Security snapshot digest');
    }
    if (kind === 'git_revision' &&
        (!Object.hasOwn(target, 'revision') ||
            typeof target.revision !== 'string' ||
            PYTHON_WHITESPACE_RE.test(target.revision))) {
        invalid(`${pointer}/revision`, 'git_revision requires a nonempty revision');
    }
    if (kind !== 'git_revision' &&
        snapshotDigest === undefined) {
        invalid(`${pointer}/snapshotDigest`, `${kind} requires a completed snapshot digest`);
    }
}
function validateScope(scope, pointer) {
    stringArrayAt(scope.includePaths, `${pointer}/includePaths`, {
        nonemptyItems: false,
    });
    stringArrayAt(scope.excludePaths, `${pointer}/excludePaths`, {
        nonemptyItems: false,
    });
    for (const key of [
        'summary',
        'runtimeStatus',
        'validationMode',
        'context',
    ]) {
        optionalStringAt(scope, key, pointer);
    }
    optionalStringArrayAt(scope, 'artifactsReviewed', pointer);
    optionalStringArrayAt(scope, 'limitations', pointer);
}
function validateThreatModel(model, pointer) {
    stringAt(model.summary, `${pointer}/summary`);
    for (const key of [
        'assets',
        'trustBoundaries',
        'attackerCapabilities',
        'securityObjectives',
        'assumptions',
    ]) {
        optionalStringArrayAt(model, key, pointer);
    }
}
function validateManifest(manifest) {
    if (manifest.documentType !== 'codex-security.scan-manifest') {
        invalid('/scan-manifest.json/documentType', 'expected codex-security.scan-manifest');
    }
    if (manifest.schemaVersion !== '1.0') {
        invalid('/scan-manifest.json/schemaVersion', 'expected schema version 1.0');
    }
    const scan = recordAt(manifest.scan, '/scan-manifest.json/scan');
    stringAt(scan.id, '/scan-manifest.json/scan/id');
    validateProducer(recordAt(scan.producer, '/scan-manifest.json/scan/producer'), '/scan-manifest.json/scan/producer');
    if (scan.status !== 'completed') {
        invalid('/scan-manifest.json/scan/status', 'expected completed');
    }
    requireTimestamp(scan.startedAt, '/scan-manifest.json/scan/startedAt');
    const completedAt = requireTimestamp(scan.completedAt, '/scan-manifest.json/scan/completedAt');
    const sealedAt = requireTimestamp(scan.sealedAt, '/scan-manifest.json/scan/sealedAt');
    if (sealedAt !== completedAt) {
        invalid('/scan-manifest.json/scan/sealedAt', 'sealedAt must be byte-for-byte equal to completedAt');
    }
    validateTarget(recordAt(scan.target, '/scan-manifest.json/scan/target'), '/scan-manifest.json/scan/target');
    validateScope(recordAt(scan.scope, '/scan-manifest.json/scan/scope'), '/scan-manifest.json/scan/scope');
    if (scan.threatModel !== undefined) {
        validateThreatModel(recordAt(scan.threatModel, '/scan-manifest.json/scan/threatModel'), '/scan-manifest.json/scan/threatModel');
    }
    if (scan.hardening !== undefined) {
        const hardening = recordAt(scan.hardening, '/scan-manifest.json/scan/hardening');
        if (hardening.portfolioPath !== 'hardening/hardening.md') {
            invalid('/scan-manifest.json/scan/hardening/portfolioPath', 'expected hardening/hardening.md');
        }
    }
    if (scan.coverageRef !== 'coverage.json') {
        invalid('/scan-manifest.json/scan/coverageRef', 'expected coverage.json');
    }
    if (scan.findingsRef !== 'findings.json') {
        invalid('/scan-manifest.json/scan/findingsRef', 'expected findings.json');
    }
    const rows = arrayAt(scan.artifacts, '/scan-manifest.json/scan/artifacts');
    if (rows.length === 0 || rows.length > MAX_ARTIFACTS) {
        invalid('/scan-manifest.json/scan/artifacts', `expected 1 through ${MAX_ARTIFACTS} artifacts`);
    }
    const seen = new Set();
    const artifacts = rows.map((row, index) => {
        const pointer = `/scan-manifest.json/scan/artifacts/${index}`;
        const artifact = recordAt(row, pointer);
        const artifactPath = safeBundlePath(artifact.path, `${pointer}/path`);
        if (artifactPath === 'scan-manifest.json') {
            invalid(`${pointer}/path`, 'the manifest cannot self-seal');
        }
        if (seen.has(artifactPath)) {
            invalid(`${pointer}/path`, 'duplicate artifact path');
        }
        seen.add(artifactPath);
        const digest = stringAt(artifact.sha256, `${pointer}/sha256`, { pattern: RAW_SHA256_RE });
        const mediaType = stringAt(artifact.mediaType, `${pointer}/mediaType`);
        return { path: artifactPath, sha256: digest, mediaType };
    });
    for (const required of ['findings.json', 'coverage.json']) {
        const artifact = artifacts.find(({ path: artifactPath }) => artifactPath === required);
        if (artifact === undefined) {
            invalid('/scan-manifest.json/scan/artifacts', `missing required artifact ${required}`);
        }
        if (artifact.mediaType !== 'application/json') {
            invalid('/scan-manifest.json/scan/artifacts', `${required} must use application/json`);
        }
    }
    return { scan, artifacts };
}
function validateLocation(location, pointer) {
    safeRepositoryPath(location.path, `${pointer}/path`);
    const startLine = positiveIntegerAt(location.startLine, `${pointer}/startLine`);
    if (location.endLine !== undefined) {
        const endLine = positiveIntegerAt(location.endLine, `${pointer}/endLine`);
        if (endLine < startLine) {
            invalid(`${pointer}/endLine`, 'must be greater than or equal to startLine');
        }
    }
    optionalStringAt(location, 'role', pointer);
}
function validateFindingShape(finding, pointer) {
    stringAt(finding.findingId, `${pointer}/findingId`, {
        pattern: SOURCE_FINDING_ID_RE,
    });
    stringAt(finding.occurrenceId, `${pointer}/occurrenceId`, {
        pattern: SOURCE_OCCURRENCE_ID_RE,
    });
    stringAt(finding.ruleId, `${pointer}/ruleId`, {
        pattern: SOURCE_SLUG_RE,
    });
    const identity = recordAt(finding.identity, `${pointer}/identity`);
    stringAt(identity.anchor, `${pointer}/identity/anchor`, {
        pattern: SOURCE_SLUG_RE,
    });
    optionalStringAt(identity, 'instance', `${pointer}/identity`, {
        pattern: SOURCE_SLUG_RE,
    });
    const fingerprints = recordAt(finding.fingerprints, `${pointer}/fingerprints`);
    if (fingerprints.algorithm !== 'codex-security/v1') {
        invalid(`${pointer}/fingerprints/algorithm`, 'unsupported fingerprint algorithm');
    }
    stringAt(fingerprints.primary, `${pointer}/fingerprints/primary`, {
        pattern: SOURCE_FINGERPRINT_RE,
    });
    stringAt(finding.title, `${pointer}/title`);
    stringAt(finding.summary, `${pointer}/summary`);
    const severity = recordAt(finding.severity, `${pointer}/severity`);
    enumAt(severity.level, ['critical', 'high', 'medium', 'low', 'informational'], `${pointer}/severity/level`);
    if (severity.score !== undefined) {
        const score = numberAt(severity.score, `${pointer}/severity/score`);
        if (score < 0 || score > 10) {
            invalid(`${pointer}/severity/score`, 'expected a score from 0 through 10');
        }
    }
    for (const key of [
        'scoringSystem',
        'vector',
        'rationale',
        'changeConditions',
    ]) {
        optionalStringAt(severity, key, `${pointer}/severity`);
    }
    const confidence = recordAt(finding.confidence, `${pointer}/confidence`);
    enumAt(confidence.level, ['high', 'medium', 'low'], `${pointer}/confidence/level`);
    stringAt(confidence.rationale, `${pointer}/confidence/rationale`);
    const taxonomy = recordAt(finding.taxonomy, `${pointer}/taxonomy`);
    stringAt(taxonomy.category, `${pointer}/taxonomy/category`);
    stringArrayAt(taxonomy.cwe, `${pointer}/taxonomy/cwe`, {
        nonemptyItems: true,
    });
    const locations = arrayAt(finding.locations, `${pointer}/locations`);
    if (locations.length === 0)
        invalid(`${pointer}/locations`, 'requires a location');
    for (const [index, row] of locations.entries()) {
        validateLocation(recordAt(row, `${pointer}/locations/${index}`), `${pointer}/locations/${index}`);
    }
    if (finding.writeup !== undefined) {
        const writeup = recordAt(finding.writeup, `${pointer}/writeup`);
        stringAt(writeup.reportPath, `${pointer}/writeup/reportPath`, {
            pattern: WRITEUP_RE,
        });
    }
    const evidenceIds = new Set();
    if (finding.codeEvidence !== undefined) {
        const evidenceRows = arrayAt(finding.codeEvidence, `${pointer}/codeEvidence`);
        if (evidenceRows.length > MAX_CODE_EVIDENCE) {
            invalid(`${pointer}/codeEvidence`, `exceeds ${MAX_CODE_EVIDENCE} snippets`);
        }
        for (const [index, row] of evidenceRows.entries()) {
            const evidencePointer = `${pointer}/codeEvidence/${index}`;
            const evidence = recordAt(row, evidencePointer);
            const id = stringAt(evidence.id, `${evidencePointer}/id`, {
                pattern: SOURCE_SLUG_RE,
            });
            if (evidenceIds.has(id)) {
                invalid(`${evidencePointer}/id`, 'duplicate code-evidence ID');
            }
            evidenceIds.add(id);
            stringAt(evidence.label, `${evidencePointer}/label`);
            validateLocation(evidence, evidencePointer);
            optionalStringAt(evidence, 'language', evidencePointer);
            stringAt(evidence.code, `${evidencePointer}/code`);
            stringAt(evidence.explanation, `${evidencePointer}/explanation`);
        }
    }
    if (finding.rootCause !== undefined) {
        if (typeof finding.rootCause === 'string') {
            stringAt(finding.rootCause, `${pointer}/rootCause`);
        }
        else {
            const rootCause = recordAt(finding.rootCause, `${pointer}/rootCause`);
            stringAt(rootCause.summary, `${pointer}/rootCause/summary`);
            optionalStringArrayAt(rootCause, 'evidenceRefs', `${pointer}/rootCause`);
            optionalStringAt(rootCause, 'code', `${pointer}/rootCause`);
            optionalStringAt(rootCause, 'language', `${pointer}/rootCause`);
        }
    }
    stringAt(finding.remediation, `${pointer}/remediation`);
    for (const key of ['validation', 'attackPath']) {
        if (finding[key] !== undefined &&
            finding[key] !== null) {
            recordAt(finding[key], `${pointer}/${key}`);
        }
    }
    for (const key of ['remediationTests', 'preventiveControls']) {
        if (finding[key] !== undefined) {
            stringArrayAt(finding[key], `${pointer}/${key}`, {
                nonemptyItems: true,
            });
        }
    }
    const provenance = recordAt(finding.provenance, `${pointer}/provenance`);
    stringAt(provenance.source, `${pointer}/provenance/source`);
    if (finding.extensions !== undefined) {
        recordAt(finding.extensions, `${pointer}/extensions`);
    }
    for (const sectionName of ['rootCause']) {
        const section = finding[sectionName];
        if (section === null ||
            typeof section !== 'object' ||
            Array.isArray(section)) {
            continue;
        }
        const refs = section.evidenceRefs;
        if (refs === undefined)
            continue;
        const values = stringArrayAt(refs, `${pointer}/${sectionName}/evidenceRefs`, { nonemptyItems: true });
        for (const ref of values) {
            if (!evidenceIds.has(ref)) {
                invalid(`${pointer}/${sectionName}/evidenceRefs`, `unknown code-evidence ID ${ref}`);
            }
        }
    }
}
function sourceFingerprint(targetId, ruleId, anchor, instance) {
    return `codex-security/v1:sha256:${sha256([
        'codex-security/v1',
        targetId,
        ruleId,
        anchor,
        instance ?? '',
    ].join('\0'))}`;
}
function validateFindings(findings, scanId, targetId) {
    if (findings.documentType !== 'codex-security.findings') {
        invalid('/findings.json/documentType', 'expected codex-security.findings');
    }
    if (findings.schemaVersion !== '1.0') {
        invalid('/findings.json/schemaVersion', 'expected schema version 1.0');
    }
    if (findings.scanId !== scanId) {
        invalid('/findings.json/scanId', 'canonical contract scan IDs do not match');
    }
    const rows = arrayAt(findings.findings, '/findings.json/findings');
    if (rows.length > MAX_FINDINGS) {
        invalid('/findings.json/findings', `exceeds ${MAX_FINDINGS} findings`);
    }
    const findingIds = new Set();
    const occurrenceIds = new Set();
    const logicalFindings = new Set();
    const writeups = new Set();
    for (const [index, row] of rows.entries()) {
        const pointer = `/findings.json/findings/${index}`;
        const finding = recordAt(row, pointer);
        validateFindingShape(finding, pointer);
        const identity = recordAt(finding.identity, `${pointer}/identity`);
        const fingerprint = sourceFingerprint(targetId, finding.ruleId, identity.anchor, identity.instance);
        const findingId = `csf_${sha256(fingerprint).slice(0, 24)}`;
        const occurrenceId = `occ_${sha256(`${scanId}\0${fingerprint}`).slice(0, 24)}`;
        const fingerprints = recordAt(finding.fingerprints, `${pointer}/fingerprints`);
        if (fingerprints.primary !== fingerprint) {
            invalid(`${pointer}/fingerprints/primary`, 'does not match derived fingerprint identity');
        }
        if (finding.findingId !== findingId) {
            invalid(`${pointer}/findingId`, 'does not match derived fingerprint identity');
        }
        if (finding.occurrenceId !== occurrenceId) {
            invalid(`${pointer}/occurrenceId`, 'does not match scan occurrence identity');
        }
        if (findingIds.has(findingId) ||
            occurrenceIds.has(occurrenceId) ||
            logicalFindings.has(fingerprint)) {
            invalid(pointer, 'duplicate or colliding logical finding');
        }
        findingIds.add(findingId);
        occurrenceIds.add(occurrenceId);
        logicalFindings.add(fingerprint);
        if (finding.writeup !== undefined) {
            const reportPath = recordAt(finding.writeup, `${pointer}/writeup`).reportPath;
            if (writeups.has(reportPath)) {
                invalid(`${pointer}/writeup/reportPath`, 'duplicate finding writeup path');
            }
            writeups.add(reportPath);
        }
    }
}
function validateCoverage(coverage, scanId, scope, manifestArtifacts) {
    if (coverage.documentType !== 'codex-security.coverage') {
        invalid('/coverage.json/documentType', 'expected codex-security.coverage');
    }
    if (coverage.schemaVersion !== '1.0') {
        invalid('/coverage.json/schemaVersion', 'expected schema version 1.0');
    }
    if (coverage.scanId !== scanId) {
        invalid('/coverage.json/scanId', 'canonical contract scan IDs do not match');
    }
    enumAt(coverage.mode, [
        'repository',
        'scoped_path',
        'diff',
        'commit',
        'branch_diff',
        'working_tree',
        'deep_repository',
    ], '/coverage.json/mode');
    const completeness = enumAt(coverage.completeness, ['complete', 'partial', 'unknown'], '/coverage.json/completeness');
    enumAt(coverage.inventoryStrategy, ['repository', 'scoped_path', 'diff', 'directory', 'custom'], '/coverage.json/inventoryStrategy');
    const includePaths = stringArrayAt(coverage.includePaths, '/coverage.json/includePaths', { nonemptyItems: false });
    const excludePaths = stringArrayAt(coverage.excludePaths, '/coverage.json/excludePaths', { nonemptyItems: false });
    if (!sameJson(includePaths, scope.includePaths) ||
        !sameJson(excludePaths, scope.excludePaths)) {
        invalid('/coverage.json', 'coverage paths do not match the manifest scope');
    }
    const surfaces = arrayAt(coverage.surfaces, '/coverage.json/surfaces');
    const surfaceIds = new Set();
    let needsFollowUp = false;
    for (const [index, row] of surfaces.entries()) {
        const pointer = `/coverage.json/surfaces/${index}`;
        const surface = recordAt(row, pointer);
        const id = stringAt(surface.id, `${pointer}/id`);
        if (surfaceIds.has(id))
            invalid(`${pointer}/id`, 'duplicate surface ID');
        surfaceIds.add(id);
        stringAt(surface.label, `${pointer}/label`);
        const disposition = enumAt(surface.disposition, [
            'reported',
            'no_issue_found',
            'rejected',
            'not_applicable',
            'needs_follow_up',
        ], `${pointer}/disposition`);
        needsFollowUp ||= disposition === 'needs_follow_up';
        const receipts = stringArrayAt(surface.receiptRefs, `${pointer}/receiptRefs`, { nonemptyItems: true });
        for (const [receiptIndex, receipt] of receipts.entries()) {
            const normalized = safeBundlePath(receipt, `${pointer}/receiptRefs/${receiptIndex}`);
            if (!normalized.startsWith('artifacts/') ||
                !manifestArtifacts.has(normalized)) {
                invalid(`${pointer}/receiptRefs/${receiptIndex}`, 'coverage receipt must be a sealed manifest artifact under artifacts/');
            }
        }
        optionalStringAt(surface, 'riskArea', pointer);
        optionalStringAt(surface, 'notes', pointer);
    }
    const exclusions = arrayAt(coverage.explicitExclusions, '/coverage.json/explicitExclusions');
    for (const [index, row] of exclusions.entries()) {
        const pointer = `/coverage.json/explicitExclusions/${index}`;
        const exclusion = recordAt(row, pointer);
        stringAt(exclusion.pattern, `${pointer}/pattern`);
        stringAt(exclusion.reason, `${pointer}/reason`);
    }
    const deferred = arrayAt(coverage.deferred, '/coverage.json/deferred');
    const deferredIds = new Set();
    for (const [index, row] of deferred.entries()) {
        const pointer = `/coverage.json/deferred/${index}`;
        const item = recordAt(row, pointer);
        const id = stringAt(item.id, `${pointer}/id`);
        if (deferredIds.has(id))
            invalid(`${pointer}/id`, 'duplicate deferred ID');
        deferredIds.add(id);
        stringAt(item.reason, `${pointer}/reason`);
        optionalStringArrayAt(item, 'paths', pointer);
        optionalStringArrayAt(item, 'surfaceIds', pointer);
    }
    if (coverage.openQuestions !== undefined) {
        const questions = arrayAt(coverage.openQuestions, '/coverage.json/openQuestions');
        for (const [index, row] of questions.entries()) {
            const pointer = `/coverage.json/openQuestions/${index}`;
            const question = recordAt(row, pointer);
            stringAt(question.question, `${pointer}/question`);
            optionalStringAt(question, 'followUpPrompt', pointer);
        }
    }
    if (completeness === 'complete' &&
        (needsFollowUp || deferred.length > 0)) {
        invalid('/coverage.json/completeness', 'complete coverage cannot contain deferred or needs_follow_up work');
    }
}
function discoverValidationArtifactRefs(finding) {
    if (finding.validation === undefined ||
        finding.validation === null) {
        return [];
    }
    const validation = recordAt(finding.validation, '/validation');
    const candidates = [
        validation.artifactRefs,
        validation.artifact_paths,
    ].filter((value) => value !== undefined);
    const refs = [];
    for (const value of candidates) {
        if (Array.isArray(value) &&
            value.every((row) => typeof row === 'string' && row.length > 0)) {
            refs.push(...value);
        }
    }
    return refs;
}
function readSealedBundle(bundleRoot) {
    return withAnchoredAuditSupportSnapshot(bundleRoot, () => {
        const files = new Map();
        let retainedBytes = 0;
        const remainingBundleBytes = () => Math.max(0, MAX_BUNDLE_BYTES - retainedBytes);
        const retainBundleBytes = (byteLength, repoPath) => {
            if (byteLength > remainingBundleBytes()) {
                invalid(`/bundle/${repoPath}`, `exceeds the aggregate ${MAX_BUNDLE_BYTES}-byte bundle budget`);
            }
            retainedBytes += byteLength;
        };
        const readJsonDocument = (repoPath) => {
            let document;
            try {
                document = readBoundedAuditJsonDocument(bundleRoot, repoPath, remainingBundleBytes());
            }
            catch (error) {
                throw new Error(`Codex Security bundle ${repoPath} is missing, unsafe, invalid, or exceeds the aggregate ${MAX_BUNDLE_BYTES}-byte bundle budget: ${error instanceof Error ? error.message : String(error)}`);
            }
            const bytes = Buffer.from(document.bytes);
            retainBundleBytes(bytes.byteLength, repoPath);
            files.set(repoPath, {
                path: repoPath,
                bytes,
                sha256: sha256(bytes),
            });
            return {
                bytes,
                value: recordAt(document.value, `/${repoPath}`),
            };
        };
        const readFile = (repoPath) => {
            const normalized = safeBundlePath(repoPath, `/bundle/${repoPath}`);
            const cached = files.get(normalized);
            if (cached !== undefined)
                return cached;
            let bytes;
            try {
                bytes = Buffer.from(readBoundedAuditBytes(bundleRoot, normalized, remainingBundleBytes()));
            }
            catch (error) {
                throw new Error(`Codex Security bundle member ${normalized} is missing, unsafe, or exceeds the aggregate ${MAX_BUNDLE_BYTES}-byte bundle budget: ${error instanceof Error ? error.message : String(error)}`);
            }
            retainBundleBytes(bytes.byteLength, normalized);
            const file = {
                path: normalized,
                bytes,
                sha256: sha256(bytes),
            };
            files.set(normalized, file);
            return file;
        };
        const manifestDocument = readJsonDocument('scan-manifest.json');
        const findingsDocument = readJsonDocument('findings.json');
        const coverageDocument = readJsonDocument('coverage.json');
        const manifestValidation = validateManifest(manifestDocument.value);
        const scan = manifestValidation.scan;
        const target = recordAt(scan.target, '/scan-manifest.json/scan/target');
        const scope = recordAt(scan.scope, '/scan-manifest.json/scan/scope');
        const manifestArtifacts = new Map(manifestValidation.artifacts.map((artifact) => [
            artifact.path,
            artifact,
        ]));
        validateFindings(findingsDocument.value, scan.id, target.targetId);
        validateCoverage(coverageDocument.value, scan.id, scope, manifestArtifacts);
        for (const artifact of manifestArtifacts.values()) {
            const file = readFile(artifact.path);
            if (file.sha256 !== artifact.sha256) {
                invalid(`/scan-manifest.json/scan/artifacts/${artifact.path}`, 'sealed artifact digest mismatch or changed content');
            }
        }
        const findingRows = arrayAt(findingsDocument.value.findings, '/findings.json/findings');
        for (const [index, row] of findingRows.entries()) {
            const finding = recordAt(row, `/findings.json/findings/${index}`);
            if (finding.writeup !== undefined) {
                const reportPath = recordAt(finding.writeup, `/findings.json/findings/${index}/writeup`).reportPath;
                readFile(reportPath);
            }
            for (const ref of discoverValidationArtifactRefs(finding)) {
                if (manifestArtifacts.has(ref))
                    readFile(ref);
            }
        }
        if (scan.hardening !== undefined) {
            const hardening = recordAt(scan.hardening, '/scan-manifest.json/scan/hardening');
            readFile(hardening.portfolioPath);
        }
        for (const [repoPath, sealed] of [...files.entries()].sort(([left], [right]) => utf16Compare(left, right))) {
            let current;
            try {
                current = Buffer.from(readBoundedAuditBytes(bundleRoot, repoPath, sealed.bytes.byteLength));
            }
            catch (error) {
                throw new Error(`Codex Security bundle member changed after validated read: ${repoPath}: ${error instanceof Error ? error.message : String(error)}`);
            }
            if (!current.equals(sealed.bytes)) {
                throw new Error(`Codex Security bundle member changed after validated read: ${repoPath}`);
            }
        }
        return {
            manifest: manifestDocument.value,
            findings: findingsDocument.value,
            coverage: coverageDocument.value,
            files,
            manifestArtifacts,
        };
    });
}
function extensionValue(value, pointer) {
    const canonical = canonicalJson(value);
    if (Buffer.byteLength(canonical, 'utf8') > 64 * 1024) {
        invalid(pointer, 'preserved extension exceeds 65536 canonical bytes');
    }
    return JSON.parse(canonical);
}
function appendExtension(rows, namespace, pointer, value) {
    const snapshot = extensionValue(value, pointer);
    rows.push({
        namespace,
        path: pointer,
        value: snapshot,
        digest: computeAuditCanonicalDigest(snapshot),
    });
}
function normalizeStringSet(source, namespace, pointer, extensions, preserveSource = true) {
    const normalized = [...new Set(source)].sort(utf16Compare);
    if (preserveSource &&
        (normalized.length !== source.length ||
            source.some((row, index) => row !== normalized[index]))) {
        appendExtension(extensions, namespace, pointer, source);
    }
    return normalized;
}
function preserveUnknown(source, known, namespace, pointer, rows) {
    for (const key of Object.keys(source).sort(utf16Compare)) {
        if (known.has(key))
            continue;
        appendExtension(rows, namespace, childPointer(pointer, key), source[key]);
    }
}
function sortExtensions(rows) {
    return rows.sort((left, right) => utf16Compare(`${left.namespace}\0${left.path}`, `${right.namespace}\0${right.path}`));
}
class SourceArtifactBuilder {
    bundle;
    rows = new Map();
    constructor(bundle) {
        this.bundle = bundle;
        const manifest = bundle.files.get('scan-manifest.json');
        this.rows.set('scan-manifest.json', {
            path: 'scan-manifest.json',
            sha256: manifest.sha256,
            mediaType: 'application/json',
            integrityKind: 'adapter-bundle',
            referencedBy: new Set(),
            retainedInAtlas: false,
        });
        for (const artifact of bundle.manifestArtifacts.values()) {
            const file = bundle.files.get(artifact.path);
            if (file === undefined) {
                invalid(`/sourceArtifacts/${artifact.path}`, 'sealed artifact was not read');
            }
            this.rows.set(artifact.path, {
                path: artifact.path,
                sha256: file.sha256,
                mediaType: artifact.mediaType,
                integrityKind: 'producer-manifest',
                integrityIndex: 'scan-manifest.json',
                referencedBy: new Set(),
                retainedInAtlas: false,
            });
        }
    }
    isManifestListed(repoPath) {
        return this.bundle.manifestArtifacts.has(repoPath);
    }
    reference(repoPath, jsonPointer, fallbackMediaType) {
        const file = this.bundle.files.get(repoPath);
        if (file === undefined) {
            invalid(jsonPointer, `referenced bundle member was not safely read: ${repoPath}`);
        }
        let row = this.rows.get(repoPath);
        if (row === undefined) {
            if (fallbackMediaType === undefined) {
                invalid(jsonPointer, `unsealed external reference has no source media type: ${repoPath}`);
            }
            row = {
                path: repoPath,
                sha256: file.sha256,
                mediaType: fallbackMediaType,
                integrityKind: 'adapter-bundle',
                referencedBy: new Set(),
                retainedInAtlas: false,
            };
            this.rows.set(repoPath, row);
        }
        row.referencedBy.add(jsonPointer);
        return row;
    }
    finish() {
        return [...this.rows.values()]
            .sort((left, right) => utf16Compare(left.path, right.path))
            .map((row) => ({
            path: row.path,
            sha256: row.sha256,
            mediaType: row.mediaType,
            integrityKind: row.integrityKind,
            ...(row.integrityIndex === undefined
                ? {}
                : { integrityIndex: row.integrityIndex }),
            referencedBy: [...row.referencedBy].sort(utf16Compare),
            retainedInAtlas: false,
        }));
    }
}
function copyOptionalStrings(source, keys) {
    const result = {};
    for (const key of keys) {
        if (source[key] !== undefined)
            result[key] = source[key];
    }
    return result;
}
function mapTarget(target, repositoryId) {
    const sourceKind = target.kind;
    const kind = {
        git_revision: 'git-revision',
        git_worktree: 'git-worktree',
        git_diff: 'git-diff',
        directory_snapshot: 'directory-snapshot',
    }[sourceKind];
    const sourceCoordinates = {
        ...(target.revision === undefined
            ? {}
            : { sourceRevision: target.revision }),
        ...(target.baseRevision === undefined
            ? {}
            : { sourceBaseRevision: target.baseRevision }),
        ...(target.headRevision === undefined
            ? {}
            : { sourceHeadRevision: target.headRevision }),
    };
    const common = {
        kind,
        sourceKind,
        repositoryId,
        targetId: target.targetId,
        displayName: target.displayName,
        ...(target.remote === undefined ? {} : { remote: target.remote }),
        ...sourceCoordinates,
    };
    if (target.snapshotDigest !== undefined) {
        const match = SNAPSHOT_RE.exec(target.snapshotDigest);
        if (match === null)
            invalid('/scan/target/snapshotDigest', 'invalid snapshot digest');
        return {
            ...common,
            identityDigest: match[1],
            identityBasis: 'snapshot',
            snapshotDigest: match[1],
            sourceSnapshotDigest: target.snapshotDigest,
        };
    }
    const identityMaterial = {
        namespace: 'repo-atlas/revision-coordinate/v1',
        sourceKind,
        targetId: target.targetId,
        ...sourceCoordinates,
    };
    return {
        ...common,
        identityDigest: computeAuditCanonicalDigest(identityMaterial),
        identityBasis: 'revision-coordinate',
    };
}
function stringValue(value) {
    return (typeof value === 'string' &&
        value.trim().length > 0 &&
        value.length <= TEXT_LIMIT &&
        !value.includes('\0'))
        ? value
        : undefined;
}
function jsonArrayValue(value) {
    return Array.isArray(value)
        ? value.map((row) => extensionValue(row, '/projection'))
        : undefined;
}
function validStringList(value) {
    return (Array.isArray(value) &&
        value.every((row) => typeof row === 'string' && row.length > 0))
        ? value
        : undefined;
}
function preserveUnprojectedKnown(source, key, projected, namespace, pointer, extensions) {
    if (Object.hasOwn(source, key) && !projected) {
        appendExtension(extensions, namespace, childPointer(pointer, key), source[key]);
    }
}
function resolveAliasedValue(source, keys, validator, namespace, pointer, extensions) {
    const accepted = keys
        .filter((key) => Object.hasOwn(source, key))
        .map((key) => ({ key, value: validator(source[key]) }))
        .filter((row) => row.value !== undefined);
    if (accepted.length > 1 &&
        accepted.some(({ value }) => !sameJson(value, accepted[0].value))) {
        invalid(pointer, `conflicting accepted spellings: ${keys.join(', ')}`);
    }
    for (const key of keys) {
        if (!Object.hasOwn(source, key))
            continue;
        const projected = accepted.some((row) => row.key === key);
        if (key !== keys[0] || !projected) {
            appendExtension(extensions, namespace, childPointer(pointer, key), source[key]);
        }
    }
    return accepted[0]?.value;
}
function mapValidation(value, findingIndex, evidenceIds, artifactBuilder, extensions) {
    if (value === undefined || value === null)
        return value;
    const pointer = `/findings/${findingIndex}/validation`;
    const source = recordAt(value, pointer);
    const result = {};
    for (const key of ['method', 'summary']) {
        const projected = stringValue(source[key]);
        if (projected !== undefined)
            result[key] = projected;
        preserveUnprojectedKnown(source, key, projected !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    }
    if (['reportable', 'suppressed', 'not_applicable', 'deferred']
        .includes(source.disposition)) {
        result.disposition = source.disposition;
    }
    else {
        preserveUnprojectedKnown(source, 'disposition', false, FINDINGS_NAMESPACE, pointer, extensions);
    }
    if (['high', 'medium', 'low'].includes(source.confidence)) {
        result.confidence = source.confidence;
    }
    else {
        preserveUnprojectedKnown(source, 'confidence', false, FINDINGS_NAMESPACE, pointer, extensions);
    }
    const confidenceRationale = resolveAliasedValue(source, ['confidenceRationale', 'confidence_rationale'], (candidate) => stringValue(candidate), FINDINGS_NAMESPACE, pointer, extensions);
    if (typeof confidenceRationale === 'string') {
        result.confidenceRationale = confidenceRationale;
    }
    const evidenceRefs = validStringList(source.evidenceRefs);
    const evidenceRefsProjected = evidenceRefs !== undefined &&
        evidenceRefs.every((evidenceId) => evidenceIds.has(evidenceId));
    if (evidenceRefsProjected) {
        result.evidenceRefs = normalizeStringSet(evidenceRefs, FINDINGS_NAMESPACE, `${pointer}/evidenceRefs`, extensions);
    }
    preserveUnprojectedKnown(source, 'evidenceRefs', evidenceRefsProjected, FINDINGS_NAMESPACE, pointer, extensions);
    for (const key of ['assertions', 'evidence', 'limitations']) {
        const projected = jsonArrayValue(source[key]);
        if (projected !== undefined)
            result[key] = projected;
        preserveUnprojectedKnown(source, key, projected !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    }
    const counterevidence = resolveAliasedValue(source, [
        'counterevidenceOrProofGap',
        'counterEvidence',
        'counterevidence_or_proof_gap',
    ], (candidate) => jsonArrayValue(candidate), FINDINGS_NAMESPACE, pointer, extensions);
    if (Array.isArray(counterevidence)) {
        result.counterevidenceOrProofGap = counterevidence;
    }
    const remaining = resolveAliasedValue(source, ['remainingUncertainty', 'remaining_uncertainty'], (candidate) => jsonArrayValue(candidate), FINDINGS_NAMESPACE, pointer, extensions);
    if (Array.isArray(remaining))
        result.remainingUncertainty = remaining;
    const artifactRefs = resolveAliasedValue(source, ['artifactRefs', 'artifact_paths'], (candidate) => {
        const values = validStringList(candidate);
        if (values === undefined ||
            values.some((repoPath) => !artifactBuilder.isManifestListed(repoPath))) {
            return undefined;
        }
        return normalizeStringSet(values, FINDINGS_NAMESPACE, `${pointer}/artifactRefs`, extensions, false);
    }, FINDINGS_NAMESPACE, pointer, extensions);
    if (Array.isArray(artifactRefs)) {
        result.artifactRefs = artifactRefs;
        const canonicalSource = validStringList(source.artifactRefs);
        if (canonicalSource !== undefined &&
            canonicalSource.every((repoPath) => artifactBuilder.isManifestListed(repoPath))) {
            normalizeStringSet(canonicalSource, FINDINGS_NAMESPACE, `${pointer}/artifactRefs`, extensions);
        }
        for (const [index, repoPath] of result.artifactRefs.entries()) {
            artifactBuilder.reference(repoPath, `/findings/${findingIndex}/validation/artifactRefs/${index}`);
        }
    }
    preserveUnknown(source, new Set([
        'method',
        'disposition',
        'summary',
        'confidence',
        'confidenceRationale',
        'confidence_rationale',
        'evidenceRefs',
        'assertions',
        'evidence',
        'counterevidenceOrProofGap',
        'counterEvidence',
        'counterevidence_or_proof_gap',
        'remainingUncertainty',
        'remaining_uncertainty',
        'limitations',
        'artifactRefs',
        'artifact_paths',
    ]), FINDINGS_NAMESPACE, pointer, extensions);
    return result;
}
function mapDataflow(value, pointer, evidenceIds, extensions) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        appendExtension(extensions, FINDINGS_NAMESPACE, pointer, value);
        return undefined;
    }
    const source = recordAt(value, pointer);
    const result = {};
    for (const key of ['summary', 'source', 'sink', 'outcome']) {
        const projected = stringValue(source[key]);
        if (projected !== undefined)
            result[key] = projected;
        preserveUnprojectedKnown(source, key, projected !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    }
    const transformations = jsonArrayValue(source.transformations);
    if (transformations !== undefined)
        result.transformations = transformations;
    preserveUnprojectedKnown(source, 'transformations', transformations !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    const evidenceRefs = validStringList(source.evidenceRefs);
    const evidenceRefsProjected = evidenceRefs !== undefined &&
        evidenceRefs.every((evidenceId) => evidenceIds.has(evidenceId));
    if (evidenceRefsProjected) {
        result.evidenceRefs = normalizeStringSet(evidenceRefs, FINDINGS_NAMESPACE, `${pointer}/evidenceRefs`, extensions);
    }
    preserveUnprojectedKnown(source, 'evidenceRefs', evidenceRefsProjected, FINDINGS_NAMESPACE, pointer, extensions);
    preserveUnknown(source, new Set([
        'summary',
        'source',
        'transformations',
        'sink',
        'outcome',
        'evidenceRefs',
    ]), FINDINGS_NAMESPACE, pointer, extensions);
    return result;
}
function mapReachability(value, pointer, extensions) {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        appendExtension(extensions, FINDINGS_NAMESPACE, pointer, value);
        return undefined;
    }
    const source = recordAt(value, pointer);
    const result = {};
    for (const key of [
        'summary',
        'attacker',
        'entrypoint',
        'outcome',
    ]) {
        const projected = stringValue(source[key]);
        if (projected !== undefined)
            result[key] = projected;
        preserveUnprojectedKnown(source, key, projected !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    }
    for (const key of ['accessRequirements', 'preconditions']) {
        const projected = jsonArrayValue(source[key]);
        if (projected !== undefined)
            result[key] = projected;
        preserveUnprojectedKnown(source, key, projected !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    }
    preserveUnknown(source, new Set([
        'summary',
        'attacker',
        'entrypoint',
        'accessRequirements',
        'preconditions',
        'outcome',
    ]), FINDINGS_NAMESPACE, pointer, extensions);
    return result;
}
function mapAttackPath(value, findingIndex, evidenceIds, extensions) {
    if (value === undefined || value === null)
        return value;
    const pointer = `/findings/${findingIndex}/attackPath`;
    const source = recordAt(value, pointer);
    const result = {};
    const summary = stringValue(source.summary);
    if (summary !== undefined)
        result.summary = summary;
    preserveUnprojectedKnown(source, 'summary', summary !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    if (source.dataflow !== undefined) {
        const dataflow = mapDataflow(source.dataflow, `${pointer}/dataflow`, evidenceIds, extensions);
        if (dataflow !== undefined)
            result.dataflow = dataflow;
    }
    if (source.reachability !== undefined) {
        const reachability = mapReachability(source.reachability, `${pointer}/reachability`, extensions);
        if (reachability !== undefined)
            result.reachability = reachability;
    }
    for (const [key, levels] of [
        [
            'impact',
            ['critical', 'high', 'medium', 'low', 'informational'],
        ],
        ['likelihood', ['high', 'medium', 'low']],
    ]) {
        const candidate = source[key];
        if (candidate !== undefined &&
            candidate !== null &&
            typeof candidate === 'object' &&
            !Array.isArray(candidate)) {
            const section = recordAt(candidate, `${pointer}/${key}`);
            if (levels.includes(section.level)) {
                result[key] = {
                    level: section.level,
                    ...(stringValue(section.why) === undefined
                        ? {}
                        : { why: section.why }),
                };
                preserveUnprojectedKnown(section, 'why', section.why === undefined || stringValue(section.why) !== undefined, FINDINGS_NAMESPACE, `${pointer}/${key}`, extensions);
                preserveUnknown(section, new Set(['level', 'why']), FINDINGS_NAMESPACE, `${pointer}/${key}`, extensions);
            }
            else {
                appendExtension(extensions, FINDINGS_NAMESPACE, `${pointer}/${key}`, candidate);
            }
        }
        else if (candidate !== undefined) {
            appendExtension(extensions, FINDINGS_NAMESPACE, `${pointer}/${key}`, candidate);
        }
    }
    const evidenceRefs = validStringList(source.evidenceRefs);
    const evidenceRefsProjected = evidenceRefs !== undefined &&
        evidenceRefs.every((evidenceId) => evidenceIds.has(evidenceId));
    if (evidenceRefsProjected) {
        result.evidenceRefs = normalizeStringSet(evidenceRefs, FINDINGS_NAMESPACE, `${pointer}/evidenceRefs`, extensions);
    }
    preserveUnprojectedKnown(source, 'evidenceRefs', evidenceRefsProjected, FINDINGS_NAMESPACE, pointer, extensions);
    const limitations = jsonArrayValue(source.limitations);
    if (limitations !== undefined)
        result.limitations = limitations;
    preserveUnprojectedKnown(source, 'limitations', limitations !== undefined, FINDINGS_NAMESPACE, pointer, extensions);
    preserveUnknown(source, new Set([
        'summary',
        'dataflow',
        'reachability',
        'impact',
        'likelihood',
        'evidenceRefs',
        'limitations',
    ]), FINDINGS_NAMESPACE, pointer, extensions);
    return result;
}
function mapRootCause(value, findingIndex, extensions) {
    if (value === undefined || typeof value === 'string')
        return value;
    const pointer = `/findings/${findingIndex}/rootCause`;
    const source = recordAt(value, pointer);
    const rootCause = {
        summary: source.summary,
    };
    const evidenceRefs = validStringList(source.evidenceRefs);
    if (evidenceRefs !== undefined) {
        rootCause.evidenceRefs = normalizeStringSet(evidenceRefs, FINDINGS_NAMESPACE, `${pointer}/evidenceRefs`, extensions);
    }
    if (source.code !== undefined) {
        rootCause.legacyCode = {
            code: source.code,
            ...(source.language === undefined
                ? {}
                : { language: source.language }),
        };
        appendExtension(extensions, FINDINGS_NAMESPACE, `${pointer}/code`, source.code);
        if (source.language !== undefined) {
            appendExtension(extensions, FINDINGS_NAMESPACE, `${pointer}/language`, source.language);
        }
    }
    else if (source.language !== undefined) {
        appendExtension(extensions, FINDINGS_NAMESPACE, `${pointer}/language`, source.language);
    }
    preserveUnknown(source, new Set(['summary', 'evidenceRefs', 'code', 'language']), FINDINGS_NAMESPACE, pointer, extensions);
    return rootCause;
}
function mapFinding(source, index, observationId, repositoryId, targetId, unitSlug, findingsDigest, artifactBuilder) {
    const sourcePointer = `/findings/${index}`;
    const extensions = [];
    const identity = recordAt(source.identity, `${sourcePointer}/identity`);
    const taxonomySource = recordAt(source.taxonomy, `${sourcePointer}/taxonomy`);
    const taxonomyCwe = normalizeStringSet(taxonomySource.cwe, FINDINGS_NAMESPACE, `${sourcePointer}/taxonomy/cwe`, extensions);
    const atlasFingerprint = computeAtlasFingerprint({
        repositoryId,
        domain: 'security',
        ruleId: source.ruleId,
        anchor: identity.anchor,
        ...(identity.instance === undefined
            ? {}
            : { instance: identity.instance }),
    });
    const locations = source.locations.map((row) => {
        const location = row;
        return {
            path: location.path,
            startLine: location.startLine,
            ...(location.endLine === undefined
                ? {}
                : { endLine: location.endLine }),
            ...(location.role === undefined
                ? {}
                : { role: location.role }),
        };
    });
    const evidenceIds = new Set(source.codeEvidence?.map((row) => row.id) ?? []);
    const codeEvidence = source.codeEvidence === undefined
        ? undefined
        : source.codeEvidence.map((row, evidenceIndex) => {
            const evidence = row;
            preserveUnknown(evidence, new Set([
                'id',
                'label',
                'path',
                'startLine',
                'endLine',
                'language',
                'role',
                'code',
                'explanation',
            ]), FINDINGS_NAMESPACE, `${sourcePointer}/codeEvidence/${evidenceIndex}`, extensions);
            const sealPointer = `/findings/${index}/codeEvidence/${evidenceIndex}/sourceSeal/artifactPath`;
            artifactBuilder.reference('findings.json', sealPointer, 'application/json');
            return {
                evidenceBasis: 'sealed-producer-snippet',
                id: evidence.id,
                label: evidence.label,
                path: evidence.path,
                startLine: evidence.startLine,
                ...(evidence.endLine === undefined
                    ? {}
                    : { endLine: evidence.endLine }),
                ...(evidence.language === undefined
                    ? {}
                    : { language: evidence.language }),
                ...(evidence.role === undefined
                    ? {}
                    : { role: evidence.role }),
                code: evidence.code,
                explanation: evidence.explanation,
                sourceSeal: {
                    artifactPath: 'findings.json',
                    artifactSha256: findingsDigest,
                    jsonPointer: `/findings/${index}/codeEvidence/${evidenceIndex}`,
                },
            };
        });
    const rootCause = mapRootCause(source.rootCause, index, extensions);
    const validation = mapValidation(source.validation, index, evidenceIds, artifactBuilder, extensions);
    const attackPath = mapAttackPath(source.attackPath, index, evidenceIds, extensions);
    const provenanceSource = recordAt(source.provenance, `${sourcePointer}/provenance`);
    const sourceExtensions = source.extensions === undefined
        ? undefined
        : recordAt(source.extensions, `${sourcePointer}/extensions`);
    const provenance = {
        source: 'codex-security',
        producerSource: provenanceSource.source,
        sourceFindingId: source.findingId,
        sourceOccurrenceId: source.occurrenceId,
        ...(sourceExtensions?.candidateId === undefined
            ? {}
            : { candidateId: sourceExtensions.candidateId }),
        ...(sourceExtensions?.ledgerRowId === undefined
            ? {}
            : { ledgerRowId: sourceExtensions.ledgerRowId }),
        ...(sourceExtensions?.reportId === undefined
            ? {}
            : { reportId: sourceExtensions.reportId }),
    };
    preserveUnknown(provenanceSource, new Set(['source']), FINDINGS_NAMESPACE, `${sourcePointer}/provenance`, extensions);
    if (sourceExtensions !== undefined) {
        preserveUnknown(sourceExtensions, new Set(['candidateId', 'ledgerRowId', 'reportId']), FINDINGS_NAMESPACE, `${sourcePointer}/extensions`, extensions);
    }
    const artifactRefs = [];
    const artifactRefPaths = new Set();
    const addArtifactRef = (artifactPath, fallbackMediaType) => {
        if (artifactRefPaths.has(artifactPath))
            return;
        const artifactIndex = artifactRefs.length;
        const artifact = artifactBuilder.reference(artifactPath, `/findings/${index}/artifactRefs/${artifactIndex}/sourceArtifactPath`, fallbackMediaType);
        artifactRefPaths.add(artifactPath);
        artifactRefs.push({
            kind: 'external',
            sourceArtifactPath: artifactPath,
            integrityKind: artifact.integrityKind,
            sha256: artifact.sha256,
            mediaType: artifact.mediaType,
            retainedInAtlas: false,
        });
    };
    if (source.writeup !== undefined) {
        const writeup = recordAt(source.writeup, `${sourcePointer}/writeup`);
        const reportPath = writeup.reportPath;
        addArtifactRef(reportPath, 'text/markdown');
        preserveUnknown(writeup, new Set(['reportPath']), FINDINGS_NAMESPACE, `${sourcePointer}/writeup`, extensions);
    }
    if (validation?.artifactRefs !== undefined) {
        for (const artifactPath of validation.artifactRefs) {
            addArtifactRef(artifactPath);
        }
    }
    preserveUnknown(identity, new Set(['anchor', 'instance']), FINDINGS_NAMESPACE, `${sourcePointer}/identity`, extensions);
    preserveUnknown(recordAt(source.fingerprints, `${sourcePointer}/fingerprints`), new Set(['algorithm', 'primary']), FINDINGS_NAMESPACE, `${sourcePointer}/fingerprints`, extensions);
    for (const [key, known] of [
        ['severity', new Set([
                'level',
                'score',
                'scoringSystem',
                'vector',
                'rationale',
                'changeConditions',
            ])],
        ['confidence', new Set(['level', 'rationale'])],
        ['taxonomy', new Set(['category', 'cwe'])],
    ]) {
        preserveUnknown(recordAt(source[key], `${sourcePointer}/${key}`), known, FINDINGS_NAMESPACE, `${sourcePointer}/${key}`, extensions);
    }
    for (const [locationIndex, row] of source.locations.entries()) {
        preserveUnknown(row, new Set(['path', 'startLine', 'endLine', 'role']), FINDINGS_NAMESPACE, `${sourcePointer}/locations/${locationIndex}`, extensions);
    }
    preserveUnknown(source, new Set([
        'findingId',
        'occurrenceId',
        'ruleId',
        'identity',
        'fingerprints',
        'title',
        'summary',
        'severity',
        'confidence',
        'taxonomy',
        'locations',
        'writeup',
        'codeEvidence',
        'rootCause',
        'remediation',
        'validation',
        'attackPath',
        'remediationTests',
        'preventiveControls',
        'provenance',
        'extensions',
    ]), FINDINGS_NAMESPACE, sourcePointer, extensions);
    return {
        findingId: computeAtlasFindingId(atlasFingerprint),
        occurrenceId: computeAtlasOccurrenceId(observationId, atlasFingerprint),
        decisionLedger: unitSlug,
        ruleId: source.ruleId,
        identity: {
            anchor: identity.anchor,
            ...(identity.instance === undefined
                ? {}
                : { instance: identity.instance }),
        },
        fingerprints: [
            {
                scheme: 'atlas/v1',
                value: atlasFingerprint,
                role: 'canonical',
            },
            {
                scheme: 'codex-security/v1',
                value: source.fingerprints.primary,
                role: 'producer',
            },
        ],
        title: source.title,
        summary: source.summary,
        severity: {
            level: source.severity.level,
            ...copyOptionalStrings(source.severity, ['scoringSystem', 'vector', 'rationale', 'changeConditions']),
            ...(source.severity.score === undefined
                ? {}
                : { score: source.severity.score }),
        },
        confidence: {
            level: source.confidence.level,
            rationale: source.confidence.rationale,
        },
        taxonomy: {
            category: taxonomySource.category,
            cwe: taxonomyCwe,
        },
        locations,
        ...(codeEvidence === undefined ? {} : { codeEvidence }),
        ...(rootCause === undefined ? {} : { rootCause }),
        remediation: source.remediation,
        ...(validation === undefined ? {} : { validation }),
        ...(attackPath === undefined ? {} : { attackPath }),
        ...(source.remediationTests === undefined
            ? {}
            : { remediationTests: source.remediationTests }),
        ...(source.preventiveControls === undefined
            ? {}
            : { preventiveControls: source.preventiveControls }),
        provenance,
        ...(artifactRefs.length === 0 ? {} : { artifactRefs }),
        ...(extensions.length === 0
            ? {}
            : { extensions: sortExtensions(extensions) }),
    };
}
function mapBundle(bundle, repositoryId, options) {
    const manifestExtensions = [];
    const findingRootExtensions = [];
    const coverageExtensions = [];
    const manifest = bundle.manifest;
    const scan = recordAt(manifest.scan, '/scan');
    const producer = recordAt(scan.producer, '/scan/producer');
    const targetSource = recordAt(scan.target, '/scan/target');
    const scopeSource = recordAt(scan.scope, '/scan/scope');
    const coverage = bundle.coverage;
    const artifactBuilder = new SourceArtifactBuilder(bundle);
    artifactBuilder.reference('scan-manifest.json', '/producer/sourceContract/manifestPath', 'application/json');
    artifactBuilder.reference('coverage.json', '/producer/sourceContract/coverageRef', 'application/json');
    artifactBuilder.reference('findings.json', '/producer/sourceContract/findingsRef', 'application/json');
    const producerIdentity = computeAuditCanonicalDigest({
        namespace: 'repo-atlas/codex-contract-identity/v1',
        documents: [...CONTRACT_DOCUMENTS],
        producer: {
            name: producer.name,
            version: producer.version,
        },
        adapter: {
            name: ADAPTER_NAME,
            version: ADAPTER_VERSION,
        },
    });
    const target = mapTarget(targetSource, repositoryId);
    normalizeStringSet(scopeSource.includePaths, MANIFEST_NAMESPACE, '/scan/scope/includePaths', manifestExtensions);
    normalizeStringSet(scopeSource.excludePaths, MANIFEST_NAMESPACE, '/scan/scope/excludePaths', manifestExtensions);
    const includePaths = normalizeStringSet(coverage.includePaths, COVERAGE_NAMESPACE, '/includePaths', coverageExtensions);
    const excludePaths = normalizeStringSet(coverage.excludePaths, COVERAGE_NAMESPACE, '/excludePaths', coverageExtensions);
    const sourceExplicitExclusions = coverage.explicitExclusions.map((row) => {
        const exclusion = row;
        return {
            pattern: exclusion.pattern,
            reason: exclusion.reason,
        };
    });
    const explicitExclusions = [
        ...new Map(sourceExplicitExclusions.map((row) => [
            `${row.pattern}\0${row.reason}`,
            row,
        ])).values(),
    ].sort((left, right) => utf16Compare(`${left.pattern}\0${left.reason}`, `${right.pattern}\0${right.reason}`));
    if (sourceExplicitExclusions.length !== explicitExclusions.length ||
        sourceExplicitExclusions.some((row, index) => row.pattern !== explicitExclusions[index]?.pattern ||
            row.reason !== explicitExclusions[index]?.reason)) {
        appendExtension(coverageExtensions, COVERAGE_NAMESPACE, '/explicitExclusions', coverage.explicitExclusions);
    }
    const scopeIdentity = computeSemanticScopeIdentityDigest({
        mode: coverage.mode,
        inventoryStrategy: coverage.inventoryStrategy,
        includePaths,
        excludePaths,
        explicitExclusions,
    });
    const observationId = computeAtlasObservationId({
        slug: options.unitSlug,
        adapter: ADAPTER_NAME,
        runId: scan.id,
        producerIdentityDigest: producerIdentity,
        targetId: target.targetId,
        targetIdentityDigest: target.identityDigest,
        scopeIdentityDigest: scopeIdentity,
    });
    const findingsDigest = bundle.files.get('findings.json').sha256;
    const findingRows = bundle.findings.findings;
    const findings = findingRows.map((row, index) => mapFinding(row, index, observationId, repositoryId, target.targetId, options.unitSlug, findingsDigest, artifactBuilder));
    const semanticSurfaces = coverage.surfaces.map((row, surfaceIndex) => {
        const source = row;
        const receiptRefs = normalizeStringSet(source.receiptRefs, COVERAGE_NAMESPACE, `/surfaces/${surfaceIndex}/receiptRefs`, coverageExtensions);
        for (const [receiptIndex, repoPath] of receiptRefs.entries()) {
            artifactBuilder.reference(repoPath, `/semanticCoverage/surfaces/${surfaceIndex}/receiptRefs/${receiptIndex}`);
        }
        preserveUnknown(source, new Set([
            'id',
            'label',
            'disposition',
            'receiptRefs',
            'riskArea',
            'notes',
        ]), COVERAGE_NAMESPACE, `/surfaces/${surfaceIndex}`, coverageExtensions);
        return {
            id: source.id,
            label: source.label,
            disposition: source.disposition,
            receiptRefs,
            ...(source.riskArea === undefined
                ? {}
                : { riskArea: source.riskArea }),
            ...(source.notes === undefined
                ? {}
                : { notes: source.notes }),
        };
    });
    const deferred = coverage.deferred.map((row, index) => {
        const source = row;
        preserveUnknown(source, new Set(['id', 'reason', 'paths', 'surfaceIds']), COVERAGE_NAMESPACE, `/deferred/${index}`, coverageExtensions);
        const paths = source.paths === undefined
            ? undefined
            : normalizeStringSet(source.paths, COVERAGE_NAMESPACE, `/deferred/${index}/paths`, coverageExtensions);
        const surfaceIds = source.surfaceIds === undefined
            ? undefined
            : normalizeStringSet(source.surfaceIds, COVERAGE_NAMESPACE, `/deferred/${index}/surfaceIds`, coverageExtensions);
        return {
            id: source.id,
            reason: source.reason,
            ...(paths === undefined ? {} : { paths }),
            ...(surfaceIds === undefined ? {} : { surfaceIds }),
        };
    });
    const openQuestions = coverage.openQuestions === undefined
        ? undefined
        : coverage.openQuestions.map((row, index) => {
            const source = row;
            preserveUnknown(source, new Set(['question', 'followUpPrompt']), COVERAGE_NAMESPACE, `/openQuestions/${index}`, coverageExtensions);
            return {
                question: source.question,
                ...(source.followUpPrompt === undefined
                    ? {}
                    : { followUpPrompt: source.followUpPrompt }),
            };
        });
    for (const [index, row] of coverage.explicitExclusions.entries()) {
        preserveUnknown(row, new Set(['pattern', 'reason']), COVERAGE_NAMESPACE, `/explicitExclusions/${index}`, coverageExtensions);
    }
    preserveUnknown(manifest, new Set(['documentType', 'schemaVersion', 'scan']), MANIFEST_NAMESPACE, '', manifestExtensions);
    preserveUnknown(scan, new Set([
        'id',
        'producer',
        'status',
        'startedAt',
        'completedAt',
        'sealedAt',
        'target',
        'scope',
        'threatModel',
        'hardening',
        'coverageRef',
        'findingsRef',
        'artifacts',
    ]), MANIFEST_NAMESPACE, '/scan', manifestExtensions);
    preserveUnknown(producer, new Set(['name', 'version']), MANIFEST_NAMESPACE, '/scan/producer', manifestExtensions);
    preserveUnknown(targetSource, new Set([
        'kind',
        'targetId',
        'displayName',
        'remote',
        'revision',
        'baseRevision',
        'headRevision',
        'snapshotDigest',
    ]), MANIFEST_NAMESPACE, '/scan/target', manifestExtensions);
    preserveUnknown(scopeSource, new Set([
        'includePaths',
        'excludePaths',
        'summary',
        'artifactsReviewed',
        'runtimeStatus',
        'validationMode',
        'context',
        'limitations',
    ]), MANIFEST_NAMESPACE, '/scan/scope', manifestExtensions);
    if (scan.threatModel !== undefined) {
        preserveUnknown(scan.threatModel, new Set([
            'summary',
            'assets',
            'trustBoundaries',
            'attackerCapabilities',
            'securityObjectives',
            'assumptions',
        ]), MANIFEST_NAMESPACE, '/scan/threatModel', manifestExtensions);
    }
    if (scan.hardening !== undefined) {
        preserveUnknown(scan.hardening, new Set(['portfolioPath']), MANIFEST_NAMESPACE, '/scan/hardening', manifestExtensions);
    }
    for (const [index, row] of scan.artifacts.entries()) {
        preserveUnknown(row, new Set(['path', 'sha256', 'mediaType']), MANIFEST_NAMESPACE, `/scan/artifacts/${index}`, manifestExtensions);
    }
    preserveUnknown(bundle.findings, new Set(['documentType', 'schemaVersion', 'scanId', 'findings']), FINDINGS_NAMESPACE, '', findingRootExtensions);
    preserveUnknown(coverage, new Set([
        'documentType',
        'schemaVersion',
        'scanId',
        'mode',
        'completeness',
        'inventoryStrategy',
        'includePaths',
        'excludePaths',
        'surfaces',
        'explicitExclusions',
        'deferred',
        'openQuestions',
    ]), COVERAGE_NAMESPACE, '', coverageExtensions);
    const hardening = scan.hardening === undefined
        ? undefined
        : (() => {
            const portfolioPath = scan.hardening
                .portfolioPath;
            const artifact = artifactBuilder.reference(portfolioPath, '/hardening/portfolio/sourceArtifactPath', 'text/markdown');
            return {
                portfolio: {
                    kind: 'external',
                    sourceArtifactPath: portfolioPath,
                    integrityKind: artifact.integrityKind,
                    sha256: artifact.sha256,
                    mediaType: artifact.mediaType,
                    retainedInAtlas: false,
                },
            };
        })();
    const threatModel = scan.threatModel === undefined
        ? undefined
        : (() => {
            const source = scan.threatModel;
            return {
                summary: source.summary,
                ...Object.fromEntries([
                    'assets',
                    'trustBoundaries',
                    'attackerCapabilities',
                    'securityObjectives',
                    'assumptions',
                ]
                    .filter((key) => source[key] !== undefined)
                    .map((key) => [
                    key,
                    normalizeStringSet(source[key], MANIFEST_NAMESPACE, `/scan/threatModel/${key}`, manifestExtensions),
                ])),
            };
        })();
    const artifactsReviewed = scopeSource.artifactsReviewed === undefined
        ? undefined
        : normalizeStringSet(scopeSource.artifactsReviewed, MANIFEST_NAMESPACE, '/scan/scope/artifactsReviewed', manifestExtensions);
    const limitations = scopeSource.limitations === undefined
        ? undefined
        : normalizeStringSet(scopeSource.limitations, MANIFEST_NAMESPACE, '/scan/scope/limitations', manifestExtensions);
    const producerExtensions = sortExtensions([
        ...manifestExtensions,
        ...findingRootExtensions,
        ...coverageExtensions,
    ]);
    const observation = {
        observationId,
        observedAt: new Date(scan.completedAt).toISOString(),
        reviewState: 'complete',
        producer: {
            kind: 'codex-security',
            name: producer.name,
            version: producer.version,
            adapter: ADAPTER_NAME,
            adapterVersion: ADAPTER_VERSION,
            runId: scan.id,
            identityDigest: producerIdentity,
            identityBasis: 'codex-contract',
            sourceContract: {
                namespace: CONTRACT_NAMESPACE,
                status: 'completed',
                startedAt: scan.startedAt,
                completedAt: scan.completedAt,
                sealedAt: scan.sealedAt,
                manifestPath: 'scan-manifest.json',
                coverageRef: 'coverage.json',
                findingsRef: 'findings.json',
            },
        },
        target,
        scope: {
            mode: coverage.mode,
            identityDigest: scopeIdentity,
            identityBasis: 'semantic-declaration',
            inventoryStrategy: coverage.inventoryStrategy,
            includePaths,
            excludePaths,
            explicitExclusions,
            ...(scopeSource.summary === undefined
                ? {}
                : { summary: scopeSource.summary }),
            ...(artifactsReviewed === undefined ? {} : { artifactsReviewed }),
            ...(scopeSource.runtimeStatus === undefined
                ? {}
                : { runtimeStatus: scopeSource.runtimeStatus }),
            ...(scopeSource.validationMode === undefined
                ? {}
                : { validationMode: scopeSource.validationMode }),
            ...(scopeSource.context === undefined
                ? {}
                : { context: scopeSource.context }),
            ...(limitations === undefined ? {} : { limitations }),
        },
        exactCoverage: {
            completeness: 'unknown',
            basis: 'unavailable',
            reason: UNAVAILABLE_EXACT_REASON,
        },
        semanticCoverage: {
            mode: coverage.mode,
            completeness: coverage.completeness,
            inventoryStrategy: coverage.inventoryStrategy,
            surfaces: semanticSurfaces,
            explicitExclusions,
            deferred,
            ...(openQuestions === undefined ? {} : { openQuestions }),
        },
        ...(threatModel === undefined ? {} : { threatModel }),
        ...(hardening === undefined ? {} : { hardening }),
        findings,
        evidenceRefs: [],
        sourceArtifacts: artifactBuilder.finish(),
        producerExtensions,
    };
    return observation;
}
function repositoryId(root) {
    const config = recordAt(readBoundedAuditJson(root, '.atlas/config.json', 1024 * 1024), '/config');
    const identity = stringAt(config.repositoryId, '/config/repositoryId');
    if (!REPOSITORY_ID_RE.test(identity)) {
        invalid('/config/repositoryId', 'expected a stable committed repo_ identity');
    }
    return identity;
}
export function importCodexSecurityBundle(root, unsafeOptions) {
    const options = snapshotImportOptions(unsafeOptions);
    const bundle = readSealedBundle(localBundleRoot(root, options.bundlePath));
    const prepared = withAnchoredAuditSupportSnapshot(root, () => {
        const observation = mapBundle(bundle, repositoryId(root), options);
        const publication = prepareAuditObservationPublication(root, observation, {
            slug: options.unitSlug,
            ...(options.unitTitle === undefined
                ? {}
                : { title: options.unitTitle }),
            ...(options.conceptSlug === undefined
                ? {}
                : { conceptSlug: options.conceptSlug }),
        });
        return { observation: publication.ledger.current, publication };
    });
    const published = options.apply
        ? publishAuditObservation(root, prepared.publication.ledger)
        : undefined;
    return {
        observation: prepared.observation,
        ledger: prepared.publication.ledger,
        historyEntry: prepared.publication.historyEntry,
        currentBytes: prepared.publication.currentBytes,
        applied: options.apply,
        ...(published === undefined
            ? {}
            : {
                publication: {
                    currentPath: published.currentPath,
                    historyPath: published.historyPath,
                    appendedObservationId: published.appendedObservationId,
                },
            }),
    };
}
