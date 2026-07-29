import { createHash } from 'node:crypto';
import { AUDIT_LIMITS, atomicWriteAuditFile, canonicalJson, listBoundedAuditDirectory, normalizeAuditRepoPath, parseBoundedAuditJsonBytes, readBoundedAuditBytes, stableAuditId, withAuditLock, } from './audit-core.js';
const SHA256_RE = /^sha256:[0-9a-f]{64}$/u;
const GIT_BLOB_RE = /^(?:git-sha1:[0-9a-f]{40}|git-sha256:[0-9a-f]{64})$/u;
const EVENT_ID_RE = /^adev_[0-9a-f]{24}$/u;
const COMPARISON_ID_RE = /^acmp_[0-9a-f]{24}$/u;
const FINDING_ID_RE = /^atf_[0-9a-f]{24}$/u;
const OCCURRENCE_ID_RE = /^atocc_[0-9a-f]{24}$/u;
const OBSERVATION_ID_RE = /^aobs_[0-9a-f]{24}$/u;
const SECURITY_SLUG_RE = /^security-[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;
const FULL_REVISION_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/u;
const IDENTITY_RE = /^[a-z0-9][a-z0-9._:@/+-]{0,127}$/u;
const SOURCE_NAME_RE = /^[a-z0-9][a-z0-9._/@+-]{0,127}$/u;
const ALIAS_SCHEME_RE = /^[a-z0-9][a-z0-9._/-]{0,127}$/u;
const JSON_POINTER_RE = /^(?:\/(?:[^~\u0000-\u001f\u007f]|~[01])*)+$/u;
const TEXT_LIMIT = 256 * 1024;
const COLLECTION_LIMIT = 10_000;
const LEDGER_ENTRY_LIMIT = COLLECTION_LIMIT;
const DECISION_LEDGER_BYTE_LIMIT = 32 * 1024 * 1024;
const DECISION_LEDGER_COUNT_LIMIT = 10_000;
const DECISION_PORTFOLIO_BYTE_LIMIT = 64 * 1024 * 1024;
const DECISION_INDEX_ITEM_LIMIT = 100_000;
const RECONCILIATION_EVENT_LIMIT = 10_000;
const ACTIVE_CONFIRMED_EDGE_LIMIT = 10_000;
class DecisionValidationFailure extends Error {
    code;
    pointer;
    constructor(code, pointer, message) {
        super(message);
        this.code = code;
        this.pointer = pointer;
    }
}
function invalid(code, pointer, message) {
    throw new DecisionValidationFailure(code, pointer, message);
}
function diagnostic(error) {
    if (error instanceof DecisionValidationFailure) {
        return { code: error.code, path: error.pointer, message: error.message };
    }
    return {
        code: 'invalid-decision-ledger',
        path: '',
        message: error instanceof Error ? error.message : String(error),
    };
}
function utf16Compare(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function sha256Canonical(value) {
    return `sha256:${createHash('sha256')
        .update(canonicalJson(value), 'utf8')
        .digest('hex')}`;
}
function dataRecordAt(value, pointer) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        invalid('invalid-type', pointer, 'must be a data-only JSON object');
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
        invalid('invalid-object', pointer, 'must be a data-only JSON object');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(value).some((key) => typeof key !== 'string')) {
        invalid('invalid-object', pointer, 'symbol members are forbidden');
    }
    const snapshot = {};
    for (const [key, descriptor] of Object.entries(descriptors)) {
        if (!descriptor.enumerable ||
            !('value' in descriptor) ||
            /[\u0000-\u001f\u007f]/u.test(key) ||
            key === '__proto__' ||
            key === 'constructor' ||
            key === 'prototype') {
            invalid('invalid-object', `${pointer}/${escapePointer(key)}`, 'members must be safe enumerable data properties');
        }
        Object.defineProperty(snapshot, key, {
            value: descriptor.value,
            enumerable: true,
            writable: true,
            configurable: true,
        });
    }
    return snapshot;
}
function dataArrayAt(value, pointer, limit = COLLECTION_LIMIT) {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
        invalid('invalid-type', pointer, 'must be a dense data-only JSON array');
    }
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length');
    if (!lengthDescriptor ||
        !('value' in lengthDescriptor) ||
        !Number.isSafeInteger(lengthDescriptor.value) ||
        lengthDescriptor.value < 0 ||
        lengthDescriptor.value > limit) {
        invalid('invalid-array', pointer, `has an invalid length or exceeds the ${limit}-item limit`);
    }
    const length = lengthDescriptor.value;
    const keys = Reflect.ownKeys(value);
    if (keys.length !== length + 1 ||
        keys.some((key) => {
            if (key === 'length')
                return false;
            if (typeof key !== 'string' || !/^(?:0|[1-9][0-9]*)$/u.test(key)) {
                return true;
            }
            const index = Number(key);
            return !Number.isSafeInteger(index) || index < 0 || index >= length;
        })) {
        invalid('invalid-array', pointer, 'must be dense without extra members');
    }
    const rows = [];
    for (let index = 0; index < length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor?.enumerable || !('value' in descriptor)) {
            invalid('invalid-array', `${pointer}/${index}`, 'accessors and holes are forbidden');
        }
        rows.push(descriptor.value);
    }
    return rows;
}
function escapePointer(value) {
    return value.replace(/~/gu, '~0').replace(/\//gu, '~1');
}
function exactKeys(value, required, optional, pointer) {
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            invalid('unknown-member', `${pointer}/${escapePointer(key)}`, 'unknown member');
        }
    }
    for (const key of required) {
        if (!Object.hasOwn(value, key)) {
            invalid('missing-member', `${pointer}/${escapePointer(key)}`, 'required member is missing');
        }
    }
}
function boundedTextAt(value, pointer) {
    if (typeof value !== 'string' ||
        value.length > TEXT_LIMIT ||
        value.includes('\0')) {
        invalid('invalid-string', pointer, 'must be a bounded string without NUL');
    }
    return value;
}
function textAt(value, pointer) {
    const text = boundedTextAt(value, pointer);
    if (text.trim().length === 0) {
        invalid('invalid-string', pointer, 'must be nonempty text');
    }
    return text;
}
function enumAt(value, allowed, pointer) {
    if (typeof value !== 'string' || !allowed.includes(value)) {
        invalid('invalid-enum', pointer, `must be one of ${allowed.join(', ')}`);
    }
    return value;
}
function booleanAt(value, pointer) {
    if (typeof value !== 'boolean') {
        invalid('invalid-type', pointer, 'must be a boolean');
    }
    return value;
}
function safeIntegerAt(value, pointer, minimum = 0) {
    if (!Number.isSafeInteger(value) || value < minimum) {
        invalid('invalid-integer', pointer, `must be a safe integer >= ${minimum}`);
    }
    return value;
}
function patternAt(value, pattern, pointer, description) {
    const text = textAt(value, pointer);
    if (!pattern.test(text))
        invalid('invalid-identity', pointer, description);
    return text;
}
function sha256At(value, pointer) {
    return patternAt(value, SHA256_RE, pointer, 'must be a lowercase SHA-256 digest');
}
function blobAt(value, pointer) {
    return patternAt(value, GIT_BLOB_RE, pointer, 'must be a canonical Git blob digest');
}
function revisionAt(value, pointer) {
    return patternAt(value, FULL_REVISION_RE, pointer, 'must be a full lowercase repository revision');
}
function timestampAt(value, pointer) {
    const text = patternAt(value, TIMESTAMP_RE, pointer, 'must be a canonical RFC 3339 timestamp');
    if (new Date(text).toISOString() !== text) {
        invalid('invalid-timestamp', pointer, 'must be a real canonical timestamp');
    }
    return text;
}
function slugAt(value, pointer) {
    return patternAt(value, SECURITY_SLUG_RE, pointer, 'must be a security- prefixed lowercase kebab-case slug');
}
function identityAt(value, pointer) {
    const identity = patternAt(value, IDENTITY_RE, pointer, 'must be a canonical lowercase stable identity');
    if (identity.normalize('NFC') !== identity) {
        invalid('invalid-identity', pointer, 'must already be NFC-normalized');
    }
    return identity;
}
function repoPathAt(value, pointer) {
    const text = textAt(value, pointer);
    try {
        return normalizeAuditRepoPath(text);
    }
    catch {
        invalid('invalid-path', pointer, 'must be a normalized repository-relative path');
    }
}
function strictJsonPointerAt(value, pointer) {
    return patternAt(value, JSON_POINTER_RE, pointer, 'must be a strict non-root JSON Pointer');
}
function sortedUniqueStringsAt(value, pointer, parse = textAt, nonempty = false) {
    const rows = dataArrayAt(value, pointer).map((candidate, index) => parse(candidate, `${pointer}/${index}`));
    if (nonempty && rows.length === 0) {
        invalid('empty-array', pointer, 'must be nonempty');
    }
    if (new Set(rows).size !== rows.length) {
        invalid('duplicate', pointer, 'must contain unique values');
    }
    const sorted = [...rows].sort(utf16Compare);
    if (rows.some((row, index) => row !== sorted[index])) {
        invalid('invalid-order', pointer, 'must use UTF-16 lexical order');
    }
    return rows;
}
function parseBlobBinding(value, pointer) {
    const binding = dataRecordAt(value, pointer);
    exactKeys(binding, ['path', 'blob'], [], pointer);
    return {
        path: repoPathAt(binding.path, `${pointer}/path`),
        blob: blobAt(binding.blob, `${pointer}/blob`),
    };
}
function compareBindings(left, right) {
    return utf16Compare(left.path, right.path) ||
        utf16Compare(left.blob, right.blob);
}
function parseBindings(value, pointer, nonempty = true) {
    const bindings = dataArrayAt(value, pointer).map((candidate, index) => parseBlobBinding(candidate, `${pointer}/${index}`));
    if (nonempty && bindings.length === 0) {
        invalid('empty-array', pointer, 'must contain at least one binding');
    }
    const keys = bindings.map(({ path: bindingPath, blob }) => `${bindingPath}\0${blob}`);
    if (new Set(keys).size !== keys.length) {
        invalid('duplicate', pointer, 'contains duplicate bindings');
    }
    const sorted = [...bindings].sort(compareBindings);
    if (bindings.some((binding, index) => compareBindings(binding, sorted[index]) !== 0)) {
        invalid('invalid-order', pointer, 'bindings must be sorted by path and blob');
    }
    return bindings;
}
function parseSourceArtifact(value, pointer) {
    const artifact = dataRecordAt(value, pointer);
    exactKeys(artifact, ['path', 'repositoryRevision', 'gitBlob', 'sha256'], [], pointer);
    return {
        path: repoPathAt(artifact.path, `${pointer}/path`),
        repositoryRevision: revisionAt(artifact.repositoryRevision, `${pointer}/repositoryRevision`),
        gitBlob: blobAt(artifact.gitBlob, `${pointer}/gitBlob`),
        sha256: sha256At(artifact.sha256, `${pointer}/sha256`),
    };
}
function parseCreatedAtBasis(value, pointer) {
    return enumAt(value, ['recorded', 'source', 'source-revision-upper-bound'], pointer);
}
function parseReconciliationSource(value, pointer) {
    const source = dataRecordAt(value, pointer);
    const kind = enumAt(source.kind, ['grok-cli', 'codex-security', 'migration', 'manual'], `${pointer}/kind`);
    if (kind === 'manual') {
        exactKeys(source, ['kind', 'name'], ['sourceArtifact'], pointer);
        return {
            kind,
            name: identityAt(source.name, `${pointer}/name`),
            ...(source.sourceArtifact === undefined
                ? {}
                : {
                    sourceArtifact: parseSourceArtifact(source.sourceArtifact, `${pointer}/sourceArtifact`),
                }),
        };
    }
    exactKeys(source, ['kind', 'name', 'version'], ['sourceArtifact'], pointer);
    return {
        kind,
        name: patternAt(source.name, SOURCE_NAME_RE, `${pointer}/name`, 'must be a canonical lowercase source name'),
        version: textAt(source.version, `${pointer}/version`),
        ...(source.sourceArtifact === undefined
            ? {}
            : {
                sourceArtifact: parseSourceArtifact(source.sourceArtifact, `${pointer}/sourceArtifact`),
            }),
    };
}
function parseAlias(value, pointer) {
    const alias = dataRecordAt(value, pointer);
    exactKeys(alias, ['scheme', 'value'], [], pointer);
    return {
        scheme: patternAt(alias.scheme, ALIAS_SCHEME_RE, `${pointer}/scheme`, 'must be a canonical lowercase alias scheme'),
        value: textAt(alias.value, `${pointer}/value`),
    };
}
function parseAliasEvent(value, pointer) {
    exactKeys(value, [
        'type',
        'decisionLedger',
        'aliases',
        'findingId',
        'occurrenceIds',
        'relationship',
        'source',
        'createdAt',
        'createdAtBasis',
        'evidenceRefs',
    ], [], pointer);
    const aliases = dataArrayAt(value.aliases, `${pointer}/aliases`).map((candidate, index) => parseAlias(candidate, `${pointer}/aliases/${index}`));
    if (aliases.length === 0) {
        invalid('empty-array', `${pointer}/aliases`, 'must contain at least one alias');
    }
    const aliasKeys = aliases.map(({ scheme, value: aliasValue }) => `${scheme}\0${aliasValue}`);
    if (new Set(aliasKeys).size !== aliasKeys.length) {
        invalid('duplicate', `${pointer}/aliases`, 'contains duplicate aliases');
    }
    const sortedAliases = [...aliases].sort((left, right) => utf16Compare(left.scheme, right.scheme) ||
        utf16Compare(left.value, right.value));
    if (aliases.some((alias, index) => alias.scheme !== sortedAliases[index].scheme ||
        alias.value !== sortedAliases[index].value)) {
        invalid('invalid-order', `${pointer}/aliases`, 'aliases must be sorted by scheme and value');
    }
    return {
        type: 'identity-alias-reconciliation',
        decisionLedger: slugAt(value.decisionLedger, `${pointer}/decisionLedger`),
        aliases: aliases,
        findingId: patternAt(value.findingId, FINDING_ID_RE, `${pointer}/findingId`, 'must be an Atlas finding ID'),
        occurrenceIds: sortedUniqueStringsAt(value.occurrenceIds, `${pointer}/occurrenceIds`, (candidate, candidatePointer) => patternAt(candidate, OCCURRENCE_ID_RE, candidatePointer, 'must be an Atlas occurrence ID'), true),
        relationship: enumAt(value.relationship, ['canonical', 'duplicate-of'], `${pointer}/relationship`),
        source: parseReconciliationSource(value.source, `${pointer}/source`),
        createdAt: timestampAt(value.createdAt, `${pointer}/createdAt`),
        createdAtBasis: parseCreatedAtBasis(value.createdAtBasis, `${pointer}/createdAtBasis`),
        evidenceRefs: sortedUniqueStringsAt(value.evidenceRefs, `${pointer}/evidenceRefs`),
    };
}
function parseFindingReconciliationEvent(value, pointer) {
    exactKeys(value, [
        'type',
        'comparisonId',
        'decisionLedger',
        'beforeOccurrenceIds',
        'afterOccurrenceIds',
        'outcome',
        'confidence',
        'reason',
        'source',
        'createdAt',
        'createdAtBasis',
        'evidenceRefs',
    ], ['supersedesEventId'], pointer);
    const parseOccurrenceId = (candidate, candidatePointer) => patternAt(candidate, OCCURRENCE_ID_RE, candidatePointer, 'must be an Atlas occurrence ID');
    const beforeOccurrenceIds = sortedUniqueStringsAt(value.beforeOccurrenceIds, `${pointer}/beforeOccurrenceIds`, parseOccurrenceId, true);
    const afterOccurrenceIds = sortedUniqueStringsAt(value.afterOccurrenceIds, `${pointer}/afterOccurrenceIds`, parseOccurrenceId, true);
    if (beforeOccurrenceIds.length > 1 &&
        afterOccurrenceIds.length > 1) {
        invalid('invalid-reconciliation-shape', pointer, 'many-to-many reconciliation groups are forbidden');
    }
    if (beforeOccurrenceIds.some((occurrenceId) => afterOccurrenceIds.includes(occurrenceId))) {
        invalid('invalid-reconciliation-shape', pointer, 'before and after occurrence sets must be disjoint');
    }
    return {
        type: 'finding-reconciliation',
        comparisonId: patternAt(value.comparisonId, COMPARISON_ID_RE, `${pointer}/comparisonId`, 'must be an Atlas comparison ID'),
        decisionLedger: slugAt(value.decisionLedger, `${pointer}/decisionLedger`),
        beforeOccurrenceIds,
        afterOccurrenceIds,
        outcome: enumAt(value.outcome, ['equivalent', 'distinct', 'uncertain'], `${pointer}/outcome`),
        confidence: enumAt(value.confidence, ['high', 'medium', 'low'], `${pointer}/confidence`),
        reason: textAt(value.reason, `${pointer}/reason`),
        source: parseReconciliationSource(value.source, `${pointer}/source`),
        createdAt: timestampAt(value.createdAt, `${pointer}/createdAt`),
        createdAtBasis: parseCreatedAtBasis(value.createdAtBasis, `${pointer}/createdAtBasis`),
        evidenceRefs: sortedUniqueStringsAt(value.evidenceRefs, `${pointer}/evidenceRefs`),
        ...(value.supersedesEventId === undefined
            ? {}
            : {
                supersedesEventId: patternAt(value.supersedesEventId, EVENT_ID_RE, `${pointer}/supersedesEventId`, 'must be an Atlas decision event ID'),
            }),
    };
}
function parseReviewContext(value, pointer) {
    const context = dataRecordAt(value, pointer);
    exactKeys(context, ['observationId', 'bindings', 'ruleset', 'policyDigest'], [], pointer);
    const ruleset = dataRecordAt(context.ruleset, `${pointer}/ruleset`);
    exactKeys(ruleset, ['id', 'digest'], [], `${pointer}/ruleset`);
    return {
        observationId: patternAt(context.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
        bindings: parseBindings(context.bindings, `${pointer}/bindings`),
        ruleset: {
            id: textAt(ruleset.id, `${pointer}/ruleset/id`),
            digest: sha256At(ruleset.digest, `${pointer}/ruleset/digest`),
        },
        policyDigest: sha256At(context.policyDigest, `${pointer}/policyDigest`),
    };
}
function optionalSourceArtifact(value, pointer) {
    return value.sourceArtifact === undefined
        ? {}
        : {
            sourceArtifact: parseSourceArtifact(value.sourceArtifact, `${pointer}/sourceArtifact`),
        };
}
function parseDecisionProof(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    const kind = enumAt(proof.kind, [
        'current-review',
        'post-fix',
        'source-evidence',
        'replacement',
        'deletion',
        'no-replacement',
    ], `${pointer}/kind`);
    const sourceArtifact = () => optionalSourceArtifact(proof, pointer);
    if (kind === 'current-review') {
        exactKeys(proof, ['kind', 'observationId', 'reviewedBindings', 'outcome', 'summary'], ['sourceArtifact'], pointer);
        if (proof.outcome !== 'finding-present') {
            invalid('invalid-proof-outcome', `${pointer}/outcome`, 'current-review outcome must equal finding-present');
        }
        return {
            kind,
            observationId: patternAt(proof.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
            reviewedBindings: parseBindings(proof.reviewedBindings, `${pointer}/reviewedBindings`),
            outcome: 'finding-present',
            summary: textAt(proof.summary, `${pointer}/summary`),
            ...sourceArtifact(),
        };
    }
    if (kind === 'post-fix') {
        exactKeys(proof, [
            'kind',
            'beforeObservationId',
            'afterObservationId',
            'beforeBindings',
            'afterBindings',
            'fixRevision',
            'outcome',
            'summary',
        ], ['sourceArtifact'], pointer);
        if (proof.outcome !== 'finding-absent-after-fix') {
            invalid('invalid-proof-outcome', `${pointer}/outcome`, 'post-fix outcome must equal finding-absent-after-fix');
        }
        return {
            kind,
            beforeObservationId: patternAt(proof.beforeObservationId, OBSERVATION_ID_RE, `${pointer}/beforeObservationId`, 'must be an Atlas observation ID'),
            afterObservationId: patternAt(proof.afterObservationId, OBSERVATION_ID_RE, `${pointer}/afterObservationId`, 'must be an Atlas observation ID'),
            beforeBindings: parseBindings(proof.beforeBindings, `${pointer}/beforeBindings`),
            afterBindings: parseBindings(proof.afterBindings, `${pointer}/afterBindings`),
            fixRevision: revisionAt(proof.fixRevision, `${pointer}/fixRevision`),
            outcome: 'finding-absent-after-fix',
            summary: textAt(proof.summary, `${pointer}/summary`),
            ...sourceArtifact(),
        };
    }
    if (kind === 'source-evidence') {
        exactKeys(proof, ['kind', 'observationId', 'reviewedBindings', 'outcome', 'summary'], ['sourceArtifact'], pointer);
        if (proof.outcome !== 'not-reportable') {
            invalid('invalid-proof-outcome', `${pointer}/outcome`, 'source-evidence outcome must equal not-reportable');
        }
        return {
            kind,
            observationId: patternAt(proof.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
            reviewedBindings: parseBindings(proof.reviewedBindings, `${pointer}/reviewedBindings`),
            outcome: 'not-reportable',
            summary: textAt(proof.summary, `${pointer}/summary`),
            ...sourceArtifact(),
        };
    }
    if (kind === 'replacement') {
        exactKeys(proof, [
            'kind',
            'observationId',
            'replacementFindingId',
            'replacementOccurrenceId',
            'replacementBindings',
            'outcome',
            'summary',
        ], ['sourceArtifact'], pointer);
        if (proof.outcome !== 'replacement-tracks-root-cause') {
            invalid('invalid-proof-outcome', `${pointer}/outcome`, 'replacement outcome must equal replacement-tracks-root-cause');
        }
        return {
            kind,
            observationId: patternAt(proof.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
            replacementFindingId: patternAt(proof.replacementFindingId, FINDING_ID_RE, `${pointer}/replacementFindingId`, 'must be an Atlas finding ID'),
            replacementOccurrenceId: patternAt(proof.replacementOccurrenceId, OCCURRENCE_ID_RE, `${pointer}/replacementOccurrenceId`, 'must be an Atlas occurrence ID'),
            replacementBindings: parseBindings(proof.replacementBindings, `${pointer}/replacementBindings`),
            outcome: 'replacement-tracks-root-cause',
            summary: textAt(proof.summary, `${pointer}/summary`),
            ...sourceArtifact(),
        };
    }
    if (kind === 'deletion') {
        exactKeys(proof, [
            'kind',
            'deletionCommit',
            'parentRevision',
            'deletedBindings',
            'outcome',
            'summary',
        ], ['sourceArtifact'], pointer);
        if (proof.outcome !== 'exact-source-deleted') {
            invalid('invalid-proof-outcome', `${pointer}/outcome`, 'deletion outcome must equal exact-source-deleted');
        }
        return {
            kind,
            deletionCommit: revisionAt(proof.deletionCommit, `${pointer}/deletionCommit`),
            parentRevision: revisionAt(proof.parentRevision, `${pointer}/parentRevision`),
            deletedBindings: parseBindings(proof.deletedBindings, `${pointer}/deletedBindings`),
            outcome: 'exact-source-deleted',
            summary: textAt(proof.summary, `${pointer}/summary`),
            ...sourceArtifact(),
        };
    }
    exactKeys(proof, [
        'kind',
        'observationId',
        'searchRevision',
        'reviewedBindings',
        'outcome',
        'summary',
    ], ['sourceArtifact'], pointer);
    if (proof.outcome !== 'no-reportable-replacement') {
        invalid('invalid-proof-outcome', `${pointer}/outcome`, 'no-replacement outcome must equal no-reportable-replacement');
    }
    return {
        kind,
        observationId: patternAt(proof.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
        searchRevision: revisionAt(proof.searchRevision, `${pointer}/searchRevision`),
        reviewedBindings: parseBindings(proof.reviewedBindings, `${pointer}/reviewedBindings`),
        outcome: 'no-reportable-replacement',
        summary: textAt(proof.summary, `${pointer}/summary`),
        ...sourceArtifact(),
    };
}
function parseActionEvidence(value, pointer) {
    const evidence = dataRecordAt(value, pointer);
    const kind = enumAt(evidence.kind, ['source-evidence', 'remediation', 'replacement', 'deletion'], `${pointer}/kind`);
    if (kind === 'source-evidence') {
        exactKeys(evidence, ['kind', 'reviewedBindings', 'conclusion', 'rationale'], [], pointer);
        if (evidence.conclusion !== 'not-reportable') {
            invalid('invalid-action-evidence', `${pointer}/conclusion`, 'must equal not-reportable');
        }
        return {
            kind,
            reviewedBindings: parseBindings(evidence.reviewedBindings, `${pointer}/reviewedBindings`),
            conclusion: 'not-reportable',
            rationale: textAt(evidence.rationale, `${pointer}/rationale`),
        };
    }
    if (kind === 'remediation') {
        exactKeys(evidence, ['kind', 'beforeBindings', 'afterBindings', 'fixRevision'], [], pointer);
        return {
            kind,
            beforeBindings: parseBindings(evidence.beforeBindings, `${pointer}/beforeBindings`),
            afterBindings: parseBindings(evidence.afterBindings, `${pointer}/afterBindings`),
            fixRevision: revisionAt(evidence.fixRevision, `${pointer}/fixRevision`),
        };
    }
    if (kind === 'replacement') {
        exactKeys(evidence, ['kind', 'replacementFindingId', 'replacementOccurrenceId'], [], pointer);
        return {
            kind,
            replacementFindingId: patternAt(evidence.replacementFindingId, FINDING_ID_RE, `${pointer}/replacementFindingId`, 'must be an Atlas finding ID'),
            replacementOccurrenceId: patternAt(evidence.replacementOccurrenceId, OCCURRENCE_ID_RE, `${pointer}/replacementOccurrenceId`, 'must be an Atlas occurrence ID'),
        };
    }
    exactKeys(evidence, [
        'kind',
        'deletionCommit',
        'deletedBindings',
        'noReplacementEvidence',
    ], [], pointer);
    const noReplacement = dataRecordAt(evidence.noReplacementEvidence, `${pointer}/noReplacementEvidence`);
    exactKeys(noReplacement, [
        'observationId',
        'searchRevision',
        'reviewedBindings',
        'summary',
    ], [], `${pointer}/noReplacementEvidence`);
    return {
        kind,
        deletionCommit: revisionAt(evidence.deletionCommit, `${pointer}/deletionCommit`),
        deletedBindings: parseBindings(evidence.deletedBindings, `${pointer}/deletedBindings`),
        noReplacementEvidence: {
            observationId: patternAt(noReplacement.observationId, OBSERVATION_ID_RE, `${pointer}/noReplacementEvidence/observationId`, 'must be an Atlas observation ID'),
            searchRevision: revisionAt(noReplacement.searchRevision, `${pointer}/noReplacementEvidence/searchRevision`),
            reviewedBindings: parseBindings(noReplacement.reviewedBindings, `${pointer}/noReplacementEvidence/reviewedBindings`),
            summary: textAt(noReplacement.summary, `${pointer}/noReplacementEvidence/summary`),
        },
    };
}
function parseRevisionBinding(value, pointer) {
    const binding = dataRecordAt(value, pointer);
    exactKeys(binding, ['repositoryRevision', 'files'], ['observationId'], pointer);
    return {
        repositoryRevision: revisionAt(binding.repositoryRevision, `${pointer}/repositoryRevision`),
        ...(binding.observationId === undefined
            ? {}
            : {
                observationId: patternAt(binding.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
            }),
        files: parseBindings(binding.files, `${pointer}/files`),
    };
}
function parseRegression(value, pointer) {
    const regression = dataRecordAt(value, pointer);
    const kind = enumAt(regression.kind, ['test', 'guardrail', 'check', 'manual'], `${pointer}/kind`);
    if (kind === 'manual') {
        exactKeys(regression, ['kind', 'name', 'result', 'binding'], ['observedAt'], pointer);
        return {
            kind,
            name: textAt(regression.name, `${pointer}/name`),
            result: enumAt(regression.result, ['passed', 'failed', 'not-run'], `${pointer}/result`),
            binding: parseRevisionBinding(regression.binding, `${pointer}/binding`),
            ...(regression.observedAt === undefined
                ? {}
                : {
                    observedAt: timestampAt(regression.observedAt, `${pointer}/observedAt`),
                }),
        };
    }
    exactKeys(regression, ['kind', 'name', 'command', 'result', 'binding'], ['observedAt'], pointer);
    return {
        kind,
        name: textAt(regression.name, `${pointer}/name`),
        command: textAt(regression.command, `${pointer}/command`),
        result: enumAt(regression.result, ['passed', 'failed', 'not-run'], `${pointer}/result`),
        binding: parseRevisionBinding(regression.binding, `${pointer}/binding`),
        ...(regression.observedAt === undefined
            ? {}
            : {
                observedAt: timestampAt(regression.observedAt, `${pointer}/observedAt`),
            }),
    };
}
function parseDecisionReview(value, pointer) {
    const review = dataRecordAt(value, pointer);
    exactKeys(review, [
        'reviewer',
        'verdict',
        'reason',
        'evidence',
        'evidenceRefs',
        'createdAt',
    ], [], pointer);
    return {
        reviewer: identityAt(review.reviewer, `${pointer}/reviewer`),
        verdict: enumAt(review.verdict, ['approve', 'reject'], `${pointer}/verdict`),
        reason: textAt(review.reason, `${pointer}/reason`),
        evidence: boundedTextAt(review.evidence, `${pointer}/evidence`),
        evidenceRefs: sortedUniqueStringsAt(review.evidenceRefs, `${pointer}/evidenceRefs`),
        createdAt: timestampAt(review.createdAt, `${pointer}/createdAt`),
    };
}
function sameBindings(left, right) {
    return left.length === right.length &&
        left.every((binding, index) => binding.path === right[index].path &&
            binding.blob === right[index].blob);
}
function sameRuleset(left, right) {
    return left === null
        ? right === null
        : right !== null &&
            left.id === right.id &&
            left.digest === right.digest;
}
function requireStableIdentityReconciliation(event, occurrences) {
    const beforeFindingIds = new Set(event.beforeOccurrenceIds.map((occurrenceId) => {
        const occurrence = occurrences.get(occurrenceId);
        if (!occurrence) {
            throw new Error(`reconciliation ${event.eventId} references unknown occurrence ${occurrenceId}`);
        }
        return occurrence.findingId;
    }));
    const sharesFinding = event.afterOccurrenceIds.some((occurrenceId) => {
        const occurrence = occurrences.get(occurrenceId);
        if (!occurrence) {
            throw new Error(`reconciliation ${event.eventId} references unknown occurrence ${occurrenceId}`);
        }
        return beforeFindingIds.has(occurrence.findingId);
    });
    if (sharesFinding &&
        (event.outcome !== 'equivalent' || event.confidence !== 'high')) {
        throw new Error(`reconciliation ${event.eventId} compares occurrences of the same finding and must be high-confidence equivalent`);
    }
}
function parseFindingDispositionEvent(value, pointer) {
    const action = enumAt(value.action, [
        'open',
        'reopened',
        'accepted-risk',
        'separate-design',
        'false-positive',
        'remediated',
        'superseded',
    ], `${pointer}/action`);
    const commonRequired = [
        'type',
        'findingId',
        'occurrenceId',
        'action',
        'actor',
        'owner',
        'reason',
        'createdAt',
        'createdAtBasis',
        'reviewContext',
        'evidenceRefs',
        'proofs',
        'reviews',
    ];
    let required = [...commonRequired];
    let optional = [];
    if (action === 'open')
        optional = ['supersedesEventId'];
    if (action === 'reopened')
        required.push('supersedesEventId');
    if (action === 'accepted-risk' || action === 'separate-design') {
        required.push('expiresAt');
    }
    if (action === 'false-positive') {
        required.push('expiresAt', 'actionEvidence');
    }
    if (action === 'remediated') {
        required.push('regression', 'actionEvidence');
    }
    if (action === 'superseded')
        required.push('actionEvidence');
    exactKeys(value, required, optional, pointer);
    const createdAtBasis = parseCreatedAtBasis(value.createdAtBasis, `${pointer}/createdAtBasis`);
    const context = parseReviewContext(value.reviewContext, `${pointer}/reviewContext`);
    const proofs = dataArrayAt(value.proofs, `${pointer}/proofs`).map((candidate, index) => parseDecisionProof(candidate, `${pointer}/proofs/${index}`));
    const reviews = dataArrayAt(value.reviews, `${pointer}/reviews`).map((candidate, index) => parseDecisionReview(candidate, `${pointer}/reviews/${index}`));
    if (createdAtBasis !== 'recorded' &&
        proofs.some((proof) => proof.sourceArtifact === undefined)) {
        invalid('missing-migrated-source-artifact', `${pointer}/proofs`, 'migrated proofs require a sealed sourceArtifact');
    }
    const common = {
        type: 'finding-disposition',
        findingId: patternAt(value.findingId, FINDING_ID_RE, `${pointer}/findingId`, 'must be an Atlas finding ID'),
        occurrenceId: patternAt(value.occurrenceId, OCCURRENCE_ID_RE, `${pointer}/occurrenceId`, 'must be an Atlas occurrence ID'),
        actor: identityAt(value.actor, `${pointer}/actor`),
        owner: identityAt(value.owner, `${pointer}/owner`),
        reason: textAt(value.reason, `${pointer}/reason`),
        createdAt: timestampAt(value.createdAt, `${pointer}/createdAt`),
        createdAtBasis,
        reviewContext: context,
        evidenceRefs: sortedUniqueStringsAt(value.evidenceRefs, `${pointer}/evidenceRefs`),
        proofs,
        reviews,
    };
    const requireProofKinds = (allowed, minimum) => {
        if (proofs.length < minimum ||
            proofs.some((proof) => !allowed.includes(proof.kind))) {
            invalid('invalid-action-proof', `${pointer}/proofs`, `${action} requires ${allowed.join(' or ')} proofs`);
        }
    };
    const requireReviewProofMatches = () => {
        for (const [index, proof] of proofs.entries()) {
            if ((proof.kind === 'current-review' ||
                proof.kind === 'source-evidence') &&
                (proof.observationId !== context.observationId ||
                    !sameBindings(proof.reviewedBindings, context.bindings))) {
                invalid('review-proof-mismatch', `${pointer}/proofs/${index}`, 'review proof must equal the event review context');
            }
        }
    };
    if (action === 'open') {
        requireProofKinds(['current-review'], 0);
        requireReviewProofMatches();
        return {
            ...common,
            action,
            proofs: proofs,
            ...(value.supersedesEventId === undefined
                ? {}
                : {
                    supersedesEventId: patternAt(value.supersedesEventId, EVENT_ID_RE, `${pointer}/supersedesEventId`, 'must be an Atlas decision event ID'),
                }),
        };
    }
    if (action === 'reopened') {
        requireProofKinds(['current-review'], 1);
        requireReviewProofMatches();
        return {
            ...common,
            action,
            proofs: proofs,
            supersedesEventId: patternAt(value.supersedesEventId, EVENT_ID_RE, `${pointer}/supersedesEventId`, 'must be an Atlas decision event ID'),
        };
    }
    if (action === 'accepted-risk' || action === 'separate-design') {
        requireProofKinds(['current-review'], 1);
        requireReviewProofMatches();
        return {
            ...common,
            action,
            expiresAt: timestampAt(value.expiresAt, `${pointer}/expiresAt`),
            proofs: proofs,
        };
    }
    const actionEvidence = parseActionEvidence(value.actionEvidence, `${pointer}/actionEvidence`);
    if (action === 'false-positive') {
        if (value.expiresAt !== null) {
            invalid('invalid-expiry', `${pointer}/expiresAt`, 'false-positive expiresAt must be null');
        }
        requireProofKinds(['source-evidence'], 1);
        requireReviewProofMatches();
        if (actionEvidence.kind !== 'source-evidence' ||
            !sameBindings(actionEvidence.reviewedBindings, context.bindings)) {
            invalid('invalid-action-evidence', `${pointer}/actionEvidence`, 'false-positive requires source-evidence matching review bindings');
        }
        return {
            ...common,
            action,
            expiresAt: null,
            proofs: proofs,
            actionEvidence,
        };
    }
    if (action === 'remediated') {
        requireProofKinds(['post-fix'], 1);
        const regression = parseRegression(value.regression, `${pointer}/regression`);
        if (regression.kind === 'manual' || regression.result !== 'passed') {
            invalid('invalid-regression', `${pointer}/regression`, 'remediation regression must be a passing test, guardrail, or check');
        }
        if (actionEvidence.kind !== 'remediation') {
            invalid('invalid-action-evidence', `${pointer}/actionEvidence`, 'remediation requires remediation evidence');
        }
        for (const [index, proof] of proofs.entries()) {
            if (proof.kind !== 'post-fix' ||
                proof.beforeObservationId !== context.observationId ||
                !sameBindings(proof.beforeBindings, context.bindings) ||
                !sameBindings(proof.beforeBindings, actionEvidence.beforeBindings) ||
                !sameBindings(proof.afterBindings, actionEvidence.afterBindings) ||
                proof.fixRevision !== actionEvidence.fixRevision ||
                regression.binding.repositoryRevision !== proof.fixRevision ||
                !sameBindings(regression.binding.files, proof.afterBindings) ||
                (regression.binding.observationId !== undefined &&
                    regression.binding.observationId !== proof.afterObservationId)) {
                invalid('remediation-proof-mismatch', `${pointer}/proofs/${index}`, 'post-fix proof, action evidence, regression, and context must agree');
            }
        }
        return {
            ...common,
            action,
            proofs: proofs,
            regression: regression,
            actionEvidence,
        };
    }
    if (actionEvidence.kind === 'replacement') {
        requireProofKinds(['replacement'], 1);
        for (const [index, proof] of proofs.entries()) {
            if (proof.kind !== 'replacement' ||
                proof.replacementFindingId !==
                    actionEvidence.replacementFindingId ||
                proof.replacementOccurrenceId !==
                    actionEvidence.replacementOccurrenceId) {
                invalid('replacement-proof-mismatch', `${pointer}/proofs/${index}`, 'replacement proof and action evidence must agree');
            }
        }
        return {
            ...common,
            action,
            proofs: proofs,
            actionEvidence,
        };
    }
    if (actionEvidence.kind !== 'deletion') {
        invalid('invalid-action-evidence', `${pointer}/actionEvidence`, 'superseded requires replacement or deletion evidence');
    }
    requireProofKinds(['deletion', 'no-replacement'], 2);
    const deletionProofs = proofs.filter((proof) => proof.kind === 'deletion');
    const noReplacementProofs = proofs.filter((proof) => proof.kind === 'no-replacement');
    if (deletionProofs.length === 0 || noReplacementProofs.length === 0) {
        invalid('invalid-action-proof', `${pointer}/proofs`, 'deletion supersession requires deletion and no-replacement proofs');
    }
    if (deletionProofs.some((proof) => proof.deletionCommit !== actionEvidence.deletionCommit ||
        !sameBindings(proof.deletedBindings, actionEvidence.deletedBindings)) ||
        noReplacementProofs.some((proof) => proof.observationId !==
            actionEvidence.noReplacementEvidence.observationId ||
            proof.searchRevision !==
                actionEvidence.noReplacementEvidence.searchRevision ||
            !sameBindings(proof.reviewedBindings, actionEvidence.noReplacementEvidence.reviewedBindings))) {
        invalid('deletion-proof-mismatch', `${pointer}/proofs`, 'deletion proofs and action evidence must agree');
    }
    return {
        ...common,
        action,
        proofs: proofs,
        actionEvidence,
    };
}
function parseRetirementHistoryProof(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    exactKeys(proof, ['slug', 'observationId', 'path', 'blob'], [], pointer);
    return {
        slug: slugAt(proof.slug, `${pointer}/slug`),
        observationId: patternAt(proof.observationId, OBSERVATION_ID_RE, `${pointer}/observationId`, 'must be an Atlas observation ID'),
        path: repoPathAt(proof.path, `${pointer}/path`),
        blob: blobAt(proof.blob, `${pointer}/blob`),
    };
}
function parseStagedAbsenceProof(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    exactKeys(proof, [
        'kind',
        'headRevision',
        'headBinding',
        'indexState',
        'worktreeState',
    ], [], pointer);
    if (proof.kind !== 'worktree-index-absence' ||
        proof.indexState !== 'absent' ||
        proof.worktreeState !== 'absent') {
        invalid('invalid-absence-proof', pointer, 'must be a worktree-index-absence proof with absent states');
    }
    return {
        kind: 'worktree-index-absence',
        headRevision: revisionAt(proof.headRevision, `${pointer}/headRevision`),
        headBinding: parseBlobBinding(proof.headBinding, `${pointer}/headBinding`),
        indexState: 'absent',
        worktreeState: 'absent',
    };
}
function parseDeletionCommitProof(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    exactKeys(proof, [
        'kind',
        'parentRevision',
        'parentBindings',
        'absentPaths',
    ], [], pointer);
    if (proof.kind !== 'git-deletion') {
        invalid('invalid-deletion-proof', `${pointer}/kind`, 'must equal git-deletion');
    }
    return {
        kind: 'git-deletion',
        parentRevision: revisionAt(proof.parentRevision, `${pointer}/parentRevision`),
        parentBindings: parseBindings(proof.parentBindings, `${pointer}/parentBindings`),
        absentPaths: sortedUniqueStringsAt(proof.absentPaths, `${pointer}/absentPaths`, repoPathAt, true),
    };
}
function parseTreeState(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    exactKeys(proof, ['kind', 'repositoryRevision', 'presentBindings', 'absentPaths'], [], pointer);
    if (proof.kind !== 'git-tree-state') {
        invalid('invalid-tree-state', `${pointer}/kind`, 'must equal git-tree-state');
    }
    const presentBindings = parseBindings(proof.presentBindings, `${pointer}/presentBindings`, false);
    const absentPaths = sortedUniqueStringsAt(proof.absentPaths, `${pointer}/absentPaths`, repoPathAt);
    if (presentBindings.some((binding) => absentPaths.includes(binding.path))) {
        invalid('invalid-tree-state', pointer, 'present and absent path sets must be disjoint');
    }
    return {
        kind: 'git-tree-state',
        repositoryRevision: revisionAt(proof.repositoryRevision, `${pointer}/repositoryRevision`),
        presentBindings,
        absentPaths,
    };
}
function parseMigrationSourceProof(value, pointer) {
    const proof = dataRecordAt(value, pointer);
    exactKeys(proof, [
        'kind',
        'sourceArtifact',
        'jsonPointer',
        'sourceReason',
        'summary',
    ], [], pointer);
    if (proof.kind !== 'sealed-migration-source' ||
        proof.sourceReason !== 'uncommitted_snapshot_absent') {
        invalid('invalid-migration-proof', pointer, 'must be a sealed uncommitted_snapshot_absent source proof');
    }
    return {
        kind: 'sealed-migration-source',
        sourceArtifact: parseSourceArtifact(proof.sourceArtifact, `${pointer}/sourceArtifact`),
        jsonPointer: strictJsonPointerAt(proof.jsonPointer, `${pointer}/jsonPointer`),
        sourceReason: 'uncommitted_snapshot_absent',
        summary: textAt(proof.summary, `${pointer}/summary`),
    };
}
function parseScopeRetirementEvent(value, pointer) {
    const reason = enumAt(value.reason, [
        'deleted',
        'moved',
        'superseded',
        'staged-deletion',
        'uncommitted-snapshot-absent',
    ], `${pointer}/reason`);
    const commonRequired = [
        'type',
        'decisionLedger',
        'path',
        'blob',
        'reason',
        'retiredAt',
        'retiredAtPrecision',
        'actor',
        'createdAt',
        'createdAtBasis',
        'historyProof',
        'evidenceRefs',
    ];
    const required = [...commonRequired];
    const optional = [];
    if (reason === 'staged-deletion')
        required.push('absenceProof');
    if (reason === 'deleted') {
        required.push('deletionCommit', 'deletionProof');
        optional.push('supersedesEventId');
    }
    if (reason === 'moved')
        required.push('successor', 'revisionProof');
    if (reason === 'superseded') {
        required.push('revisionProof');
        optional.push('successor', 'noReplacementProof');
    }
    if (reason === 'uncommitted-snapshot-absent') {
        required.push('migrationSourceProof');
    }
    const precision = enumAt(value.retiredAtPrecision, ['timestamp', 'date'], `${pointer}/retiredAtPrecision`);
    if (precision === 'date')
        required.push('originalRetiredDate');
    exactKeys(value, required, optional, pointer);
    const decisionLedger = slugAt(value.decisionLedger, `${pointer}/decisionLedger`);
    const retiredPath = repoPathAt(value.path, `${pointer}/path`);
    const retiredBlob = blobAt(value.blob, `${pointer}/blob`);
    const retiredAt = timestampAt(value.retiredAt, `${pointer}/retiredAt`);
    const historyProof = parseRetirementHistoryProof(value.historyProof, `${pointer}/historyProof`);
    if (historyProof.slug !== decisionLedger ||
        historyProof.path !== retiredPath ||
        historyProof.blob !== retiredBlob) {
        invalid('retirement-history-proof-mismatch', `${pointer}/historyProof`, 'must bind the containing ledger and exact retired path/blob');
    }
    const originalRetiredDate = precision === 'date'
        ? patternAt(value.originalRetiredDate, DATE_RE, `${pointer}/originalRetiredDate`, 'must be a YYYY-MM-DD calendar date')
        : undefined;
    const common = {
        type: 'scope-retirement',
        decisionLedger,
        path: retiredPath,
        blob: retiredBlob,
        retiredAt,
        actor: identityAt(value.actor, `${pointer}/actor`),
        createdAt: timestampAt(value.createdAt, `${pointer}/createdAt`),
        createdAtBasis: parseCreatedAtBasis(value.createdAtBasis, `${pointer}/createdAtBasis`),
        historyProof,
        evidenceRefs: sortedUniqueStringsAt(value.evidenceRefs, `${pointer}/evidenceRefs`),
        ...(precision === 'timestamp'
            ? { retiredAtPrecision: 'timestamp' }
            : {
                retiredAtPrecision: 'date',
                originalRetiredDate: originalRetiredDate,
            }),
    };
    if (precision === 'date' &&
        (retiredAt !== `${originalRetiredDate}T00:00:00.000Z` ||
            new Date(retiredAt).toISOString() !== retiredAt)) {
        invalid('retirement-date-precision-mismatch', `${pointer}/retiredAt`, 'date precision must normalize the original date to midnight UTC');
    }
    if (reason === 'staged-deletion') {
        const absenceProof = parseStagedAbsenceProof(value.absenceProof, `${pointer}/absenceProof`);
        if (absenceProof.headBinding.path !== retiredPath ||
            absenceProof.headBinding.blob !== retiredBlob) {
            invalid('retirement-absence-proof-mismatch', `${pointer}/absenceProof/headBinding`, 'must equal the retired path/blob');
        }
        return { ...common, reason, absenceProof };
    }
    if (reason === 'deleted') {
        const deletionCommit = revisionAt(value.deletionCommit, `${pointer}/deletionCommit`);
        const deletionProof = parseDeletionCommitProof(value.deletionProof, `${pointer}/deletionProof`);
        if (!deletionProof.parentBindings.some((binding) => binding.path === retiredPath && binding.blob === retiredBlob) ||
            !deletionProof.absentPaths.includes(retiredPath)) {
            invalid('retirement-deletion-proof-mismatch', `${pointer}/deletionProof`, 'must prove the retired binding in the parent and path absent after deletion');
        }
        return {
            ...common,
            reason,
            deletionCommit,
            deletionProof,
            ...(value.supersedesEventId === undefined
                ? {}
                : {
                    supersedesEventId: patternAt(value.supersedesEventId, EVENT_ID_RE, `${pointer}/supersedesEventId`, 'must be an Atlas decision event ID'),
                }),
        };
    }
    if (reason === 'moved' || reason === 'superseded') {
        const revisionProof = parseTreeState(value.revisionProof, `${pointer}/revisionProof`);
        if (!revisionProof.absentPaths.includes(retiredPath)) {
            invalid('retirement-revision-proof-mismatch', `${pointer}/revisionProof/absentPaths`, 'must prove the retired path absent');
        }
        if (value.successor !== undefined) {
            if (reason === 'superseded' && value.noReplacementProof !== undefined) {
                invalid('invalid-retirement-branch', pointer, 'superseded must choose exactly one successor or no-replacement branch');
            }
            const successor = parseBlobBinding(value.successor, `${pointer}/successor`);
            if (!revisionProof.presentBindings.some((binding) => binding.path === successor.path && binding.blob === successor.blob) ||
                (reason === 'moved' && successor.blob !== retiredBlob)) {
                invalid('retirement-successor-mismatch', `${pointer}/successor`, reason === 'moved'
                    ? 'moved successor must exist and have the exact retired blob'
                    : 'successor must exist in the verified tree state');
            }
            return { ...common, reason, successor, revisionProof };
        }
        if (reason === 'moved' || value.noReplacementProof === undefined) {
            invalid('missing-retirement-branch', pointer, `${reason} requires its reason-specific successor or no-replacement branch`);
        }
        const noReplacementProof = parseDecisionProof(value.noReplacementProof, `${pointer}/noReplacementProof`);
        if (noReplacementProof.kind !== 'no-replacement') {
            invalid('invalid-retirement-proof', `${pointer}/noReplacementProof/kind`, 'must equal no-replacement');
        }
        if (common.createdAtBasis !== 'recorded' &&
            noReplacementProof.sourceArtifact === undefined) {
            invalid('missing-migrated-source-artifact', `${pointer}/noReplacementProof/sourceArtifact`, 'migrated no-replacement proofs require a sealed sourceArtifact');
        }
        return {
            ...common,
            reason,
            noReplacementProof,
            revisionProof,
        };
    }
    return {
        ...common,
        reason,
        migrationSourceProof: parseMigrationSourceProof(value.migrationSourceProof, `${pointer}/migrationSourceProof`),
    };
}
function parseDecisionEventInput(value, pointer) {
    const event = dataRecordAt(value, pointer);
    const type = enumAt(event.type, [
        'finding-disposition',
        'scope-retirement',
        'finding-reconciliation',
        'identity-alias-reconciliation',
    ], `${pointer}/type`);
    if (type === 'identity-alias-reconciliation') {
        return parseAliasEvent(event, pointer);
    }
    if (type === 'finding-reconciliation') {
        return parseFindingReconciliationEvent(event, pointer);
    }
    if (type === 'finding-disposition') {
        return parseFindingDispositionEvent(event, pointer);
    }
    return parseScopeRetirementEvent(event, pointer);
}
function parseStoredDecisionEvent(value, pointer) {
    const event = dataRecordAt(value, pointer);
    if (!Object.hasOwn(event, 'eventId')) {
        invalid('missing-member', `${pointer}/eventId`, 'required member is missing');
    }
    const eventId = patternAt(event.eventId, EVENT_ID_RE, `${pointer}/eventId`, 'must be an Atlas decision event ID');
    const input = { ...event };
    delete input.eventId;
    const parsedInput = parseDecisionEventInput(input, pointer);
    const expectedEventId = computeAuditDecisionEventId(parsedInput);
    if (eventId !== expectedEventId) {
        invalid('decision-event-id-mismatch', `${pointer}/eventId`, 'does not match the canonical event identity');
    }
    return { ...parsedInput, eventId };
}
export function computeAuditDecisionEventId(event) {
    const parsed = parseDecisionEventInput(event, '/event');
    return stableAuditId('adev', 'atlas-decision-event/v1', [canonicalJson(parsed)]);
}
export function computeAuditDecisionEntryDigest(entry) {
    return sha256Canonical(entry);
}
export function computeAuditFindingComparisonId(boundary) {
    const value = dataRecordAt(boundary, '/comparison');
    exactKeys(value, ['beforeObservationIds', 'afterObservationIds'], [], '/comparison');
    const parseObservationId = (candidate, pointer) => patternAt(candidate, OBSERVATION_ID_RE, pointer, 'must be an Atlas observation ID');
    const before = dataArrayAt(value.beforeObservationIds, '/comparison/beforeObservationIds').map((candidate, index) => parseObservationId(candidate, `/comparison/beforeObservationIds/${index}`));
    const after = dataArrayAt(value.afterObservationIds, '/comparison/afterObservationIds').map((candidate, index) => parseObservationId(candidate, `/comparison/afterObservationIds/${index}`));
    if (before.length === 0 || after.length === 0) {
        invalid('invalid-comparison-boundary', '/comparison', 'before and after observation sets must be nonempty');
    }
    if (new Set(before).size !== before.length ||
        new Set(after).size !== after.length) {
        invalid('invalid-comparison-boundary', '/comparison', 'observation sets must contain unique IDs');
    }
    if (before.some((observationId) => after.includes(observationId))) {
        invalid('invalid-comparison-boundary', '/comparison', 'before and after observation sets must be disjoint');
    }
    const normalized = {
        beforeObservationIds: [...before].sort(utf16Compare),
        afterObservationIds: [...after].sort(utf16Compare),
    };
    return stableAuditId('acmp', 'atlas-finding-comparison/v1', [canonicalJson(normalized)]);
}
export function validateUniqueAuditIdentityRecords(records) {
    const diagnostics = [];
    let candidates;
    try {
        candidates = dataArrayAt(records, '/records', AUDIT_LIMITS.collectionItems);
    }
    catch {
        return [{
                code: 'invalid-identity-registry',
                path: '',
                message: 'identity records must be a dense plain data-only array',
            }];
    }
    const byId = new Map();
    const byDigest = new Map();
    for (const [index, candidate] of candidates.entries()) {
        let parsed;
        try {
            const pointer = `/records/${index}`;
            const record = dataRecordAt(candidate, pointer);
            exactKeys(record, ['namespace', 'id', 'digest', 'location'], [], pointer);
            const namespace = enumAt(record.namespace, ['decision-event', 'decision-entry', 'comparison'], `${pointer}/namespace`);
            const id = namespace === 'decision-event'
                ? patternAt(record.id, EVENT_ID_RE, `${pointer}/id`, 'must be an Atlas decision event ID')
                : namespace === 'comparison'
                    ? patternAt(record.id, COMPARISON_ID_RE, `${pointer}/id`, 'must be an Atlas comparison ID')
                    : sha256At(record.id, `${pointer}/id`);
            parsed = {
                namespace,
                id,
                digest: sha256At(record.digest, `${pointer}/digest`),
                location: textAt(record.location, `${pointer}/location`),
            };
        }
        catch {
            diagnostics.push({
                code: 'invalid-identity-record',
                path: `/records/${index}`,
                message: 'identity record must contain exact own enumerable data properties',
            });
            continue;
        }
        const idKey = `${parsed.namespace}\0${parsed.id}`;
        const digestKey = `${parsed.namespace}\0${parsed.digest}`;
        const priorId = byId.get(idKey);
        if (priorId) {
            diagnostics.push({
                code: priorId.digest === parsed.digest
                    ? 'duplicate-audit-identity'
                    : 'audit-identity-collision',
                path: parsed.location,
                message: priorId.digest === parsed.digest
                    ? `duplicates ${priorId.location}`
                    : `collides with ${priorId.location}`,
            });
        }
        else {
            byId.set(idKey, parsed);
        }
        const priorDigest = byDigest.get(digestKey);
        if (priorDigest && priorDigest.id !== parsed.id) {
            diagnostics.push({
                code: 'audit-identity-digest-alias',
                path: parsed.location,
                message: `digest aliases ${priorDigest.id} at ${priorDigest.location}`,
            });
        }
        else if (!priorDigest) {
            byDigest.set(digestKey, parsed);
        }
    }
    return diagnostics;
}
function parseDecisionLedger(value, pointer = '') {
    const ledger = dataRecordAt(value, pointer || '/');
    exactKeys(ledger, ['formatVersion', 'format', 'domain', 'slug', 'entries'], [], pointer || '');
    if (ledger.formatVersion !== 1) {
        invalid('invalid-format-version', `${pointer}/formatVersion`, 'must equal 1');
    }
    if (ledger.format !== 'atlas-audit-decisions-v1') {
        invalid('invalid-format', `${pointer}/format`, 'must equal atlas-audit-decisions-v1');
    }
    if (ledger.domain !== 'security') {
        invalid('invalid-domain', `${pointer}/domain`, 'must equal security');
    }
    const slug = slugAt(ledger.slug, `${pointer}/slug`);
    const candidates = dataArrayAt(ledger.entries, `${pointer}/entries`);
    if (candidates.length === 0 || candidates.length > LEDGER_ENTRY_LIMIT) {
        invalid('invalid-chain', `${pointer}/entries`, `must contain between 1 and ${LEDGER_ENTRY_LIMIT} entries`);
    }
    const entries = [];
    const identityRecords = [];
    let previousEntryDigest = null;
    for (const [index, candidate] of candidates.entries()) {
        const entryPointer = `${pointer}/entries/${index}`;
        const entry = dataRecordAt(candidate, entryPointer);
        exactKeys(entry, ['eventId', 'previousEntryDigest', 'event', 'entryDigest'], [], entryPointer);
        const eventId = patternAt(entry.eventId, EVENT_ID_RE, `${entryPointer}/eventId`, 'must be an Atlas decision event ID');
        const storedPrevious = entry.previousEntryDigest === null
            ? null
            : sha256At(entry.previousEntryDigest, `${entryPointer}/previousEntryDigest`);
        if (storedPrevious !== previousEntryDigest) {
            invalid('decision-chain-mismatch', `${entryPointer}/previousEntryDigest`, index === 0
                ? 'genesis must use null'
                : 'must equal the prior entry digest');
        }
        const event = parseStoredDecisionEvent(entry.event, `${entryPointer}/event`);
        if (event.eventId !== eventId) {
            invalid('decision-entry-event-mismatch', `${entryPointer}/eventId`, 'must equal event.eventId');
        }
        if ('decisionLedger' in event &&
            event.decisionLedger !== slug) {
            invalid('decision-ledger-home-mismatch', `${entryPointer}/event/decisionLedger`, 'must equal the containing ledger slug');
        }
        const entryDigest = sha256At(entry.entryDigest, `${entryPointer}/entryDigest`);
        const core = {
            eventId,
            previousEntryDigest: storedPrevious,
            event,
        };
        if (entryDigest !== computeAuditDecisionEntryDigest(core)) {
            invalid('decision-entry-digest-mismatch', `${entryPointer}/entryDigest`, 'does not seal the canonical entry');
        }
        const parsedEntry = {
            ...core,
            entryDigest,
        };
        entries.push(parsedEntry);
        identityRecords.push({
            namespace: 'decision-event',
            id: eventId,
            digest: sha256Canonical(event),
            location: `${entryPointer}/event`,
        }, {
            namespace: 'decision-entry',
            id: entryDigest,
            digest: sha256Canonical(core),
            location: entryPointer,
        });
        previousEntryDigest = entryDigest;
    }
    const identityDiagnostics = validateUniqueAuditIdentityRecords(identityRecords);
    if (identityDiagnostics.length > 0) {
        const first = identityDiagnostics[0];
        invalid(first.code, first.path, first.message);
    }
    return {
        formatVersion: 1,
        format: 'atlas-audit-decisions-v1',
        domain: 'security',
        slug,
        entries,
    };
}
export function prepareAuditDecisionAppend(ledger, domain, slug, event) {
    if (domain !== 'security') {
        throw new Error('decision ledger domain must equal security');
    }
    const parsedSlug = slugAt(slug, '/slug');
    const parsedEvent = parseDecisionEventInput(event, '/event');
    if ('decisionLedger' in parsedEvent &&
        parsedEvent.decisionLedger !== parsedSlug) {
        throw new Error('decision event home does not match the ledger slug');
    }
    const eventId = computeAuditDecisionEventId(parsedEvent);
    const storedEvent = { ...parsedEvent, eventId };
    const parsedLedger = ledger === null
        ? null
        : parseDecisionLedger(ledger, '/ledger');
    if (parsedLedger &&
        (parsedLedger.domain !== domain ||
            parsedLedger.slug !== parsedSlug)) {
        throw new Error('existing decision ledger domain or slug does not match');
    }
    const existingEntry = parsedLedger?.entries.find((entry) => entry.eventId === eventId);
    if (existingEntry) {
        if (canonicalJson(existingEntry.event) !== canonicalJson(storedEvent)) {
            throw new Error('same decision event ID collides with different content');
        }
        return {
            ledger: parsedLedger,
            event: existingEntry.event,
            entry: existingEntry,
            bytes: `${canonicalJson(parsedLedger)}\n`,
            status: 'already-present',
        };
    }
    const previousEntryDigest = parsedLedger?.entries.at(-1)?.entryDigest ?? null;
    const entryCore = {
        eventId,
        previousEntryDigest,
        event: storedEvent,
    };
    const entry = {
        ...entryCore,
        entryDigest: computeAuditDecisionEntryDigest(entryCore),
    };
    const nextLedger = {
        formatVersion: 1,
        format: 'atlas-audit-decisions-v1',
        domain,
        slug: parsedSlug,
        entries: [...(parsedLedger?.entries ?? []), entry],
    };
    const validatedNextLedger = parseDecisionLedger(nextLedger, '/ledger');
    return {
        ledger: validatedNextLedger,
        event: storedEvent,
        entry,
        bytes: `${canonicalJson(validatedNextLedger)}\n`,
        status: 'append',
    };
}
export function loadAuditDecisionLedgers(root) {
    const ledgers = [];
    const diagnostics = [];
    let entries;
    try {
        entries = listBoundedAuditDirectory(root, '.atlas/audit-decisions', DECISION_LEDGER_COUNT_LIMIT + 1);
    }
    catch (error) {
        if (error instanceof Error &&
            error.message.startsWith(`audit directory exceeds the ${DECISION_LEDGER_COUNT_LIMIT + 1}-entry limit:`)) {
            return {
                ledgers,
                diagnostics: [{
                        code: 'audit-decision-portfolio-ledger-limit',
                        path: '.atlas/audit-decisions',
                        message: `decision portfolio exceeds the ${DECISION_LEDGER_COUNT_LIMIT}-ledger limit`,
                    }],
            };
        }
        return {
            ledgers,
            diagnostics: [{
                    code: 'audit-decision-directory-invalid',
                    path: '.atlas/audit-decisions',
                    message: error instanceof Error ? error.message : String(error),
                }],
        };
    }
    if (entries.length > DECISION_LEDGER_COUNT_LIMIT) {
        return {
            ledgers: [],
            diagnostics: [{
                    code: 'audit-decision-portfolio-ledger-limit',
                    path: '.atlas/audit-decisions',
                    message: `decision portfolio exceeds the ${DECISION_LEDGER_COUNT_LIMIT}-ledger limit`,
                }],
        };
    }
    const identityRecords = [];
    let rawBytes = 0;
    for (const name of entries) {
        const repoPath = `.atlas/audit-decisions/${name}`;
        if (!name.endsWith('.json')) {
            diagnostics.push({
                code: 'audit-decision-unexpected-entry',
                path: repoPath,
                message: 'decision ledger directory entries must be JSON files',
            });
            continue;
        }
        const expectedSlug = name.slice(0, -'.json'.length);
        const remainingBytes = DECISION_PORTFOLIO_BYTE_LIMIT - rawBytes;
        if (remainingBytes <= 0) {
            return {
                ledgers: [],
                diagnostics: [{
                        code: 'audit-decision-portfolio-byte-limit',
                        path: '.atlas/audit-decisions',
                        message: `decision portfolio exceeds the ${DECISION_PORTFOLIO_BYTE_LIMIT}-byte cumulative raw-byte limit`,
                    }],
            };
        }
        const readLimit = Math.min(DECISION_LEDGER_BYTE_LIMIT, remainingBytes);
        try {
            const bytes = readBoundedAuditBytes(root, repoPath, readLimit);
            rawBytes += bytes.byteLength;
            slugAt(expectedSlug, repoPath);
            const ledger = parseDecisionLedger(parseBoundedAuditJsonBytes(bytes, readLimit, repoPath));
            if (ledger.slug !== expectedSlug) {
                throw new Error('decision ledger filename and envelope slug do not match');
            }
            ledgers.push(ledger);
            for (const [index, entry] of ledger.entries.entries()) {
                identityRecords.push({
                    namespace: 'decision-event',
                    id: entry.eventId,
                    digest: sha256Canonical(entry.event),
                    location: `${repoPath}/entries/${index}/event`,
                }, {
                    namespace: 'decision-entry',
                    id: entry.entryDigest,
                    digest: sha256Canonical({
                        eventId: entry.eventId,
                        previousEntryDigest: entry.previousEntryDigest,
                        event: entry.event,
                    }),
                    location: `${repoPath}/entries/${index}`,
                });
            }
        }
        catch (error) {
            if (remainingBytes < DECISION_LEDGER_BYTE_LIMIT &&
                error instanceof Error &&
                error.message.startsWith(`audit file exceeds the ${remainingBytes}-byte limit:`)) {
                return {
                    ledgers: [],
                    diagnostics: [{
                            code: 'audit-decision-portfolio-byte-limit',
                            path: '.atlas/audit-decisions',
                            message: `decision portfolio exceeds the ${DECISION_PORTFOLIO_BYTE_LIMIT}-byte cumulative raw-byte limit`,
                        }],
                };
            }
            const row = diagnostic(error);
            diagnostics.push({
                ...row,
                path: row.path
                    ? `${repoPath}${row.path}`
                    : repoPath,
            });
        }
    }
    diagnostics.push(...validateUniqueAuditIdentityRecords(identityRecords));
    ledgers.sort((left, right) => utf16Compare(left.slug, right.slug));
    return { ledgers, diagnostics };
}
export function appendAuditDecision(root, slug, event) {
    return withAuditLock(root, () => {
        const normalizedSlug = slugAt(slug, '/slug');
        const repoPath = `.atlas/audit-decisions/${normalizedSlug}.json`;
        const portfolio = loadAuditDecisionLedgers(root);
        if (portfolio.diagnostics.length > 0) {
            throw new Error(`decision portfolio is invalid: ${portfolio.diagnostics.map((row) => `${row.code} ${row.path} ${row.message}`).join('; ')}`);
        }
        let names;
        try {
            names = listBoundedAuditDirectory(root, '.atlas/audit-decisions', DECISION_LEDGER_COUNT_LIMIT + 1);
        }
        catch (error) {
            if (error instanceof Error &&
                error.message.startsWith(`audit directory exceeds the ${DECISION_LEDGER_COUNT_LIMIT + 1}-entry limit:`)) {
                throw new Error(`decision portfolio exceeds the ${DECISION_LEDGER_COUNT_LIMIT}-ledger limit`);
            }
            throw error;
        }
        const targetName = `${normalizedSlug}.json`;
        let rawPortfolioBytes = 0;
        let existingBytes = null;
        for (const name of names) {
            const remainingBytes = DECISION_PORTFOLIO_BYTE_LIMIT - rawPortfolioBytes;
            if (remainingBytes <= 0) {
                throw new Error(`decision portfolio exceeds the ${DECISION_PORTFOLIO_BYTE_LIMIT}-byte cumulative raw-byte limit`);
            }
            const bytes = readBoundedAuditBytes(root, `.atlas/audit-decisions/${name}`, Math.min(DECISION_LEDGER_BYTE_LIMIT, remainingBytes));
            rawPortfolioBytes += bytes.byteLength;
            if (name === targetName)
                existingBytes = bytes;
        }
        const existingLedger = existingBytes === null
            ? null
            : parseDecisionLedger(parseBoundedAuditJsonBytes(existingBytes, DECISION_LEDGER_BYTE_LIMIT, repoPath));
        const plan = prepareAuditDecisionAppend(existingLedger, 'security', normalizedSlug, event);
        const planByteLength = Buffer.byteLength(plan.bytes, 'utf8');
        if (planByteLength > DECISION_LEDGER_BYTE_LIMIT) {
            throw new Error(`decision ledger exceeds the ${DECISION_LEDGER_BYTE_LIMIT}-byte limit`);
        }
        const nextLedgerCount = names.length + (existingBytes === null ? 1 : 0);
        if (nextLedgerCount > DECISION_LEDGER_COUNT_LIMIT) {
            throw new Error(`decision portfolio exceeds the ${DECISION_LEDGER_COUNT_LIMIT}-ledger limit`);
        }
        const nextPortfolioBytes = rawPortfolioBytes -
            (existingBytes?.byteLength ?? 0) +
            planByteLength;
        if (nextPortfolioBytes > DECISION_PORTFOLIO_BYTE_LIMIT) {
            throw new Error(`decision portfolio exceeds the ${DECISION_PORTFOLIO_BYTE_LIMIT}-byte cumulative raw-byte limit`);
        }
        if (plan.status === 'append') {
            const identityRecords = [];
            for (const ledger of portfolio.ledgers) {
                const ledgerPath = `.atlas/audit-decisions/${ledger.slug}.json`;
                for (const [index, entry] of ledger.entries.entries()) {
                    identityRecords.push({
                        namespace: 'decision-event',
                        id: entry.eventId,
                        digest: sha256Canonical(entry.event),
                        location: `${ledgerPath}/entries/${index}/event`,
                    }, {
                        namespace: 'decision-entry',
                        id: entry.entryDigest,
                        digest: sha256Canonical({
                            eventId: entry.eventId,
                            previousEntryDigest: entry.previousEntryDigest,
                            event: entry.event,
                        }),
                        location: `${ledgerPath}/entries/${index}`,
                    });
                }
            }
            identityRecords.push({
                namespace: 'decision-event',
                id: plan.entry.eventId,
                digest: sha256Canonical(plan.entry.event),
                location: `${repoPath}/entries/${plan.ledger.entries.length - 1}/event`,
            }, {
                namespace: 'decision-entry',
                id: plan.entry.entryDigest,
                digest: sha256Canonical({
                    eventId: plan.entry.eventId,
                    previousEntryDigest: plan.entry.previousEntryDigest,
                    event: plan.entry.event,
                }),
                location: `${repoPath}/entries/${plan.ledger.entries.length - 1}`,
            });
            const identityDiagnostics = validateUniqueAuditIdentityRecords(identityRecords);
            if (identityDiagnostics.length > 0) {
                throw new Error(`decision portfolio global identity validation failed: ${identityDiagnostics.map((row) => `${row.code} ${row.path} ${row.message}`).join('; ')}`);
            }
        }
        const rawMatches = existingBytes !== null &&
            Buffer.from(existingBytes).equals(Buffer.from(plan.bytes, 'utf8'));
        if (plan.status === 'append' || !rawMatches) {
            atomicWriteAuditFile(root, repoPath, plan.bytes);
        }
        return {
            path: repoPath,
            eventId: plan.event.eventId,
            entryDigest: plan.entry.entryDigest,
            status: plan.status === 'append' ? 'appended' : 'already-present',
        };
    });
}
export function parseAuditDecisionPolicy(value, fullPolicyDigest) {
    const policyDigest = sha256At(fullPolicyDigest, '/fullPolicyDigest');
    const policy = dataRecordAt(value, '/securityDecisions');
    exactKeys(policy, [
        'requireDisposition',
        'blockingActions',
        'drift',
        'expiry',
        'remediation',
        'falsePositive',
        'superseded',
        'retirement',
        'acceptedRulesets',
    ], [], '/securityDecisions');
    const parseEnumSet = (candidate, pointer, allowed, nonempty = false) => {
        const rows = dataArrayAt(candidate, pointer).map((row, index) => enumAt(row, allowed, `${pointer}/${index}`));
        if (nonempty && rows.length === 0) {
            invalid('empty-array', pointer, 'must be nonempty');
        }
        if (new Set(rows).size !== rows.length) {
            invalid('duplicate', pointer, 'must contain unique values');
        }
        const selected = new Set(rows);
        return allowed.filter((value) => selected.has(value));
    };
    const drift = dataRecordAt(policy.drift, '/securityDecisions/drift');
    exactKeys(drift, ['findingBearing', 'clean', 'unknown'], [], '/securityDecisions/drift');
    const driftValue = (candidate, pointer) => enumAt(candidate, ['blocking', 'advisory'], pointer);
    const expiry = dataRecordAt(policy.expiry, '/securityDecisions/expiry');
    exactKeys(expiry, [
        'warningDays',
        'requiredFor',
        'acceptedRiskMaximumDays',
        'separateDesignMaximumDays',
        'falsePositiveMustBeNull',
        'severityOverrides',
    ], [], '/securityDecisions/expiry');
    const severityRows = dataArrayAt(expiry.severityOverrides, '/securityDecisions/expiry/severityOverrides');
    const seenSeverities = new Set();
    const severityOverrides = severityRows.map((candidate, index) => {
        const pointer = `/securityDecisions/expiry/severityOverrides/${index}`;
        const override = dataRecordAt(candidate, pointer);
        exactKeys(override, [
            'severities',
            'maximumDays',
            'minimumIndependentReviews',
            'reviewEvidenceRequired',
        ], [], pointer);
        const severities = parseEnumSet(override.severities, `${pointer}/severities`, [
            'critical',
            'high',
            'medium',
            'low',
            'informational',
        ], true);
        for (const severity of severities) {
            if (seenSeverities.has(severity)) {
                invalid('duplicate-policy-severity', `${pointer}/severities`, 'severity overrides must not overlap');
            }
            seenSeverities.add(severity);
        }
        return {
            severities: severities,
            maximumDays: safeIntegerAt(override.maximumDays, `${pointer}/maximumDays`, 1),
            minimumIndependentReviews: safeIntegerAt(override.minimumIndependentReviews, `${pointer}/minimumIndependentReviews`),
            reviewEvidenceRequired: booleanAt(override.reviewEvidenceRequired, `${pointer}/reviewEvidenceRequired`),
        };
    });
    const remediation = dataRecordAt(policy.remediation, '/securityDecisions/remediation');
    exactKeys(remediation, [
        'fixBlobRequired',
        'postFixProofRequired',
        'passingRegressionRequired',
        'allowedRegressionKinds',
    ], [], '/securityDecisions/remediation');
    const falsePositive = dataRecordAt(policy.falsePositive, '/securityDecisions/falsePositive');
    exactKeys(falsePositive, ['reviewedBlobRequired', 'sourceEvidenceRequired'], [], '/securityDecisions/falsePositive');
    const superseded = dataRecordAt(policy.superseded, '/securityDecisions/superseded');
    exactKeys(superseded, [
        'replacementOrDeletionProofRequired',
        'existingPathRequiresCurrentReview',
    ], [], '/securityDecisions/superseded');
    const retirement = dataRecordAt(policy.retirement, '/securityDecisions/retirement');
    exactKeys(retirement, ['historyProofRequired', 'allowedReasons'], [], '/securityDecisions/retirement');
    const parsed = {
        requireDisposition: booleanAt(policy.requireDisposition, '/securityDecisions/requireDisposition'),
        blockingActions: parseEnumSet(policy.blockingActions, '/securityDecisions/blockingActions', [
            'open',
            'remediated',
            'accepted-risk',
            'separate-design',
            'false-positive',
            'superseded',
            'reopened',
        ]),
        drift: {
            findingBearing: driftValue(drift.findingBearing, '/securityDecisions/drift/findingBearing'),
            clean: driftValue(drift.clean, '/securityDecisions/drift/clean'),
            unknown: driftValue(drift.unknown, '/securityDecisions/drift/unknown'),
        },
        expiry: {
            warningDays: safeIntegerAt(expiry.warningDays, '/securityDecisions/expiry/warningDays'),
            requiredFor: parseEnumSet(expiry.requiredFor, '/securityDecisions/expiry/requiredFor', ['accepted-risk', 'separate-design']),
            acceptedRiskMaximumDays: safeIntegerAt(expiry.acceptedRiskMaximumDays, '/securityDecisions/expiry/acceptedRiskMaximumDays', 1),
            separateDesignMaximumDays: safeIntegerAt(expiry.separateDesignMaximumDays, '/securityDecisions/expiry/separateDesignMaximumDays', 1),
            falsePositiveMustBeNull: booleanAt(expiry.falsePositiveMustBeNull, '/securityDecisions/expiry/falsePositiveMustBeNull'),
            severityOverrides,
        },
        remediation: {
            fixBlobRequired: booleanAt(remediation.fixBlobRequired, '/securityDecisions/remediation/fixBlobRequired'),
            postFixProofRequired: booleanAt(remediation.postFixProofRequired, '/securityDecisions/remediation/postFixProofRequired'),
            passingRegressionRequired: booleanAt(remediation.passingRegressionRequired, '/securityDecisions/remediation/passingRegressionRequired'),
            allowedRegressionKinds: parseEnumSet(remediation.allowedRegressionKinds, '/securityDecisions/remediation/allowedRegressionKinds', ['test', 'guardrail', 'check']),
        },
        falsePositive: {
            reviewedBlobRequired: booleanAt(falsePositive.reviewedBlobRequired, '/securityDecisions/falsePositive/reviewedBlobRequired'),
            sourceEvidenceRequired: booleanAt(falsePositive.sourceEvidenceRequired, '/securityDecisions/falsePositive/sourceEvidenceRequired'),
        },
        superseded: {
            replacementOrDeletionProofRequired: booleanAt(superseded.replacementOrDeletionProofRequired, '/securityDecisions/superseded/replacementOrDeletionProofRequired'),
            existingPathRequiresCurrentReview: booleanAt(superseded.existingPathRequiresCurrentReview, '/securityDecisions/superseded/existingPathRequiresCurrentReview'),
        },
        retirement: {
            historyProofRequired: booleanAt(retirement.historyProofRequired, '/securityDecisions/retirement/historyProofRequired'),
            allowedReasons: parseEnumSet(retirement.allowedReasons, '/securityDecisions/retirement/allowedReasons', [
                'deleted',
                'moved',
                'superseded',
                'staged-deletion',
                'uncommitted-snapshot-absent',
            ]),
        },
        acceptedRulesets: sortedUniqueStringsAt(policy.acceptedRulesets, '/securityDecisions/acceptedRulesets', (candidate, pointer) => patternAt(candidate, SOURCE_NAME_RE, pointer, 'must be a canonical ruleset ID')),
    };
    return { ...parsed, policyDigest };
}
function snapshotCanonicalRows(value, subject, pointer, limit, options = {}) {
    let candidates;
    try {
        candidates = dataArrayAt(value, pointer, limit);
    }
    catch (error) {
        throw new Error(`${subject} must be a dense bounded data-only array: ${error instanceof Error ? error.message : String(error)}`);
    }
    const rows = [];
    let cumulativeBytes = 0;
    for (const [index, candidate] of candidates.entries()) {
        let canonical;
        try {
            canonical = canonicalJson(candidate);
        }
        catch (error) {
            throw new Error(`${subject} row ${index} must be bounded data-only canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
        }
        const byteLength = Buffer.byteLength(canonical, 'utf8') +
            (options.countTrailingNewline ? 1 : 0);
        if (options.perRowByteLimit !== undefined &&
            byteLength > options.perRowByteLimit) {
            throw new Error(`${subject} row ${index} exceeds the ${options.perRowByteLimit}-byte limit`);
        }
        if (options.cumulativeByteLimit !== undefined &&
            byteLength > options.cumulativeByteLimit - cumulativeBytes) {
            throw new Error(`${subject} exceed the ${options.cumulativeByteLimit}-byte cumulative canonical-byte limit`);
        }
        cumulativeBytes += byteLength;
        const row = JSON.parse(canonical);
        rows.push(row);
        options.onSnapshot?.(row, index, byteLength);
    }
    return rows;
}
export function validateAuditDecisionLedgerCanonicalByteBudget(cumulativeCanonicalBytes, ledgerCanonicalBytes) {
    if (!Number.isSafeInteger(cumulativeCanonicalBytes) ||
        cumulativeCanonicalBytes < 0 ||
        !Number.isSafeInteger(ledgerCanonicalBytes) ||
        ledgerCanonicalBytes <= 0) {
        throw new Error('decision ledger canonical byte counts must be positive safe integers, except the cumulative count may be zero');
    }
    if (ledgerCanonicalBytes > DECISION_LEDGER_BYTE_LIMIT) {
        throw new Error(`decision ledger canonical bytes including its trailing newline exceed the ${DECISION_LEDGER_BYTE_LIMIT}-byte per-ledger limit`);
    }
    if (cumulativeCanonicalBytes > DECISION_PORTFOLIO_BYTE_LIMIT ||
        ledgerCanonicalBytes >
            DECISION_PORTFOLIO_BYTE_LIMIT - cumulativeCanonicalBytes) {
        throw new Error(`decision ledger portfolio canonical bytes exceed the ${DECISION_PORTFOLIO_BYTE_LIMIT}-byte cumulative limit`);
    }
    return cumulativeCanonicalBytes + ledgerCanonicalBytes;
}
function preflightDecisionLedgerResources(candidates) {
    const entryGroups = [];
    const canonicalValues = new Map();
    let canonicalByteCount = 0;
    let entryCount = 0;
    for (const candidate of candidates) {
        let ledgerValue = candidate.value;
        let canonicalByteLength = candidate.canonicalByteLength;
        if (canonicalByteLength === undefined) {
            let canonical;
            try {
                canonical = canonicalJson(candidate.value);
            }
            catch (error) {
                invalid('decision-index-resource-limit', candidate.pointer, `decision ledger must be bounded data-only canonical JSON: ${error instanceof Error ? error.message : String(error)}`);
            }
            canonicalByteLength = Buffer.byteLength(canonical, 'utf8') + 1;
            ledgerValue = JSON.parse(canonical);
        }
        try {
            canonicalByteCount =
                validateAuditDecisionLedgerCanonicalByteBudget(canonicalByteCount, canonicalByteLength);
        }
        catch (error) {
            invalid('decision-index-resource-limit', candidate.pointer, error instanceof Error ? error.message : String(error));
        }
        canonicalValues.set(candidate.pointer, ledgerValue);
        const ledger = dataRecordAt(ledgerValue, candidate.pointer);
        exactKeys(ledger, ['formatVersion', 'format', 'domain', 'slug', 'entries'], [], candidate.pointer);
        const entriesPointer = `${candidate.pointer}/entries`;
        const entries = dataArrayAt(ledger.entries, entriesPointer, LEDGER_ENTRY_LIMIT);
        if (entries.length > DECISION_INDEX_ITEM_LIMIT - entryCount) {
            invalid('decision-index-resource-limit', entriesPointer, `aggregate decision ledger entries exceed the ${DECISION_INDEX_ITEM_LIMIT}-item limit`);
        }
        entryCount += entries.length;
        entryGroups.push({ entries, pointer: entriesPointer });
    }
    let reconciliationEventCount = 0;
    for (const group of entryGroups) {
        for (const [entryIndex, candidate] of group.entries.entries()) {
            const entryPointer = `${group.pointer}/${entryIndex}`;
            const entry = dataRecordAt(candidate, entryPointer);
            const event = dataRecordAt(entry.event, `${entryPointer}/event`);
            if (event.type !== 'finding-reconciliation')
                continue;
            if (reconciliationEventCount >= RECONCILIATION_EVENT_LIMIT) {
                invalid('decision-index-resource-limit', `${entryPointer}/event/type`, `reconciliation events exceed the ${RECONCILIATION_EVENT_LIMIT}-event limit`);
            }
            reconciliationEventCount += 1;
        }
    }
    return {
        entryCount,
        reconciliationEventCount,
        canonicalByteCount,
        canonicalValues,
    };
}
function confirmedReconciliationEdgeCount(event) {
    return event.outcome === 'equivalent' && event.confidence === 'high'
        ? event.beforeOccurrenceIds.length * event.afterOccurrenceIds.length
        : 0;
}
export function validateAuditDecisionReconciliationEdgeBudget(activeConfirmedEdgeCount, beforeOccurrenceCount, afterOccurrenceCount) {
    if (!Number.isSafeInteger(activeConfirmedEdgeCount) ||
        activeConfirmedEdgeCount < 0 ||
        !Number.isSafeInteger(beforeOccurrenceCount) ||
        beforeOccurrenceCount <= 0 ||
        !Number.isSafeInteger(afterOccurrenceCount) ||
        afterOccurrenceCount <= 0) {
        throw new Error('active confirmed reconciliation edge counts must be positive safe integers, except the active count may be zero');
    }
    const remaining = ACTIVE_CONFIRMED_EDGE_LIMIT - activeConfirmedEdgeCount;
    if (remaining < 0 ||
        afterOccurrenceCount >
            Math.floor(remaining / beforeOccurrenceCount)) {
        throw new Error(`active confirmed reconciliation edges exceed the ${ACTIVE_CONFIRMED_EDGE_LIMIT}-edge limit`);
    }
    return activeConfirmedEdgeCount +
        beforeOccurrenceCount * afterOccurrenceCount;
}
function requireConfirmedEdgeCapacity(activeConfirmedEdgeCount, event) {
    if (event.outcome !== 'equivalent' || event.confidence !== 'high') {
        return 0;
    }
    const beforeCount = event.beforeOccurrenceIds.length;
    const afterCount = event.afterOccurrenceIds.length;
    return validateAuditDecisionReconciliationEdgeBudget(activeConfirmedEdgeCount, beforeCount, afterCount) - activeConfirmedEdgeCount;
}
export function buildAuditDecisionIndex(currentLedgers, histories, decisionLedgers) {
    const currentRows = snapshotCanonicalRows(currentLedgers, 'current ledgers', '/currentLedgers', DECISION_INDEX_ITEM_LIMIT);
    const historyRows = snapshotCanonicalRows(histories, 'observation histories', '/histories', DECISION_INDEX_ITEM_LIMIT);
    const decisionLedgerResourceCandidates = [];
    const decisionRows = snapshotCanonicalRows(decisionLedgers, 'decision ledgers', '/decisionLedgers', DECISION_LEDGER_COUNT_LIMIT, {
        countTrailingNewline: true,
        onSnapshot(row, index, canonicalByteLength) {
            decisionLedgerResourceCandidates.push({
                value: row,
                pointer: `/decisionLedgers/${index}`,
                canonicalByteLength,
            });
        },
    });
    preflightDecisionLedgerResources(decisionLedgerResourceCandidates);
    const findings = new Map();
    const occurrences = new Map();
    const observations = new Map();
    const historyBySlug = new Map();
    const observationHistorySlug = new Map();
    const receiptOwners = new Map();
    const findingHistorySlugs = new Map();
    const observationDetails = (observation, slug) => {
        if (!OBSERVATION_ID_RE.test(observation.observationId)) {
            throw new Error(`history ${slug} contains an invalid observation ID`);
        }
        if (observations.has(observation.observationId)) {
            throw new Error(`observation identity collision: ${observation.observationId}`);
        }
        if (observations.size >= DECISION_INDEX_ITEM_LIMIT) {
            throw new Error(`decision index observations exceed the ${DECISION_INDEX_ITEM_LIMIT}-item limit`);
        }
        const producer = observation.producer;
        const producerRuleset = producer?.ruleset;
        let ruleset = null;
        if (producerRuleset &&
            typeof producerRuleset === 'object' &&
            !Array.isArray(producerRuleset)) {
            const candidate = producerRuleset;
            if (typeof candidate.id !== 'string' ||
                !SHA256_RE.test(String(candidate.digest))) {
                throw new Error(`observation ${observation.observationId} has an invalid ruleset`);
            }
            ruleset = {
                id: candidate.id,
                digest: candidate.digest,
            };
        }
        const target = observation.target;
        const revisionCandidate = [
            target?.revision,
            target?.headRevision,
            target?.sourceRevision,
            target?.sourceHeadRevision,
        ].find((candidate) => typeof candidate === 'string' && FULL_REVISION_RE.test(candidate));
        const repositoryRevision = typeof revisionCandidate === 'string' ? revisionCandidate : null;
        const scope = observation.scope;
        const exactByPath = new Map();
        const reviewedByPath = new Map();
        const reviewedBindings = [];
        if (Array.isArray(scope?.files)) {
            for (const candidate of scope.files) {
                if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) {
                    throw new Error(`observation ${observation.observationId} has an invalid scope receipt`);
                }
                const file = candidate;
                if (typeof file.path === 'string' &&
                    typeof file.blob === 'string' &&
                    GIT_BLOB_RE.test(file.blob) &&
                    (file.status === 'reviewed' || file.status === 'not-reviewed')) {
                    const parsedPath = repoPathAt(file.path, `/observations/${observation.observationId}/scope/files/path`);
                    if (exactByPath.has(parsedPath)) {
                        throw new Error(`observation ${observation.observationId} duplicates exact path ${parsedPath}`);
                    }
                    const binding = {
                        path: parsedPath,
                        blob: file.blob,
                    };
                    exactByPath.set(parsedPath, binding);
                    if (file.status === 'reviewed') {
                        reviewedByPath.set(parsedPath, binding);
                        reviewedBindings.push(binding);
                        const receiptKey = `${binding.path}\0${binding.blob}`;
                        const owners = receiptOwners.get(receiptKey) ?? new Set();
                        owners.add(slug);
                        receiptOwners.set(receiptKey, owners);
                    }
                }
            }
        }
        const inventoryBindings = [...exactByPath.values()].sort(compareBindings);
        reviewedBindings.sort(compareBindings);
        const occurrenceIds = [];
        if (!Array.isArray(observation.findings)) {
            throw new Error(`observation ${observation.observationId} findings must be an array`);
        }
        for (const findingCandidate of observation.findings) {
            if (occurrenceIds.length >= COLLECTION_LIMIT) {
                throw new Error(`observation ${observation.observationId} occurrence membership exceeds the ${COLLECTION_LIMIT}-item limit`);
            }
            const finding = findingCandidate;
            if (!FINDING_ID_RE.test(String(finding.findingId)) ||
                !OCCURRENCE_ID_RE.test(String(finding.occurrenceId))) {
                throw new Error(`observation ${observation.observationId} contains an invalid finding identity`);
            }
            const findingId = finding.findingId;
            const occurrenceId = finding.occurrenceId;
            const historySlugs = findingHistorySlugs.get(findingId) ??
                new Set();
            historySlugs.add(slug);
            findingHistorySlugs.set(findingId, historySlugs);
            const decisionLedger = slugAt(finding.decisionLedger, `/observations/${observation.observationId}/findings/decisionLedger`);
            const priorFinding = findings.get(findingId);
            if (priorFinding &&
                priorFinding.decisionLedger !== decisionLedger) {
                throw new Error(`finding ${findingId} has conflicting stable decision-ledger ownership`);
            }
            if (occurrences.has(occurrenceId)) {
                throw new Error(`occurrence identity collision: ${occurrenceId}`);
            }
            if (occurrences.size >= DECISION_INDEX_ITEM_LIMIT) {
                throw new Error(`decision index occurrences exceed the ${DECISION_INDEX_ITEM_LIMIT}-item limit`);
            }
            if (priorFinding &&
                priorFinding.occurrenceIds.length >= COLLECTION_LIMIT) {
                throw new Error(`finding ${findingId} occurrence membership exceeds the ${COLLECTION_LIMIT}-item limit`);
            }
            const locationPaths = [];
            if (!Array.isArray(finding.locations) || finding.locations.length === 0) {
                throw new Error(`finding ${findingId} has no authoritative locations`);
            }
            for (const locationCandidate of finding.locations) {
                if (!locationCandidate ||
                    typeof locationCandidate !== 'object' ||
                    Array.isArray(locationCandidate) ||
                    typeof locationCandidate.path !== 'string') {
                    throw new Error(`finding ${findingId} has an invalid location`);
                }
                locationPaths.push(repoPathAt(locationCandidate.path, `/observations/${observation.observationId}/findings/locations/path`));
            }
            const exactScope = scope?.identityBasis === 'exact-inventory';
            const bindings = [...new Set(locationPaths)]
                .map((locationPath) => exactByPath.get(locationPath))
                .filter((binding) => binding !== undefined)
                .sort(compareBindings);
            const findingReviewedBindings = [...new Set(locationPaths)]
                .map((locationPath) => reviewedByPath.get(locationPath))
                .filter((binding) => binding !== undefined)
                .sort(compareBindings);
            if (exactScope &&
                bindings.length !== new Set(locationPaths).size) {
                throw new Error(`finding ${findingId} locations do not resolve to exact reviewed path/blob bindings`);
            }
            const severityCandidate = finding.severity?.level;
            const severity = enumAt(severityCandidate, [
                'critical',
                'high',
                'medium',
                'low',
                'informational',
            ], `/observations/${observation.observationId}/findings/severity`);
            occurrences.set(occurrenceId, {
                occurrenceId,
                findingId,
                observationId: observation.observationId,
                decisionLedger,
                bindings,
                reviewedBindings: findingReviewedBindings,
                closureEligible: exactScope &&
                    bindings.length > 0 &&
                    findingReviewedBindings.length === bindings.length &&
                    ruleset !== null,
                ruleset,
                repositoryRevision,
                severity,
                authoritative: false,
            });
            occurrenceIds.push(occurrenceId);
            if (priorFinding) {
                priorFinding.occurrenceIds.push(occurrenceId);
            }
            else {
                if (findings.size >= DECISION_INDEX_ITEM_LIMIT) {
                    throw new Error(`decision index findings exceed the ${DECISION_INDEX_ITEM_LIMIT}-item limit`);
                }
                findings.set(findingId, {
                    findingId,
                    decisionLedger,
                    occurrenceIds: [occurrenceId],
                    currentOccurrenceIds: [],
                });
            }
        }
        occurrenceIds.sort(utf16Compare);
        return {
            occurrenceIds,
            inventoryBindings,
            reviewedBindings,
            ruleset,
            repositoryRevision,
        };
    };
    for (const historyCandidate of historyRows) {
        const history = historyCandidate;
        if (history.formatVersion !== 1 ||
            history.format !== 'atlas-audit-history-v1' ||
            history.domain !== 'security') {
            throw new Error('invalid observation history envelope');
        }
        const slug = slugAt(history.slug, '/history/slug');
        if (historyBySlug.has(slug)) {
            throw new Error(`duplicate observation history slug: ${slug}`);
        }
        if (!Array.isArray(history.entries) || history.entries.length === 0) {
            throw new Error(`observation history ${slug} must be nonempty`);
        }
        let previousEntryDigest = null;
        for (const [index, entry] of history.entries.entries()) {
            if (entry.previousEntryDigest !== previousEntryDigest) {
                throw new Error(`observation history ${slug} entry ${index} breaks the chain`);
            }
            if (entry.observationId !== entry.observation.observationId ||
                entry.observationDigest !== sha256Canonical(entry.observation)) {
                throw new Error(`observation history ${slug} entry ${index} has a mismatched observation`);
            }
            const expectedEntryDigest = sha256Canonical({
                observationId: entry.observationId,
                observationDigest: entry.observationDigest,
                previousEntryDigest: entry.previousEntryDigest,
                observation: entry.observation,
            });
            if (entry.entryDigest !== expectedEntryDigest) {
                throw new Error(`observation history ${slug} entry ${index} has a mismatched digest`);
            }
            const details = observationDetails(entry.observation, slug);
            observations.set(entry.observationId, {
                observationId: entry.observationId,
                slug,
                historyIndex: index,
                ...details,
                authoritative: false,
                publicationState: 'historical',
            });
            observationHistorySlug.set(entry.observationId, slug);
            previousEntryDigest = entry.entryDigest;
        }
        historyBySlug.set(slug, history);
    }
    const currentBySlug = new Map();
    for (const current of currentRows) {
        if (current.formatVersion !== 3 ||
            current.format !== 'atlas-audit-v3' ||
            current.domain !== 'security') {
            throw new Error('invalid current audit wrapper');
        }
        const slug = slugAt(current.slug, '/current/slug');
        if (currentBySlug.has(slug)) {
            throw new Error(`duplicate current audit slug: ${slug}`);
        }
        const history = historyBySlug.get(slug);
        if (!history) {
            throw new Error(`current wrapper ${slug} has no verified history`);
        }
        if (current.history.path !== `.atlas/audit-history/${slug}.json`) {
            throw new Error(`current wrapper ${slug} has a mismatched history path`);
        }
        const index = history.entries.findIndex((entry) => entry.entryDigest === current.history.entryDigest);
        if (index < 0) {
            throw new Error(`current pointer for ${slug} is missing from history`);
        }
        const entry = history.entries[index];
        if (current.history.observationId !== entry.observationId ||
            current.currentDigest !== entry.observationDigest ||
            canonicalJson(current.current) !== canonicalJson(entry.observation)) {
            throw new Error(`current pointer for ${slug} differs from its history entry`);
        }
        const trailing = history.entries.length - index - 1;
        if (trailing > 1) {
            throw new Error(`current pointer for ${slug} has more than one trailing history-ahead entry`);
        }
        const indexedObservation = observations.get(entry.observationId);
        indexedObservation.authoritative = true;
        indexedObservation.publicationState = 'current';
        for (const occurrenceId of indexedObservation.occurrenceIds) {
            const occurrence = occurrences.get(occurrenceId);
            occurrence.authoritative = true;
            const finding = findings.get(occurrence.findingId);
            if (finding.currentOccurrenceIds.length >= COLLECTION_LIMIT) {
                throw new Error(`finding ${finding.findingId} current occurrence membership exceeds the ${COLLECTION_LIMIT}-item limit`);
            }
            finding.currentOccurrenceIds.push(occurrenceId);
        }
        for (const trailingEntry of history.entries.slice(index + 1)) {
            observations.get(trailingEntry.observationId).publicationState = 'history-ahead';
        }
        currentBySlug.set(slug, current);
    }
    for (const [slug, history] of historyBySlug) {
        if (!currentBySlug.has(slug) && history.entries.length !== 1) {
            throw new Error(`history ${slug} without current may contain only one genesis history-ahead entry`);
        }
        if (!currentBySlug.has(slug)) {
            observations.get(history.entries[0].observationId).publicationState = 'history-ahead';
        }
    }
    for (const finding of findings.values()) {
        const hasAnyPublishedOccurrence = finding.occurrenceIds.some((occurrenceId) => {
            const occurrence = occurrences.get(occurrenceId);
            return observations.get(occurrence.observationId).publicationState !== 'history-ahead';
        });
        const hasPublishedHome = finding.occurrenceIds.some((occurrenceId) => {
            const occurrence = occurrences.get(occurrenceId);
            const observation = observations.get(occurrence.observationId);
            return observation.slug === finding.decisionLedger &&
                observation.publicationState !== 'history-ahead';
        });
        if (!findingHistorySlugs.get(finding.findingId)?.has(finding.decisionLedger) ||
            (hasAnyPublishedOccurrence && !hasPublishedHome)) {
            throw new Error(`finding ${finding.findingId} names a decision home with no published historical occurrence`);
        }
    }
    for (const finding of findings.values()) {
        finding.occurrenceIds.sort(utf16Compare);
        finding.currentOccurrenceIds.sort(utf16Compare);
    }
    const parsedDecisionLedgers = new Map();
    const events = new Map();
    const retirementEvents = [];
    const reconciliationEvents = [];
    const aliasEvents = [];
    const aliasOwners = new Map();
    const activeStaged = new Map();
    const terminalRetirements = new Map();
    const activeFindingClosures = new Map();
    const activeReconciliations = new Map();
    const comparisonEndpointOwners = new Map();
    const confirmedBeforeOwners = new Map();
    const confirmedAfterOwners = new Map();
    const confirmedAdjacency = new Map();
    let activeConfirmedEdgeCount = 0;
    const isConfirmedReconciliation = (event) => event.outcome === 'equivalent' && event.confidence === 'high';
    const removeActiveReconciliation = (event) => {
        activeReconciliations.delete(event.eventId);
        const comparisonOwners = comparisonEndpointOwners.get(event.comparisonId);
        if (comparisonOwners) {
            for (const occurrenceId of [
                ...event.beforeOccurrenceIds,
                ...event.afterOccurrenceIds,
            ]) {
                if (comparisonOwners.get(occurrenceId) === event.eventId) {
                    comparisonOwners.delete(occurrenceId);
                }
            }
            if (comparisonOwners.size === 0) {
                comparisonEndpointOwners.delete(event.comparisonId);
            }
        }
        if (!isConfirmedReconciliation(event))
            return;
        activeConfirmedEdgeCount -= confirmedReconciliationEdgeCount(event);
        for (const occurrenceId of event.beforeOccurrenceIds) {
            if (confirmedBeforeOwners.get(occurrenceId) === event.eventId) {
                confirmedBeforeOwners.delete(occurrenceId);
            }
            const targets = confirmedAdjacency.get(occurrenceId);
            if (!targets)
                continue;
            for (const afterOccurrenceId of event.afterOccurrenceIds) {
                const references = targets.get(afterOccurrenceId);
                if (references === undefined)
                    continue;
                if (references === 1) {
                    targets.delete(afterOccurrenceId);
                }
                else {
                    targets.set(afterOccurrenceId, references - 1);
                }
            }
            if (targets.size === 0)
                confirmedAdjacency.delete(occurrenceId);
        }
        for (const occurrenceId of event.afterOccurrenceIds) {
            if (confirmedAfterOwners.get(occurrenceId) === event.eventId) {
                confirmedAfterOwners.delete(occurrenceId);
            }
        }
    };
    const addActiveReconciliation = (event) => {
        const confirmedEdgeCount = requireConfirmedEdgeCapacity(activeConfirmedEdgeCount, event);
        const comparisonOwners = comparisonEndpointOwners.get(event.comparisonId) ??
            new Map();
        for (const occurrenceId of [
            ...event.beforeOccurrenceIds,
            ...event.afterOccurrenceIds,
        ]) {
            comparisonOwners.set(occurrenceId, event.eventId);
        }
        comparisonEndpointOwners.set(event.comparisonId, comparisonOwners);
        if (isConfirmedReconciliation(event)) {
            for (const occurrenceId of event.beforeOccurrenceIds) {
                confirmedBeforeOwners.set(occurrenceId, event.eventId);
                const targets = confirmedAdjacency.get(occurrenceId) ??
                    new Map();
                for (const afterOccurrenceId of event.afterOccurrenceIds) {
                    targets.set(afterOccurrenceId, (targets.get(afterOccurrenceId) ?? 0) + 1);
                }
                confirmedAdjacency.set(occurrenceId, targets);
            }
            for (const occurrenceId of event.afterOccurrenceIds) {
                confirmedAfterOwners.set(occurrenceId, event.eventId);
            }
            activeConfirmedEdgeCount += confirmedEdgeCount;
        }
        activeReconciliations.set(event.eventId, event);
    };
    const requireObservation = (observationId, subject) => {
        const observation = observations.get(observationId);
        if (!observation) {
            throw new Error(`${subject} references unknown observation ${observationId}`);
        }
        return observation;
    };
    const reviewedBindingKeysByObservation = new Map([...observations].map(([observationId, observation]) => [
        observationId,
        new Set(observation.reviewedBindings.map((binding) => `${binding.path}\0${binding.blob}`)),
    ]));
    const requireBindingsInObservation = (observationId, bindings, subject) => {
        requireObservation(observationId, subject);
        const known = reviewedBindingKeysByObservation.get(observationId);
        if (bindings.some((binding) => !known.has(`${binding.path}\0${binding.blob}`))) {
            throw new Error(`${subject} contains an unknown or mismatched path/blob binding`);
        }
    };
    const requireDispositionContext = (event, ledgerSlug) => {
        const occurrence = occurrences.get(event.occurrenceId);
        if (!occurrence || occurrence.findingId !== event.findingId) {
            throw new Error(`decision ${event.eventId} references an unknown or mismatched occurrence`);
        }
        if (occurrence.decisionLedger !== ledgerSlug ||
            findings.get(event.findingId)?.decisionLedger !== ledgerSlug) {
            throw new Error(`decision ${event.eventId} is not stored in the finding's stable ledger`);
        }
        if (!occurrence.closureEligible ||
            occurrence.ruleset === null) {
            throw new Error(`decision ${event.eventId} cannot govern a semantic-only occurrence without later exact review`);
        }
        if (event.reviewContext.observationId !== occurrence.observationId ||
            !sameBindings(event.reviewContext.bindings, occurrence.bindings) ||
            event.reviewContext.ruleset.id !== occurrence.ruleset.id ||
            event.reviewContext.ruleset.digest !== occurrence.ruleset.digest) {
            throw new Error(`decision ${event.eventId} review context has mismatched observation, binding, or ruleset references`);
        }
        for (const proof of event.proofs) {
            if (proof.kind === 'current-review' || proof.kind === 'source-evidence') {
                requireBindingsInObservation(proof.observationId, proof.reviewedBindings, `decision proof ${event.eventId}`);
            }
            else if (proof.kind === 'post-fix') {
                requireBindingsInObservation(proof.beforeObservationId, proof.beforeBindings, `decision proof ${event.eventId}`);
                requireBindingsInObservation(proof.afterObservationId, proof.afterBindings, `decision proof ${event.eventId}`);
                const afterObservation = requireObservation(proof.afterObservationId, `decision proof ${event.eventId}`);
                if (afterObservation.occurrenceIds.some((occurrenceId) => occurrences.get(occurrenceId)?.findingId === event.findingId)) {
                    throw new Error(`decision ${event.eventId} post-fix observation still contains the finding`);
                }
                if (afterObservation.repositoryRevision === null ||
                    afterObservation.repositoryRevision !== proof.fixRevision) {
                    throw new Error(`decision ${event.eventId} fixRevision does not match the post-fix target revision`);
                }
            }
            else if (proof.kind === 'replacement') {
                const replacement = occurrences.get(proof.replacementOccurrenceId);
                if (!replacement ||
                    replacement.findingId !== proof.replacementFindingId ||
                    replacement.observationId !== proof.observationId ||
                    !sameBindings(replacement.bindings, proof.replacementBindings)) {
                    throw new Error(`decision ${event.eventId} has mismatched replacement references`);
                }
            }
            else if (proof.kind === 'deletion') {
                const knownBinding = proof.deletedBindings.every((binding) => receiptOwners.has(`${binding.path}\0${binding.blob}`));
                if (!knownBinding) {
                    throw new Error(`decision ${event.eventId} deletion proof references unknown path/blob history`);
                }
            }
            else {
                requireBindingsInObservation(proof.observationId, proof.reviewedBindings, `decision proof ${event.eventId}`);
                const observation = requireObservation(proof.observationId, `decision proof ${event.eventId}`);
                if (observation.repositoryRevision === null ||
                    observation.repositoryRevision !== proof.searchRevision) {
                    throw new Error(`decision ${event.eventId} no-replacement revision is mismatched`);
                }
            }
        }
    };
    for (const ledgerCandidate of [...decisionRows].sort((left, right) => utf16Compare(left.slug, right.slug))) {
        const ledger = parseDecisionLedger(ledgerCandidate, '/decisionLedger');
        if (parsedDecisionLedgers.has(ledger.slug)) {
            throw new Error(`duplicate decision ledger slug: ${ledger.slug}`);
        }
        parsedDecisionLedgers.set(ledger.slug, ledger);
        for (const [chainIndex, entry] of ledger.entries.entries()) {
            if (events.has(entry.eventId)) {
                throw new Error(`duplicate or colliding decision event ${entry.eventId}`);
            }
            events.set(entry.eventId, {
                decisionLedger: ledger.slug,
                chainIndex,
                eventDigest: sha256Canonical(entry.event),
                event: entry.event,
            });
            const event = entry.event;
            if (event.type === 'finding-disposition') {
                requireDispositionContext(event, ledger.slug);
                if (event.supersedesEventId !== undefined) {
                    const prior = events.get(event.supersedesEventId);
                    if (!prior ||
                        prior.decisionLedger !== ledger.slug ||
                        prior.chainIndex >= chainIndex ||
                        prior.event.type !== 'finding-disposition' ||
                        prior.event.findingId !== event.findingId ||
                        ![
                            'accepted-risk',
                            'separate-design',
                            'false-positive',
                            'remediated',
                            'superseded',
                        ].includes(prior.event.action)) {
                        throw new Error(`decision ${event.eventId} supersedes an invalid or non-earlier closure`);
                    }
                    if (activeFindingClosures.get(event.findingId) !==
                        event.supersedesEventId) {
                        throw new Error(`decision ${event.eventId} must supersede the current active closure exactly once`);
                    }
                    activeFindingClosures.delete(event.findingId);
                }
                else if (event.action === 'open') {
                    activeFindingClosures.delete(event.findingId);
                }
                else {
                    activeFindingClosures.set(event.findingId, event.eventId);
                }
                continue;
            }
            if (event.type === 'scope-retirement') {
                if (event.reason === 'superseded' &&
                    event.noReplacementProof !== undefined) {
                    const proof = event.noReplacementProof;
                    requireBindingsInObservation(proof.observationId, proof.reviewedBindings, `retirement no-replacement proof ${event.eventId}`);
                    const searchedObservation = requireObservation(proof.observationId, `retirement no-replacement proof ${event.eventId}`);
                    if (searchedObservation.repositoryRevision === null ||
                        searchedObservation.repositoryRevision !== proof.searchRevision ||
                        proof.searchRevision !== event.revisionProof.repositoryRevision) {
                        throw new Error(`retirement ${event.eventId} no-replacement search revision is mismatched`);
                    }
                }
                const receiptKey = `${event.path}\0${event.blob}`;
                const owners = receiptOwners.get(receiptKey);
                if (!owners ||
                    owners.size !== 1 ||
                    !owners.has(ledger.slug) ||
                    event.decisionLedger !== ledger.slug ||
                    observationHistorySlug.get(event.historyProof.observationId) !==
                        ledger.slug) {
                    throw new Error(`retirement ${event.eventId} does not have unique history receipt ownership`);
                }
                requireBindingsInObservation(event.historyProof.observationId, [{ path: event.path, blob: event.blob }], `retirement ${event.eventId}`);
                if (event.reason === 'staged-deletion') {
                    if (activeStaged.has(receiptKey) ||
                        terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${event.eventId} duplicates an active staged or terminal retirement`);
                    }
                    activeStaged.set(receiptKey, event.eventId);
                }
                else if (event.reason === 'deleted') {
                    if (terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${event.eventId} duplicates a terminal retirement`);
                    }
                    const stagedEventId = activeStaged.get(receiptKey);
                    if ((stagedEventId === undefined &&
                        event.supersedesEventId !== undefined) ||
                        (stagedEventId !== undefined &&
                            event.supersedesEventId !== stagedEventId)) {
                        throw new Error(`deleted retirement ${event.eventId} must supersede exactly the active staged event`);
                    }
                    activeStaged.delete(receiptKey);
                    terminalRetirements.set(receiptKey, event.eventId);
                }
                else {
                    if (activeStaged.has(receiptKey) ||
                        terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${event.eventId} conflicts with an existing staged or terminal retirement`);
                    }
                    terminalRetirements.set(receiptKey, event.eventId);
                }
                retirementEvents.push(event);
                continue;
            }
            if (event.type === 'identity-alias-reconciliation') {
                const finding = findings.get(event.findingId);
                if (!finding || finding.decisionLedger !== ledger.slug) {
                    throw new Error(`alias event ${event.eventId} references an unknown finding home`);
                }
                for (const occurrenceId of event.occurrenceIds) {
                    if (occurrences.get(occurrenceId)?.findingId !== event.findingId) {
                        throw new Error(`alias event ${event.eventId} references a mismatched occurrence`);
                    }
                }
                for (const alias of event.aliases) {
                    const key = `${alias.scheme}\0${alias.value}`;
                    const owner = aliasOwners.get(key);
                    if (owner !== undefined) {
                        throw new Error(owner === event.findingId
                            ? `alias ${alias.scheme}:${alias.value} duplicates an existing alias pair`
                            : `alias ${alias.scheme}:${alias.value} maps to conflicting canonical findings`);
                    }
                    aliasOwners.set(key, event.findingId);
                }
                aliasEvents.push(event);
                continue;
            }
            const endpointOccurrences = [
                ...event.beforeOccurrenceIds,
                ...event.afterOccurrenceIds,
            ].map((occurrenceId) => {
                const occurrence = occurrences.get(occurrenceId);
                if (!occurrence) {
                    throw new Error(`reconciliation ${event.eventId} references unknown occurrence ${occurrenceId}`);
                }
                return occurrence;
            });
            requireStableIdentityReconciliation(event, occurrences);
            const expectedHome = endpointOccurrences
                .map((occurrence) => occurrence.decisionLedger)
                .sort(utf16Compare)[0];
            if (event.decisionLedger !== expectedHome ||
                ledger.slug !== expectedHome) {
                throw new Error(`reconciliation ${event.eventId} is not stored at its deterministic global home`);
            }
            const beforeObservationIds = [...new Set(event.beforeOccurrenceIds.map((occurrenceId) => occurrences.get(occurrenceId).observationId))].sort(utf16Compare);
            const afterObservationIds = [...new Set(event.afterOccurrenceIds.map((occurrenceId) => occurrences.get(occurrenceId).observationId))].sort(utf16Compare);
            if (computeAuditFindingComparisonId({
                beforeObservationIds,
                afterObservationIds,
            }) !== event.comparisonId) {
                throw new Error(`reconciliation ${event.eventId} has a mismatched comparison boundary`);
            }
            if (event.supersedesEventId !== undefined) {
                const prior = events.get(event.supersedesEventId);
                if (!prior ||
                    prior.decisionLedger !== ledger.slug ||
                    prior.chainIndex >= chainIndex ||
                    prior.event.type !== 'finding-reconciliation' ||
                    prior.event.comparisonId !== event.comparisonId) {
                    throw new Error(`reconciliation ${event.eventId} correction does not supersede an earlier event in the same comparison`);
                }
                const superseded = activeReconciliations.get(event.supersedesEventId);
                if (!superseded) {
                    throw new Error(`reconciliation ${event.eventId} correction must supersede the current active event`);
                }
                removeActiveReconciliation(superseded);
            }
            const candidateEndpoints = new Set([
                ...event.beforeOccurrenceIds,
                ...event.afterOccurrenceIds,
            ]);
            const comparisonOwners = comparisonEndpointOwners.get(event.comparisonId);
            if ([...candidateEndpoints].some((occurrenceId) => comparisonOwners?.has(occurrenceId))) {
                throw new Error(`reconciliation ${event.eventId} overlaps an active group in the same comparison`);
            }
            requireConfirmedEdgeCapacity(activeConfirmedEdgeCount, event);
            if (event.outcome === 'equivalent' && event.confidence === 'high') {
                const bindingSet = (occurrenceId) => {
                    const occurrence = occurrences.get(occurrenceId);
                    if (!occurrence.closureEligible ||
                        occurrence.bindings.length === 0 ||
                        !sameBindings(occurrence.bindings, occurrence.reviewedBindings)) {
                        throw new Error(`reconciliation ${event.eventId} requires exact reviewed bindings for every endpoint`);
                    }
                    return new Set(occurrence.bindings.map((binding) => `${binding.path}\0${binding.blob}`));
                };
                const sideUnion = (occurrenceIds, side) => {
                    const union = new Set();
                    for (const occurrenceId of occurrenceIds) {
                        const bindings = bindingSet(occurrenceId);
                        for (const binding of bindings) {
                            if (occurrenceIds.length > 1 && union.has(binding)) {
                                throw new Error(`reconciliation ${event.eventId} ${side} bindings overlap instead of forming a partition`);
                            }
                            union.add(binding);
                        }
                    }
                    return union;
                };
                const beforeUnion = sideUnion(event.beforeOccurrenceIds, 'before');
                const afterUnion = sideUnion(event.afterOccurrenceIds, 'after');
                if (beforeUnion.size !== afterUnion.size ||
                    [...beforeUnion].some((binding) => !afterUnion.has(binding))) {
                    throw new Error(`reconciliation ${event.eventId} binding partition/union does not match across the comparison`);
                }
                if (event.beforeOccurrenceIds.some((occurrenceId) => confirmedBeforeOwners.has(occurrenceId)) || event.afterOccurrenceIds.some((occurrenceId) => confirmedAfterOwners.has(occurrenceId))) {
                    throw new Error(`reconciliation ${event.eventId} conflicts with another active confirmed group`);
                }
                const targetOccurrenceIds = new Set(event.beforeOccurrenceIds);
                const reachable = [...event.afterOccurrenceIds];
                const visited = new Set();
                let createsCycle = false;
                while (reachable.length > 0 && !createsCycle) {
                    const occurrenceId = reachable.pop();
                    if (targetOccurrenceIds.has(occurrenceId)) {
                        createsCycle = true;
                        break;
                    }
                    if (visited.has(occurrenceId))
                        continue;
                    visited.add(occurrenceId);
                    for (const target of confirmedAdjacency.get(occurrenceId)?.keys() ?? []) {
                        if (!visited.has(target))
                            reachable.push(target);
                    }
                }
                if (createsCycle) {
                    throw new Error(`reconciliation ${event.eventId} creates a cyclic equivalence graph`);
                }
            }
            addActiveReconciliation(event);
            reconciliationEvents.push(event);
        }
    }
    return {
        findings,
        occurrences,
        observations,
        events,
        decisionLedgers: parsedDecisionLedgers,
        retirementEvents,
        reconciliationEvents,
        aliasEvents,
    };
}
function snapshotDecisionMap(value, pointer, parseKey, parseValue, options = {}) {
    const mapLimit = options.mapLimit ?? DECISION_INDEX_ITEM_LIMIT;
    if (!value ||
        typeof value !== 'object' ||
        Object.getPrototypeOf(value) !== Map.prototype ||
        Reflect.ownKeys(value).length !== 0) {
        invalid('invalid-decision-index', pointer, 'must be a plain Map without own properties');
    }
    const sizeGetter = Object.getOwnPropertyDescriptor(Map.prototype, 'size')?.get;
    const size = sizeGetter?.call(value);
    if (!Number.isSafeInteger(size) ||
        size < 0 ||
        size > mapLimit) {
        invalid('invalid-decision-index', pointer, `Map exceeds the ${mapLimit}-item limit`);
    }
    const entries = [];
    let index = 0;
    for (const entry of Map.prototype.entries.call(value)) {
        const entryPointer = `${pointer}/${index}`;
        const key = parseKey(entry[0], `${entryPointer}/key`);
        options.preflightValue?.(entry[1], `${entryPointer}/value`);
        entries.push({
            key,
            value: entry[1],
            pointer: `${entryPointer}/value`,
        });
        index += 1;
    }
    if (index !== size) {
        invalid('invalid-decision-index', pointer, 'Map size changed while it was being snapshotted');
    }
    options.afterPreflight?.();
    const snapshot = new Map();
    for (const entry of entries) {
        snapshot.set(entry.key, parseValue(entry.value, entry.pointer));
    }
    return snapshot;
}
function parseIndexedRuleset(value, pointer) {
    const ruleset = dataRecordAt(value, pointer);
    exactKeys(ruleset, ['id', 'digest'], [], pointer);
    return {
        id: patternAt(ruleset.id, SOURCE_NAME_RE, `${pointer}/id`, 'must be a canonical ruleset ID'),
        digest: sha256At(ruleset.digest, `${pointer}/digest`),
    };
}
function snapshotAuditDecisionPolicy(value) {
    const pointer = '/policy';
    const policy = dataRecordAt(value, pointer);
    const inputKeys = [
        'requireDisposition',
        'blockingActions',
        'drift',
        'expiry',
        'remediation',
        'falsePositive',
        'superseded',
        'retirement',
        'acceptedRulesets',
    ];
    exactKeys(policy, [...inputKeys, 'policyDigest'], [], pointer);
    const input = {};
    for (const key of inputKeys)
        input[key] = policy[key];
    return parseAuditDecisionPolicy(input, sha256At(policy.policyDigest, `${pointer}/policyDigest`));
}
function snapshotAuditDecisionIndex(value) {
    const index = dataRecordAt(value, '/index');
    exactKeys(index, [
        'findings',
        'occurrences',
        'observations',
        'events',
        'decisionLedgers',
        'retirementEvents',
        'reconciliationEvents',
        'aliasEvents',
    ], [], '/index');
    const parseFindingId = (candidate, pointer) => patternAt(candidate, FINDING_ID_RE, pointer, 'must be an Atlas finding ID');
    const parseOccurrenceId = (candidate, pointer) => patternAt(candidate, OCCURRENCE_ID_RE, pointer, 'must be an Atlas occurrence ID');
    const parseObservationId = (candidate, pointer) => patternAt(candidate, OBSERVATION_ID_RE, pointer, 'must be an Atlas observation ID');
    const parseNullableRuleset = (candidate, pointer) => candidate === null ? null : parseIndexedRuleset(candidate, pointer);
    const parseNullableRevision = (candidate, pointer) => candidate === null ? null : revisionAt(candidate, pointer);
    const findings = snapshotDecisionMap(index.findings, '/index/findings', parseFindingId, (candidate, pointer) => {
        const finding = dataRecordAt(candidate, pointer);
        exactKeys(finding, [
            'findingId',
            'decisionLedger',
            'occurrenceIds',
            'currentOccurrenceIds',
        ], [], pointer);
        return {
            findingId: parseFindingId(finding.findingId, `${pointer}/findingId`),
            decisionLedger: slugAt(finding.decisionLedger, `${pointer}/decisionLedger`),
            occurrenceIds: sortedUniqueStringsAt(finding.occurrenceIds, `${pointer}/occurrenceIds`, parseOccurrenceId),
            currentOccurrenceIds: sortedUniqueStringsAt(finding.currentOccurrenceIds, `${pointer}/currentOccurrenceIds`, parseOccurrenceId),
        };
    });
    const occurrences = snapshotDecisionMap(index.occurrences, '/index/occurrences', parseOccurrenceId, (candidate, pointer) => {
        const occurrence = dataRecordAt(candidate, pointer);
        exactKeys(occurrence, [
            'occurrenceId',
            'findingId',
            'observationId',
            'decisionLedger',
            'bindings',
            'reviewedBindings',
            'closureEligible',
            'ruleset',
            'repositoryRevision',
            'severity',
            'authoritative',
        ], [], pointer);
        return {
            occurrenceId: parseOccurrenceId(occurrence.occurrenceId, `${pointer}/occurrenceId`),
            findingId: parseFindingId(occurrence.findingId, `${pointer}/findingId`),
            observationId: parseObservationId(occurrence.observationId, `${pointer}/observationId`),
            decisionLedger: slugAt(occurrence.decisionLedger, `${pointer}/decisionLedger`),
            bindings: parseBindings(occurrence.bindings, `${pointer}/bindings`, false),
            reviewedBindings: parseBindings(occurrence.reviewedBindings, `${pointer}/reviewedBindings`, false),
            closureEligible: booleanAt(occurrence.closureEligible, `${pointer}/closureEligible`),
            ruleset: parseNullableRuleset(occurrence.ruleset, `${pointer}/ruleset`),
            repositoryRevision: parseNullableRevision(occurrence.repositoryRevision, `${pointer}/repositoryRevision`),
            severity: enumAt(occurrence.severity, ['critical', 'high', 'medium', 'low', 'informational'], `${pointer}/severity`),
            authoritative: booleanAt(occurrence.authoritative, `${pointer}/authoritative`),
        };
    });
    const observations = snapshotDecisionMap(index.observations, '/index/observations', parseObservationId, (candidate, pointer) => {
        const observation = dataRecordAt(candidate, pointer);
        exactKeys(observation, [
            'observationId',
            'slug',
            'historyIndex',
            'occurrenceIds',
            'inventoryBindings',
            'reviewedBindings',
            'ruleset',
            'repositoryRevision',
            'authoritative',
            'publicationState',
        ], [], pointer);
        return {
            observationId: parseObservationId(observation.observationId, `${pointer}/observationId`),
            slug: slugAt(observation.slug, `${pointer}/slug`),
            historyIndex: safeIntegerAt(observation.historyIndex, `${pointer}/historyIndex`),
            occurrenceIds: sortedUniqueStringsAt(observation.occurrenceIds, `${pointer}/occurrenceIds`, parseOccurrenceId),
            inventoryBindings: parseBindings(observation.inventoryBindings, `${pointer}/inventoryBindings`, false),
            reviewedBindings: parseBindings(observation.reviewedBindings, `${pointer}/reviewedBindings`, false),
            ruleset: parseNullableRuleset(observation.ruleset, `${pointer}/ruleset`),
            repositoryRevision: parseNullableRevision(observation.repositoryRevision, `${pointer}/repositoryRevision`),
            authoritative: booleanAt(observation.authoritative, `${pointer}/authoritative`),
            publicationState: enumAt(observation.publicationState, ['historical', 'current', 'history-ahead'], `${pointer}/publicationState`),
        };
    });
    const decisionLedgerResourceCandidates = [];
    let canonicalDecisionLedgerValues = new Map();
    const decisionLedgers = snapshotDecisionMap(index.decisionLedgers, '/index/decisionLedgers', (candidate, pointer) => slugAt(candidate, pointer), (_candidate, pointer) => parseDecisionLedger(canonicalDecisionLedgerValues.get(pointer), pointer), {
        mapLimit: DECISION_LEDGER_COUNT_LIMIT,
        preflightValue(candidate, pointer) {
            decisionLedgerResourceCandidates.push({
                value: candidate,
                pointer,
            });
        },
        afterPreflight() {
            canonicalDecisionLedgerValues =
                preflightDecisionLedgerResources(decisionLedgerResourceCandidates).canonicalValues;
        },
    });
    const events = snapshotDecisionMap(index.events, '/index/events', (candidate, pointer) => patternAt(candidate, EVENT_ID_RE, pointer, 'must be an Atlas decision event ID'), (candidate, pointer) => {
        const row = dataRecordAt(candidate, pointer);
        exactKeys(row, ['decisionLedger', 'chainIndex', 'eventDigest', 'event'], [], pointer);
        return {
            decisionLedger: slugAt(row.decisionLedger, `${pointer}/decisionLedger`),
            chainIndex: safeIntegerAt(row.chainIndex, `${pointer}/chainIndex`),
            eventDigest: sha256At(row.eventDigest, `${pointer}/eventDigest`),
            event: parseStoredDecisionEvent(row.event, `${pointer}/event`),
        };
    });
    const parseEventArray = (candidate, pointer, type, limit = DECISION_INDEX_ITEM_LIMIT) => {
        let rows;
        try {
            rows = dataArrayAt(candidate, pointer, limit);
        }
        catch (error) {
            if (type === 'finding-reconciliation') {
                invalid('decision-index-resource-limit', pointer, `reconciliation events exceed the ${limit}-event limit or are not a valid bounded array`);
            }
            throw error;
        }
        return rows.map((event, eventIndex) => {
            const parsed = parseStoredDecisionEvent(event, `${pointer}/${eventIndex}`);
            if (parsed.type !== type) {
                invalid('invalid-decision-index', `${pointer}/${eventIndex}/type`, `must equal ${type}`);
            }
            return parsed;
        });
    };
    const retirementEvents = parseEventArray(index.retirementEvents, '/index/retirementEvents', 'scope-retirement');
    const reconciliationEvents = parseEventArray(index.reconciliationEvents, '/index/reconciliationEvents', 'finding-reconciliation', RECONCILIATION_EVENT_LIMIT);
    const aliasEvents = parseEventArray(index.aliasEvents, '/index/aliasEvents', 'identity-alias-reconciliation');
    for (const event of reconciliationEvents) {
        requireStableIdentityReconciliation(event, occurrences);
    }
    const bindingKey = (binding) => `${binding.path}\0${binding.blob}`;
    for (const [findingId, finding] of findings) {
        if (finding.findingId !== findingId) {
            invalid('decision-index-identity-mismatch', '/index/findings', 'finding Map keys must equal findingId values');
        }
        if (finding.occurrenceIds.length === 0) {
            invalid('decision-index-reference-mismatch', `/index/findings/${findingId}/occurrenceIds`, 'finding occurrence membership must be nonempty');
        }
    }
    const observationsBySlug = new Map();
    const inventoryBindingKeysByObservation = new Map();
    const reviewedBindingKeysByObservation = new Map();
    for (const [observationId, observation] of observations) {
        if (observation.observationId !== observationId) {
            invalid('decision-index-identity-mismatch', '/index/observations', 'observation Map keys must equal observationId values');
        }
        if (observation.authoritative !==
            (observation.publicationState === 'current')) {
            invalid('decision-index-reference-mismatch', `/index/observations/${observationId}`, 'observation authority must match current publication state');
        }
        const inventoryKeys = new Set();
        const inventoryPaths = new Set();
        for (const binding of observation.inventoryBindings) {
            inventoryKeys.add(bindingKey(binding));
            inventoryPaths.add(binding.path);
        }
        const reviewedKeys = new Set();
        const reviewedPaths = new Set();
        for (const binding of observation.reviewedBindings) {
            reviewedKeys.add(bindingKey(binding));
            reviewedPaths.add(binding.path);
        }
        if (inventoryPaths.size !== observation.inventoryBindings.length ||
            reviewedPaths.size !== observation.reviewedBindings.length ||
            observation.reviewedBindings.some((binding) => !inventoryKeys.has(bindingKey(binding)))) {
            invalid('decision-index-reference-mismatch', `/index/observations/${observationId}`, 'observation inventory and reviewed bindings require unique paths and an exact reviewed subset');
        }
        inventoryBindingKeysByObservation.set(observationId, inventoryKeys);
        reviewedBindingKeysByObservation.set(observationId, reviewedKeys);
        const slugRows = observationsBySlug.get(observation.slug) ?? [];
        slugRows.push(observation);
        observationsBySlug.set(observation.slug, slugRows);
    }
    for (const [slug, slugRows] of observationsBySlug) {
        slugRows.sort((left, right) => left.historyIndex - right.historyIndex);
        if (slugRows.some((row, index) => row.historyIndex !== index)) {
            invalid('decision-index-reference-mismatch', `/index/observations/${slug}`, 'observation history indices must be unique and contiguous from zero');
        }
        const currentRows = slugRows.filter((row) => row.publicationState === 'current');
        if (currentRows.length === 0) {
            if (slugRows.length !== 1 ||
                slugRows[0].publicationState !== 'history-ahead') {
                invalid('decision-index-reference-mismatch', `/index/observations/${slug}`, 'a slug without current must contain exactly one index-zero history-ahead observation');
            }
            continue;
        }
        if (currentRows.length !== 1) {
            invalid('decision-index-reference-mismatch', `/index/observations/${slug}`, 'a slug must contain exactly one current observation');
        }
        const currentIndex = currentRows[0].historyIndex;
        if (slugRows.some((row) => row.historyIndex < currentIndex
            ? row.publicationState !== 'historical'
            : row.historyIndex === currentIndex
                ? row.publicationState !== 'current'
                : row.historyIndex !== currentIndex + 1 ||
                    row.publicationState !== 'history-ahead') ||
            slugRows.length > currentIndex + 2) {
            invalid('decision-index-reference-mismatch', `/index/observations/${slug}`, 'observation publication topology must be historical, one current, and at most one immediate trailing history-ahead row');
        }
    }
    const occurrenceIdsByFinding = new Map();
    const currentOccurrenceIdsByFinding = new Map();
    const occurrenceIdsByObservation = new Map();
    for (const [occurrenceId, occurrence] of occurrences) {
        if (occurrence.occurrenceId !== occurrenceId) {
            invalid('decision-index-identity-mismatch', '/index/occurrences', 'occurrence Map keys must equal occurrenceId values');
        }
        const finding = findings.get(occurrence.findingId);
        const observation = observations.get(occurrence.observationId);
        if (!finding ||
            !observation ||
            occurrence.decisionLedger !== finding.decisionLedger) {
            invalid('decision-index-reference-mismatch', `/index/occurrences/${occurrenceId}`, 'occurrence must reference matching indexed finding and observation facts');
        }
        if (occurrence.authoritative !== observation.authoritative ||
            occurrence.repositoryRevision !== observation.repositoryRevision ||
            !sameRuleset(occurrence.ruleset, observation.ruleset)) {
            invalid('decision-index-reference-mismatch', `/index/occurrences/${occurrenceId}`, 'occurrence authority, revision, and ruleset must match its observation');
        }
        const inventory = inventoryBindingKeysByObservation.get(occurrence.observationId);
        const reviewed = reviewedBindingKeysByObservation.get(occurrence.observationId);
        const occurrenceBindings = new Set(occurrence.bindings.map(bindingKey));
        if (occurrence.bindings.some((binding) => !inventory.has(bindingKey(binding))) ||
            occurrence.reviewedBindings.some((binding) => !reviewed.has(bindingKey(binding)) ||
                !occurrenceBindings.has(bindingKey(binding))) ||
            (occurrence.closureEligible &&
                (occurrence.ruleset === null ||
                    occurrence.bindings.length === 0 ||
                    !sameBindings(occurrence.bindings, occurrence.reviewedBindings)))) {
            invalid('decision-index-reference-mismatch', `/index/occurrences/${occurrenceId}`, 'occurrence bindings and closure eligibility must match observation facts');
        }
        const findingOccurrences = occurrenceIdsByFinding.get(occurrence.findingId) ?? [];
        findingOccurrences.push(occurrenceId);
        occurrenceIdsByFinding.set(occurrence.findingId, findingOccurrences);
        if (occurrence.authoritative) {
            const current = currentOccurrenceIdsByFinding.get(occurrence.findingId) ?? [];
            current.push(occurrenceId);
            currentOccurrenceIdsByFinding.set(occurrence.findingId, current);
        }
        const observationOccurrences = occurrenceIdsByObservation.get(occurrence.observationId) ?? [];
        observationOccurrences.push(occurrenceId);
        occurrenceIdsByObservation.set(occurrence.observationId, observationOccurrences);
    }
    const sameIds = (left, right) => {
        if (left.length !== right.length)
            return false;
        const sortedLeft = [...left].sort(utf16Compare);
        const sortedRight = [...right].sort(utf16Compare);
        return sortedLeft.every((value, index) => value === sortedRight[index]);
    };
    for (const [findingId, finding] of findings) {
        if (!sameIds(finding.occurrenceIds, occurrenceIdsByFinding.get(findingId) ?? []) ||
            !sameIds(finding.currentOccurrenceIds, currentOccurrenceIdsByFinding.get(findingId) ?? [])) {
            invalid('decision-index-reference-mismatch', `/index/findings/${findingId}`, 'finding occurrence memberships must match the occurrence index');
        }
        const findingObservations = finding.occurrenceIds.map((occurrenceId) => observations.get(occurrences.get(occurrenceId).observationId));
        const hasHomeOccurrence = findingObservations.some((observation) => observation.slug === finding.decisionLedger);
        const hasPublishedOccurrence = findingObservations.some((observation) => observation.publicationState !== 'history-ahead');
        const hasPublishedHomeOccurrence = findingObservations.some((observation) => observation.slug === finding.decisionLedger &&
            observation.publicationState !== 'history-ahead');
        if (!hasHomeOccurrence ||
            (hasPublishedOccurrence && !hasPublishedHomeOccurrence)) {
            invalid('decision-index-reference-mismatch', `/index/findings/${findingId}/decisionLedger`, 'finding decision home must exist among its occurrences and contain a published occurrence whenever the finding is published');
        }
    }
    for (const [observationId, observation] of observations) {
        if (!sameIds(observation.occurrenceIds, occurrenceIdsByObservation.get(observationId) ?? [])) {
            invalid('decision-index-reference-mismatch', `/index/observations/${observationId}`, 'observation occurrence memberships must match the occurrence index');
        }
    }
    const sortedDecisionLedgers = [...decisionLedgers.values()].sort((left, right) => utf16Compare(left.slug, right.slug));
    const eventIdentityRecords = [];
    const entryIdentityRecords = [];
    for (const ledger of sortedDecisionLedgers) {
        if (decisionLedgers.get(ledger.slug) !== ledger) {
            invalid('decision-index-identity-mismatch', '/index/decisionLedgers', 'decision ledger Map keys must equal ledger slugs');
        }
        for (const [chainIndex, entry] of ledger.entries.entries()) {
            const entryPointer = `/index/decisionLedgers/${ledger.slug}/${chainIndex}`;
            eventIdentityRecords.push({
                namespace: 'decision-event',
                id: entry.eventId,
                digest: sha256Canonical(entry.event),
                location: `${entryPointer}/event`,
            });
            entryIdentityRecords.push({
                namespace: 'decision-entry',
                id: entry.entryDigest,
                digest: sha256Canonical({
                    eventId: entry.eventId,
                    previousEntryDigest: entry.previousEntryDigest,
                    event: entry.event,
                }),
                location: entryPointer,
            });
        }
    }
    const identityDiagnostics = [
        ...validateUniqueAuditIdentityRecords(eventIdentityRecords),
        ...validateUniqueAuditIdentityRecords(entryIdentityRecords),
    ];
    if (identityDiagnostics.length > 0) {
        const first = identityDiagnostics[0];
        invalid(first.code, first.path, first.message);
    }
    const expectedEvents = new Map();
    const expectedRetirements = [];
    const expectedReconciliations = [];
    const expectedAliases = [];
    for (const ledger of sortedDecisionLedgers) {
        for (const [chainIndex, entry] of ledger.entries.entries()) {
            expectedEvents.set(entry.eventId, {
                decisionLedger: ledger.slug,
                chainIndex,
                eventDigest: sha256Canonical(entry.event),
                event: entry.event,
            });
            if (entry.event.type === 'scope-retirement') {
                expectedRetirements.push(entry.event);
            }
            else if (entry.event.type === 'finding-reconciliation') {
                expectedReconciliations.push(entry.event);
            }
            else if (entry.event.type === 'identity-alias-reconciliation') {
                expectedAliases.push(entry.event);
            }
            else if (entry.event.type !== 'finding-disposition') {
                invalid('invalid-decision-index', `/index/decisionLedgers/${ledger.slug}/${chainIndex}/event/type`, 'decision event type is not supported');
            }
        }
    }
    if (events.size !== expectedEvents.size) {
        invalid('decision-index-event-view-mismatch', '/index/events', 'event Map must exactly match parsed decision ledgers');
    }
    for (const [eventId, expected] of expectedEvents) {
        const actual = events.get(eventId);
        if (!actual ||
            actual.event.eventId !== eventId ||
            actual.decisionLedger !== expected.decisionLedger ||
            actual.chainIndex !== expected.chainIndex ||
            actual.eventDigest !== expected.eventDigest ||
            canonicalJson(actual.event) !== canonicalJson(expected.event)) {
            invalid('decision-index-event-view-mismatch', `/index/events/${eventId}`, 'event Map row must exactly match its parsed ledger entry');
        }
    }
    const requireMatchingEventArray = (actual, expected, pointer) => {
        if (actual.length !== expected.length ||
            actual.some((event, eventIndex) => canonicalJson(event) !== canonicalJson(expected[eventIndex]))) {
            invalid('decision-index-event-view-mismatch', pointer, 'redundant event array must exactly match parsed decision ledgers');
        }
    };
    requireMatchingEventArray(retirementEvents, expectedRetirements, '/index/retirementEvents');
    requireMatchingEventArray(reconciliationEvents, expectedReconciliations, '/index/reconciliationEvents');
    requireMatchingEventArray(aliasEvents, expectedAliases, '/index/aliasEvents');
    const receiptOwners = new Map();
    for (const observation of observations.values()) {
        for (const binding of observation.reviewedBindings) {
            const key = bindingKey(binding);
            const owners = receiptOwners.get(key) ?? new Set();
            owners.add(observation.slug);
            receiptOwners.set(key, owners);
        }
    }
    const requireObservationBindings = (observationId, bindings, subject) => {
        const observation = observations.get(observationId);
        if (!observation) {
            throw new Error(`${subject} references a foreign observation`);
        }
        const known = reviewedBindingKeysByObservation.get(observationId);
        if (bindings.some((binding) => !known.has(bindingKey(binding)))) {
            throw new Error(`${subject} references foreign reviewed bindings`);
        }
        return observation;
    };
    const activeFindingClosures = new Map();
    const activeStagedRetirements = new Map();
    const terminalRetirements = new Map();
    const aliasOwners = new Map();
    const activeReconciliations = new Map();
    const comparisonEndpointOwners = new Map();
    const confirmedBeforeOwners = new Map();
    const confirmedAfterOwners = new Map();
    const confirmedAdjacency = new Map();
    let activeConfirmedEdgeCount = 0;
    const isConfirmed = (event) => event.outcome === 'equivalent' && event.confidence === 'high';
    const removeActiveReconciliation = (event) => {
        activeReconciliations.delete(event.eventId);
        const endpointOwners = comparisonEndpointOwners.get(event.comparisonId);
        if (endpointOwners) {
            for (const occurrenceId of [
                ...event.beforeOccurrenceIds,
                ...event.afterOccurrenceIds,
            ]) {
                if (endpointOwners.get(occurrenceId) === event.eventId) {
                    endpointOwners.delete(occurrenceId);
                }
            }
            if (endpointOwners.size === 0) {
                comparisonEndpointOwners.delete(event.comparisonId);
            }
        }
        if (!isConfirmed(event))
            return;
        activeConfirmedEdgeCount -= confirmedReconciliationEdgeCount(event);
        for (const occurrenceId of event.beforeOccurrenceIds) {
            if (confirmedBeforeOwners.get(occurrenceId) === event.eventId) {
                confirmedBeforeOwners.delete(occurrenceId);
            }
            const targets = confirmedAdjacency.get(occurrenceId);
            if (!targets)
                continue;
            for (const target of event.afterOccurrenceIds) {
                const count = targets.get(target);
                if (count === undefined)
                    continue;
                if (count === 1)
                    targets.delete(target);
                else
                    targets.set(target, count - 1);
            }
            if (targets.size === 0)
                confirmedAdjacency.delete(occurrenceId);
        }
        for (const occurrenceId of event.afterOccurrenceIds) {
            if (confirmedAfterOwners.get(occurrenceId) === event.eventId) {
                confirmedAfterOwners.delete(occurrenceId);
            }
        }
    };
    const addActiveReconciliation = (event) => {
        const confirmedEdgeCount = requireConfirmedEdgeCapacity(activeConfirmedEdgeCount, event);
        const endpointOwners = comparisonEndpointOwners.get(event.comparisonId) ??
            new Map();
        for (const occurrenceId of [
            ...event.beforeOccurrenceIds,
            ...event.afterOccurrenceIds,
        ]) {
            endpointOwners.set(occurrenceId, event.eventId);
        }
        comparisonEndpointOwners.set(event.comparisonId, endpointOwners);
        if (isConfirmed(event)) {
            for (const occurrenceId of event.beforeOccurrenceIds) {
                confirmedBeforeOwners.set(occurrenceId, event.eventId);
                const targets = confirmedAdjacency.get(occurrenceId) ??
                    new Map();
                for (const target of event.afterOccurrenceIds) {
                    targets.set(target, (targets.get(target) ?? 0) + 1);
                }
                confirmedAdjacency.set(occurrenceId, targets);
            }
            for (const occurrenceId of event.afterOccurrenceIds) {
                confirmedAfterOwners.set(occurrenceId, event.eventId);
            }
            activeConfirmedEdgeCount += confirmedEdgeCount;
        }
        activeReconciliations.set(event.eventId, event);
    };
    for (const [eventId, row] of [...events.entries()].sort(([, left], [, right]) => utf16Compare(left.decisionLedger, right.decisionLedger) ||
        left.chainIndex - right.chainIndex)) {
        if (row.event.eventId !== eventId) {
            invalid('decision-index-identity-mismatch', `/index/events/${eventId}`, 'event Map keys must equal eventId values');
        }
        const event = row.event;
        if (event.type === 'finding-disposition') {
            const occurrence = occurrences.get(event.occurrenceId);
            if (!occurrence ||
                occurrence.findingId !== event.findingId ||
                occurrence.decisionLedger !== row.decisionLedger ||
                findings.get(event.findingId)?.decisionLedger !== row.decisionLedger) {
                invalid('decision-index-reference-mismatch', `/index/events/${eventId}`, 'finding decision references a foreign occurrence or ledger');
            }
            if (!occurrence.closureEligible ||
                occurrence.ruleset === null ||
                event.reviewContext.observationId !== occurrence.observationId ||
                !sameBindings(event.reviewContext.bindings, occurrence.bindings) ||
                event.reviewContext.ruleset.id !== occurrence.ruleset.id ||
                event.reviewContext.ruleset.digest !== occurrence.ruleset.digest) {
                throw new Error(`decision ${eventId} has foreign review context or cannot govern a semantic-only occurrence`);
            }
            for (const proof of event.proofs) {
                switch (proof.kind) {
                    case 'current-review':
                    case 'source-evidence':
                        requireObservationBindings(proof.observationId, proof.reviewedBindings, `decision proof ${eventId}`);
                        break;
                    case 'post-fix': {
                        requireObservationBindings(proof.beforeObservationId, proof.beforeBindings, `decision proof ${eventId}`);
                        const afterObservation = requireObservationBindings(proof.afterObservationId, proof.afterBindings, `decision proof ${eventId}`);
                        if (afterObservation.repositoryRevision !== proof.fixRevision ||
                            afterObservation.occurrenceIds.some((occurrenceId) => occurrences.get(occurrenceId)?.findingId === event.findingId)) {
                            throw new Error(`decision ${eventId} has foreign post-fix observation facts`);
                        }
                        break;
                    }
                    case 'replacement': {
                        const replacement = occurrences.get(proof.replacementOccurrenceId);
                        if (!replacement ||
                            replacement.findingId !== proof.replacementFindingId ||
                            replacement.observationId !== proof.observationId ||
                            !sameBindings(replacement.bindings, proof.replacementBindings)) {
                            throw new Error(`decision ${eventId} has foreign replacement facts`);
                        }
                        break;
                    }
                    case 'deletion':
                        if (proof.deletedBindings.some((binding) => !receiptOwners.has(bindingKey(binding)))) {
                            throw new Error(`decision ${eventId} has foreign deletion bindings`);
                        }
                        break;
                    case 'no-replacement': {
                        const searched = requireObservationBindings(proof.observationId, proof.reviewedBindings, `decision proof ${eventId}`);
                        if (searched.repositoryRevision !== proof.searchRevision) {
                            throw new Error(`decision ${eventId} has foreign no-replacement revision`);
                        }
                        break;
                    }
                    default:
                        throw new Error(`decision ${eventId} contains an unsupported proof kind`);
                }
            }
            if (event.supersedesEventId !== undefined) {
                const prior = events.get(event.supersedesEventId);
                if (!prior ||
                    prior.decisionLedger !== row.decisionLedger ||
                    prior.chainIndex >= row.chainIndex ||
                    prior.event.type !== 'finding-disposition' ||
                    prior.event.findingId !== event.findingId ||
                    ![
                        'accepted-risk',
                        'separate-design',
                        'false-positive',
                        'remediated',
                        'superseded',
                    ].includes(prior.event.action) ||
                    activeFindingClosures.get(event.findingId) !==
                        event.supersedesEventId) {
                    throw new Error(`decision ${eventId} supersedes an invalid or inactive closure`);
                }
                activeFindingClosures.delete(event.findingId);
            }
            else if (event.action === 'open') {
                activeFindingClosures.delete(event.findingId);
            }
            else {
                activeFindingClosures.set(event.findingId, eventId);
            }
        }
        else if (event.type === 'finding-reconciliation') {
            requireStableIdentityReconciliation(event, occurrences);
            const endpointOccurrences = [
                ...event.beforeOccurrenceIds,
                ...event.afterOccurrenceIds,
            ].map((occurrenceId) => occurrences.get(occurrenceId));
            if (endpointOccurrences.some((occurrence) => occurrence === undefined)) {
                invalid('decision-index-reference-mismatch', `/index/events/${eventId}`, 'reconciliation references a foreign occurrence');
            }
            const expectedHome = endpointOccurrences
                .map((occurrence) => occurrence.decisionLedger)
                .sort(utf16Compare)[0];
            const beforeObservationIds = [...new Set(event.beforeOccurrenceIds.map((occurrenceId) => occurrences.get(occurrenceId).observationId))].sort(utf16Compare);
            const afterObservationIds = [...new Set(event.afterOccurrenceIds.map((occurrenceId) => occurrences.get(occurrenceId).observationId))].sort(utf16Compare);
            if (expectedHome !== row.decisionLedger ||
                event.decisionLedger !== row.decisionLedger ||
                computeAuditFindingComparisonId({
                    beforeObservationIds,
                    afterObservationIds,
                }) !== event.comparisonId) {
                invalid('decision-index-reference-mismatch', `/index/events/${eventId}`, 'reconciliation home and comparison must match endpoint facts');
            }
            if (event.supersedesEventId !== undefined) {
                const prior = events.get(event.supersedesEventId);
                const superseded = activeReconciliations.get(event.supersedesEventId);
                if (!prior ||
                    prior.decisionLedger !== row.decisionLedger ||
                    prior.chainIndex >= row.chainIndex ||
                    prior.event.type !== 'finding-reconciliation' ||
                    prior.event.comparisonId !== event.comparisonId ||
                    !superseded) {
                    throw new Error(`reconciliation ${eventId} correction must supersede the current active event in the same comparison`);
                }
                removeActiveReconciliation(superseded);
            }
            const endpointOwners = comparisonEndpointOwners.get(event.comparisonId);
            if ([...event.beforeOccurrenceIds, ...event.afterOccurrenceIds].some((occurrenceId) => endpointOwners?.has(occurrenceId))) {
                throw new Error(`reconciliation ${eventId} overlaps an active group in the same comparison`);
            }
            requireConfirmedEdgeCapacity(activeConfirmedEdgeCount, event);
            if (isConfirmed(event)) {
                const sideUnion = (occurrenceIds, side) => {
                    const union = new Set();
                    for (const occurrenceId of occurrenceIds) {
                        const occurrence = occurrences.get(occurrenceId);
                        if (!occurrence.closureEligible ||
                            occurrence.bindings.length === 0 ||
                            !sameBindings(occurrence.bindings, occurrence.reviewedBindings)) {
                            throw new Error(`reconciliation ${eventId} requires exact reviewed bindings`);
                        }
                        for (const binding of occurrence.bindings) {
                            const key = bindingKey(binding);
                            if (occurrenceIds.length > 1 && union.has(key)) {
                                throw new Error(`reconciliation ${eventId} ${side} bindings overlap`);
                            }
                            union.add(key);
                        }
                    }
                    return union;
                };
                const beforeUnion = sideUnion(event.beforeOccurrenceIds, 'before');
                const afterUnion = sideUnion(event.afterOccurrenceIds, 'after');
                if (beforeUnion.size !== afterUnion.size ||
                    [...beforeUnion].some((binding) => !afterUnion.has(binding))) {
                    throw new Error(`reconciliation ${eventId} binding partition/union is mismatched`);
                }
                if (event.beforeOccurrenceIds.some((occurrenceId) => confirmedBeforeOwners.has(occurrenceId)) ||
                    event.afterOccurrenceIds.some((occurrenceId) => confirmedAfterOwners.has(occurrenceId))) {
                    throw new Error(`reconciliation ${eventId} conflicts with another active confirmed owner`);
                }
                const targetOccurrenceIds = new Set(event.beforeOccurrenceIds);
                const reachable = [...event.afterOccurrenceIds];
                const visited = new Set();
                while (reachable.length > 0) {
                    const occurrenceId = reachable.pop();
                    if (targetOccurrenceIds.has(occurrenceId)) {
                        throw new Error(`reconciliation ${eventId} creates a cyclic equivalence graph`);
                    }
                    if (visited.has(occurrenceId))
                        continue;
                    visited.add(occurrenceId);
                    for (const target of confirmedAdjacency.get(occurrenceId)?.keys() ?? []) {
                        if (!visited.has(target))
                            reachable.push(target);
                    }
                }
            }
            addActiveReconciliation(event);
        }
        else if (event.type === 'identity-alias-reconciliation') {
            const finding = findings.get(event.findingId);
            if (!finding ||
                finding.decisionLedger !== row.decisionLedger ||
                event.occurrenceIds.some((occurrenceId) => occurrences.get(occurrenceId)?.findingId !== event.findingId)) {
                invalid('decision-index-reference-mismatch', `/index/events/${eventId}`, 'alias reconciliation references foreign finding facts');
            }
            for (const alias of event.aliases) {
                const key = `${alias.scheme}\0${alias.value}`;
                const owner = aliasOwners.get(key);
                if (owner !== undefined) {
                    throw new Error(owner === event.findingId
                        ? `alias ${alias.scheme}:${alias.value} duplicates an existing alias pair`
                        : `alias ${alias.scheme}:${alias.value} maps to conflicting canonical findings`);
                }
                aliasOwners.set(key, event.findingId);
            }
        }
        else if (event.type === 'scope-retirement') {
            const observation = observations.get(event.historyProof.observationId);
            if (!observation ||
                event.decisionLedger !== row.decisionLedger ||
                observation.slug !== event.historyProof.slug ||
                event.historyProof.path !== event.path ||
                event.historyProof.blob !== event.blob ||
                !observation.reviewedBindings.some((binding) => binding.path === event.historyProof.path &&
                    binding.blob === event.historyProof.blob)) {
                invalid('decision-index-reference-mismatch', `/index/events/${eventId}`, 'retirement references foreign history facts');
            }
            if (event.reason === 'superseded' &&
                event.noReplacementProof !== undefined) {
                const searched = requireObservationBindings(event.noReplacementProof.observationId, event.noReplacementProof.reviewedBindings, `retirement ${eventId} no-replacement proof`);
                if (searched.repositoryRevision !==
                    event.noReplacementProof.searchRevision ||
                    event.noReplacementProof.searchRevision !==
                        event.revisionProof.repositoryRevision) {
                    throw new Error(`retirement ${eventId} no-replacement revision is mismatched`);
                }
            }
            const receiptKey = `${event.path}\0${event.blob}`;
            const owners = receiptOwners.get(receiptKey);
            if (!owners ||
                owners.size !== 1 ||
                !owners.has(row.decisionLedger)) {
                throw new Error(`retirement ${eventId} lacks unique history receipt ownership`);
            }
            switch (event.reason) {
                case 'staged-deletion':
                    if (activeStagedRetirements.has(receiptKey) ||
                        terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${eventId} duplicates an active staged or terminal retirement`);
                    }
                    activeStagedRetirements.set(receiptKey, eventId);
                    break;
                case 'deleted': {
                    if (terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${eventId} duplicates a terminal retirement`);
                    }
                    const stagedEventId = activeStagedRetirements.get(receiptKey);
                    if ((stagedEventId === undefined &&
                        event.supersedesEventId !== undefined) ||
                        (stagedEventId !== undefined &&
                            event.supersedesEventId !== stagedEventId)) {
                        throw new Error(`deleted retirement ${eventId} must supersede exactly the active staged event`);
                    }
                    activeStagedRetirements.delete(receiptKey);
                    terminalRetirements.set(receiptKey, eventId);
                    break;
                }
                case 'moved':
                case 'superseded':
                case 'uncommitted-snapshot-absent':
                    if (activeStagedRetirements.has(receiptKey) ||
                        terminalRetirements.has(receiptKey)) {
                        throw new Error(`retirement ${eventId} conflicts with an existing staged or terminal retirement`);
                    }
                    terminalRetirements.set(receiptKey, eventId);
                    break;
                default:
                    throw new Error(`retirement ${eventId} has an unsupported retirement reason`);
            }
        }
        else {
            throw new Error(`decision ${eventId} has an unsupported event type`);
        }
    }
    return {
        findings,
        occurrences,
        observations,
        events,
        decisionLedgers,
        retirementEvents,
        reconciliationEvents,
        aliasEvents,
    };
}
export function reduceAuditDecisionState(index, policy, now) {
    index = snapshotAuditDecisionIndex(index);
    policy = snapshotAuditDecisionPolicy(policy);
    const canonicalNow = timestampAt(now, '/now');
    const nowMilliseconds = Date.parse(canonicalNow);
    const dayMilliseconds = 24 * 60 * 60 * 1_000;
    const dispositionIsPublished = (event) => {
        const observationIds = new Set([
            event.reviewContext.observationId,
        ]);
        for (const proof of event.proofs) {
            switch (proof.kind) {
                case 'post-fix':
                    observationIds.add(proof.beforeObservationId);
                    observationIds.add(proof.afterObservationId);
                    break;
                case 'current-review':
                case 'source-evidence':
                case 'replacement':
                case 'no-replacement':
                    observationIds.add(proof.observationId);
                    break;
                case 'deletion':
                    break;
                default:
                    throw new Error(`decision ${event.eventId} contains an unsupported proof kind`);
            }
        }
        if (event.action === 'remediated' &&
            event.regression.binding.observationId !== undefined) {
            observationIds.add(event.regression.binding.observationId);
        }
        return [...observationIds].every((observationId) => index.observations.get(observationId)?.publicationState !== 'history-ahead');
    };
    const dispositionRows = [...index.events.values()]
        .filter((row) => row.event.type === 'finding-disposition' &&
        dispositionIsPublished(row.event))
        .sort((left, right) => utf16Compare(left.decisionLedger, right.decisionLedger) ||
        left.chainIndex - right.chainIndex);
    const dispositionsByFinding = new Map();
    for (const row of dispositionRows) {
        const rows = dispositionsByFinding.get(row.event.findingId) ?? [];
        rows.push(row);
        dispositionsByFinding.set(row.event.findingId, rows);
    }
    const currentInventoryPaths = new Set();
    for (const observation of index.observations.values()) {
        if (!observation.authoritative)
            continue;
        for (const binding of observation.inventoryBindings) {
            currentInventoryPaths.add(binding.path);
        }
    }
    const policyStatus = (row) => {
        const event = row.event;
        const eventId = event.eventId;
        switch (event.action) {
            case 'open':
            case 'reopened':
            case 'remediated':
            case 'accepted-risk':
            case 'separate-design':
            case 'false-positive':
            case 'superseded':
                break;
            default:
                throw new Error(`decision ${eventId} contains an unsupported finding action`);
        }
        const occurrence = index.occurrences.get(event.occurrenceId);
        if (!occurrence) {
            throw new Error(`decision ${event.eventId} references an unknown occurrence during reduction`);
        }
        const rulesetAccepted = policy.acceptedRulesets.includes(event.reviewContext.ruleset.id);
        const contextCurrent = event.reviewContext.policyDigest === policy.policyDigest &&
            rulesetAccepted;
        if (event.action === 'accepted-risk' ||
            event.action === 'separate-design') {
            const createdAt = Date.parse(event.createdAt);
            const expiresAt = Date.parse(event.expiresAt);
            const expiryState = nowMilliseconds >= expiresAt
                ? 'expired'
                : expiresAt <=
                    nowMilliseconds + policy.expiry.warningDays * dayMilliseconds
                    ? 'warning'
                    : 'active';
            if (event.reviewContext.policyDigest !== policy.policyDigest) {
                return { contextCurrent: false, expiryState };
            }
            const baseMaximumDays = event.action === 'accepted-risk'
                ? policy.expiry.acceptedRiskMaximumDays
                : policy.expiry.separateDesignMaximumDays;
            const severityOverride = policy.expiry.severityOverrides.find((candidate) => candidate.severities.includes(occurrence.severity));
            const maximumDays = severityOverride
                ? Math.min(baseMaximumDays, severityOverride.maximumDays)
                : baseMaximumDays;
            if (expiresAt <= createdAt ||
                expiresAt - createdAt > maximumDays * dayMilliseconds) {
                throw new Error(`decision ${event.eventId} expiry exceeds the event-relative maximum of ${maximumDays} days`);
            }
            if (severityOverride) {
                const eligibleReviewers = new Set();
                for (const review of event.reviews) {
                    if (review.verdict !== 'approve' ||
                        review.reviewer === event.actor ||
                        review.reviewer === event.owner ||
                        (severityOverride.reviewEvidenceRequired &&
                            review.evidence.trim().length === 0)) {
                        continue;
                    }
                    eligibleReviewers.add(review.reviewer);
                }
                if (eligibleReviewers.size <
                    severityOverride.minimumIndependentReviews) {
                    throw new Error(`decision ${event.eventId} lacks the required independent review approvals and evidence`);
                }
            }
            return { contextCurrent, expiryState };
        }
        if (event.reviewContext.policyDigest !== policy.policyDigest) {
            return { contextCurrent: false, expiryState: 'not-applicable' };
        }
        if (event.action === 'false-positive') {
            if (policy.falsePositive.reviewedBlobRequired &&
                !sameBindings(event.reviewContext.bindings, event.actionEvidence.reviewedBindings)) {
                throw new Error(`decision ${event.eventId} lacks exact reviewed false-positive blobs`);
            }
            if (policy.falsePositive.sourceEvidenceRequired &&
                event.proofs.length === 0) {
                throw new Error(`decision ${event.eventId} lacks required source evidence`);
            }
        }
        else if (event.action === 'remediated') {
            if (policy.remediation.passingRegressionRequired &&
                event.regression.result !== 'passed') {
                throw new Error(`decision ${event.eventId} lacks a passing remediation regression`);
            }
            if (!policy.remediation.allowedRegressionKinds.includes(event.regression.kind)) {
                throw new Error(`decision ${event.eventId} uses a regression kind not allowed by policy`);
            }
            if (policy.remediation.fixBlobRequired &&
                event.actionEvidence.afterBindings.length === 0) {
                throw new Error(`decision ${event.eventId} lacks a bound post-fix blob`);
            }
            if (policy.remediation.postFixProofRequired &&
                event.proofs.length === 0) {
                throw new Error(`decision ${event.eventId} lacks a post-fix proof`);
            }
        }
        else if (event.action === 'superseded' &&
            policy.superseded.replacementOrDeletionProofRequired &&
            event.proofs.length === 0) {
            throw new Error(`decision ${event.eventId} lacks replacement or deletion proof`);
        }
        if (event.action === 'superseded' &&
            policy.superseded.existingPathRequiresCurrentReview) {
            const currentPathStillExists = event.reviewContext.bindings.some((binding) => currentInventoryPaths.has(binding.path));
            if (currentPathStillExists &&
                index.observations.get(event.reviewContext.observationId)?.publicationState !== 'current') {
                throw new Error(`superseded decision ${event.eventId} requires a current review while the existing path remains`);
            }
        }
        return { contextCurrent, expiryState: 'not-applicable' };
    };
    const sortedIds = (values) => [...new Set(values)].sort(utf16Compare);
    const explicitBlocking = (action) => {
        switch (action) {
            case 'reopened':
                return true;
            case 'open':
                return policy.requireDisposition ||
                    policy.blockingActions.includes(action);
            case 'remediated':
            case 'accepted-risk':
            case 'separate-design':
            case 'false-positive':
            case 'superseded':
                return policy.blockingActions.includes(action);
            default:
                throw new Error(`decision contains an unsupported finding action`);
        }
    };
    const stateFromDirectEvent = (row, currentOccurrenceIds) => {
        const event = row.event;
        const status = policyStatus(row);
        const stale = !status.contextCurrent || status.expiryState === 'expired';
        if (stale) {
            return {
                disposition: 'open',
                blocking: true,
                derivation: 'carry-invalidated',
                lifecycle: currentOccurrenceIds.length > 0 ? 'persisting' : 'unknown',
                currentOccurrenceIds,
                eventId: null,
                basisEventIds: [event.eventId],
                expiresAt: event.action === 'accepted-risk' ||
                    event.action === 'separate-design'
                    ? event.expiresAt
                    : null,
                expiryState: status.expiryState,
                reopenAcknowledged: false,
            };
        }
        return {
            disposition: event.action,
            blocking: explicitBlocking(event.action),
            derivation: 'explicit-event',
            lifecycle: event.action === 'remediated' && currentOccurrenceIds.length === 0
                ? 'resolved'
                : event.action === 'reopened'
                    ? 'reopened'
                    : event.action === 'false-positive' ||
                        event.action === 'superseded'
                        ? 'unknown'
                        : currentOccurrenceIds.length > 0
                            ? 'persisting'
                            : 'unknown',
            currentOccurrenceIds,
            eventId: event.eventId,
            basisEventIds: event.action === 'reopened' ? [event.supersedesEventId] : [],
            expiresAt: event.action === 'accepted-risk' ||
                event.action === 'separate-design'
                ? event.expiresAt
                : null,
            expiryState: status.expiryState,
            reopenAcknowledged: event.action === 'reopened',
        };
    };
    const findings = new Map();
    for (const [findingId, finding] of [...index.findings.entries()].sort(([left], [right]) => utf16Compare(left, right))) {
        const currentOccurrenceIds = sortedIds(finding.currentOccurrenceIds);
        const rows = dispositionsByFinding.get(findingId) ?? [];
        for (const row of rows)
            policyStatus(row);
        const latest = rows.at(-1);
        if (!latest) {
            findings.set(findingId, {
                disposition: 'open',
                blocking: currentOccurrenceIds.length > 0 &&
                    (policy.requireDisposition ||
                        policy.blockingActions.includes('open')),
                derivation: 'implicit-open',
                lifecycle: currentOccurrenceIds.length > 0 ? 'new' : 'unknown',
                currentOccurrenceIds,
                eventId: null,
                basisEventIds: [],
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
            continue;
        }
        const directlyCurrent = currentOccurrenceIds.includes(latest.event.occurrenceId);
        if (directlyCurrent && currentOccurrenceIds.length > 1) {
            findings.set(findingId, {
                disposition: 'open',
                blocking: true,
                derivation: 'reconciliation-conflict',
                lifecycle: 'unknown',
                currentOccurrenceIds,
                eventId: null,
                basisEventIds: [latest.event.eventId],
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
            continue;
        }
        if (directlyCurrent || currentOccurrenceIds.length === 0) {
            findings.set(findingId, stateFromDirectEvent(latest, currentOccurrenceIds));
            continue;
        }
        const latestEvent = latest.event;
        const latestStatus = policyStatus(latest);
        if (latestEvent.action === 'remediated' ||
            latestEvent.action === 'false-positive' ||
            latestEvent.action === 'superseded') {
            findings.set(findingId, {
                disposition: 'reopened',
                blocking: true,
                derivation: 'automatic-reopen',
                lifecycle: 'reopened',
                currentOccurrenceIds,
                eventId: null,
                basisEventIds: [latestEvent.eventId],
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
            continue;
        }
        if (latestEvent.action === 'accepted-risk' ||
            latestEvent.action === 'separate-design') {
            const compatible = latestStatus.contextCurrent &&
                latestStatus.expiryState !== 'expired' &&
                currentOccurrenceIds.length === 1 &&
                currentOccurrenceIds.every((occurrenceId) => {
                    const occurrence = index.occurrences.get(occurrenceId);
                    return occurrence !== undefined &&
                        occurrence.closureEligible &&
                        sameBindings(latestEvent.reviewContext.bindings, occurrence.bindings) &&
                        occurrence.ruleset?.id ===
                            latestEvent.reviewContext.ruleset.id &&
                        occurrence.ruleset.digest ===
                            latestEvent.reviewContext.ruleset.digest;
                });
            findings.set(findingId, compatible
                ? {
                    disposition: latestEvent.action,
                    blocking: explicitBlocking(latestEvent.action),
                    derivation: 'carried',
                    lifecycle: 'persisting',
                    currentOccurrenceIds,
                    eventId: null,
                    basisEventIds: [latestEvent.eventId],
                    expiresAt: latestEvent.expiresAt,
                    expiryState: latestStatus.expiryState,
                    reopenAcknowledged: false,
                }
                : {
                    disposition: 'open',
                    blocking: true,
                    derivation: 'carry-invalidated',
                    lifecycle: 'persisting',
                    currentOccurrenceIds,
                    eventId: null,
                    basisEventIds: [latestEvent.eventId],
                    expiresAt: latestEvent.expiresAt,
                    expiryState: latestStatus.expiryState,
                    reopenAcknowledged: false,
                });
            continue;
        }
        findings.set(findingId, {
            disposition: latestEvent.action === 'reopened' ? 'reopened' : 'open',
            blocking: true,
            derivation: 'carried',
            lifecycle: latestEvent.action === 'reopened' ? 'reopened' : 'persisting',
            currentOccurrenceIds,
            eventId: null,
            basisEventIds: [latestEvent.eventId],
            expiresAt: null,
            expiryState: 'not-applicable',
            reopenAcknowledged: latestEvent.action === 'reopened',
        });
    }
    for (const event of index.reconciliationEvents) {
        requireStableIdentityReconciliation(event, index.occurrences);
    }
    const activeReconciliations = new Map();
    for (const event of index.reconciliationEvents) {
        if (event.supersedesEventId !== undefined) {
            activeReconciliations.delete(event.supersedesEventId);
        }
        activeReconciliations.set(event.eventId, event);
    }
    const dispositionRowsByOccurrence = new Map();
    for (const row of dispositionRows) {
        const rows = dispositionRowsByOccurrence.get(row.event.occurrenceId) ?? [];
        rows.push(row);
        dispositionRowsByOccurrence.set(row.event.occurrenceId, rows);
    }
    const explicitOccurrenceIds = new Set();
    const occurrenceStates = new Map();
    for (const occurrence of index.occurrences.values()) {
        const explicitRow = dispositionRowsByOccurrence
            .get(occurrence.occurrenceId)
            ?.at(-1);
        if (explicitRow) {
            explicitOccurrenceIds.add(occurrence.occurrenceId);
            occurrenceStates.set(occurrence.occurrenceId, stateFromDirectEvent(explicitRow, [occurrence.occurrenceId]));
        }
        else {
            occurrenceStates.set(occurrence.occurrenceId, {
                disposition: 'open',
                blocking: policy.requireDisposition || policy.blockingActions.includes('open'),
                derivation: 'implicit-open',
                lifecycle: occurrence.authoritative ? 'new' : 'unknown',
                currentOccurrenceIds: [occurrence.occurrenceId],
                eventId: null,
                basisEventIds: [],
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
        }
    }
    const activeEvents = [...activeReconciliations.values()].filter((event) => [...event.beforeOccurrenceIds, ...event.afterOccurrenceIds].every((occurrenceId) => {
        const occurrence = index.occurrences.get(occurrenceId);
        return index.observations.get(occurrence.observationId).publicationState !== 'history-ahead';
    }));
    const explicitIncomingOccurrenceIds = new Set(activeEvents.flatMap((event) => event.afterOccurrenceIds));
    const explicitOutgoingOccurrenceIds = new Set(activeEvents.flatMap((event) => event.beforeOccurrenceIds));
    const stableIdentityEdges = [];
    const stableIdentityPredecessors = new Map();
    for (const finding of index.findings.values()) {
        const publishedBySlug = new Map();
        for (const occurrenceId of finding.occurrenceIds) {
            const occurrence = index.occurrences.get(occurrenceId);
            const observation = index.observations.get(occurrence.observationId);
            if (observation.publicationState === 'history-ahead')
                continue;
            const rows = publishedBySlug.get(observation.slug) ?? [];
            rows.push(occurrenceId);
            publishedBySlug.set(observation.slug, rows);
        }
        for (const rows of publishedBySlug.values()) {
            rows.sort((leftId, rightId) => {
                const left = index.occurrences.get(leftId);
                const right = index.occurrences.get(rightId);
                const leftObservation = index.observations.get(left.observationId);
                const rightObservation = index.observations.get(right.observationId);
                return leftObservation.historyIndex - rightObservation.historyIndex ||
                    utf16Compare(leftId, rightId);
            });
            for (let position = 1; position < rows.length; position += 1) {
                const beforeOccurrenceId = rows[position - 1];
                const afterOccurrenceId = rows[position];
                if (explicitIncomingOccurrenceIds.has(afterOccurrenceId))
                    continue;
                const beforeOccurrence = index.occurrences.get(beforeOccurrenceId);
                const afterOccurrence = index.occurrences.get(afterOccurrenceId);
                stableIdentityEdges.push({
                    kind: 'stable-identity',
                    beforeOccurrenceIds: [beforeOccurrenceId],
                    afterOccurrenceIds: [afterOccurrenceId],
                    outcome: 'equivalent',
                    confidence: 'high',
                    bindingsCompatible: sameBindings(beforeOccurrence.bindings, afterOccurrence.bindings),
                });
                stableIdentityPredecessors.set(afterOccurrenceId, beforeOccurrenceId);
            }
        }
    }
    const crossHistoryEdgeKeys = new Set();
    for (const occurrenceId of explicitOutgoingOccurrenceIds) {
        if (explicitOccurrenceIds.has(occurrenceId) ||
            explicitIncomingOccurrenceIds.has(occurrenceId)) {
            continue;
        }
        const outgoingOccurrence = index.occurrences.get(occurrenceId);
        let seedOccurrenceId = occurrenceId;
        while (stableIdentityPredecessors.has(seedOccurrenceId)) {
            seedOccurrenceId = stableIdentityPredecessors.get(seedOccurrenceId);
        }
        if (explicitOccurrenceIds.has(seedOccurrenceId) ||
            explicitIncomingOccurrenceIds.has(seedOccurrenceId)) {
            continue;
        }
        const seedOccurrence = index.occurrences.get(seedOccurrenceId);
        const latestDisposition = dispositionsByFinding
            .get(outgoingOccurrence.findingId)
            ?.at(-1);
        if (latestDisposition === undefined ||
            latestDisposition.event.occurrenceId === seedOccurrenceId) {
            continue;
        }
        const sourceOccurrence = index.occurrences.get(latestDisposition.event.occurrenceId);
        const sourceObservation = index.observations.get(sourceOccurrence.observationId);
        const targetObservation = index.observations.get(seedOccurrence.observationId);
        if (sourceObservation.publicationState === 'history-ahead' ||
            targetObservation.publicationState === 'history-ahead' ||
            sourceObservation.slug === targetObservation.slug) {
            continue;
        }
        const edgeKey = `${sourceOccurrence.occurrenceId}\0${seedOccurrenceId}`;
        if (crossHistoryEdgeKeys.has(edgeKey))
            continue;
        crossHistoryEdgeKeys.add(edgeKey);
        stableIdentityEdges.push({
            kind: 'stable-identity',
            beforeOccurrenceIds: [sourceOccurrence.occurrenceId],
            afterOccurrenceIds: [seedOccurrenceId],
            outcome: 'equivalent',
            confidence: 'high',
            bindingsCompatible: sameBindings(sourceOccurrence.bindings, seedOccurrence.bindings),
        });
    }
    const lifecycleEdges = [
        ...stableIdentityEdges,
        ...activeEvents.map((event) => ({
            kind: 'reconciliation',
            beforeOccurrenceIds: event.beforeOccurrenceIds,
            afterOccurrenceIds: event.afterOccurrenceIds,
            outcome: event.outcome,
            confidence: event.confidence,
            bindingsCompatible: true,
        })),
    ];
    const incomingOccurrenceIds = new Set(lifecycleEdges.flatMap((event) => event.afterOccurrenceIds));
    const resolvedOccurrenceIds = new Set([...index.occurrences.keys()].filter((occurrenceId) => explicitOccurrenceIds.has(occurrenceId) ||
        !incomingOccurrenceIds.has(occurrenceId)));
    const affectedCurrentByFinding = new Map();
    const publishedOccurrenceIdsByFinding = new Map();
    for (const occurrence of index.occurrences.values()) {
        if (index.observations.get(occurrence.observationId).publicationState === 'history-ahead') {
            continue;
        }
        const published = publishedOccurrenceIdsByFinding.get(occurrence.findingId) ?? new Set();
        published.add(occurrence.occurrenceId);
        publishedOccurrenceIdsByFinding.set(occurrence.findingId, published);
    }
    const lifecycleSuccessorIds = new Set(lifecycleEdges
        .filter((event) => event.outcome !== 'distinct')
        .flatMap((event) => event.beforeOccurrenceIds));
    const lifecycleComponentParents = new Map();
    const lifecycleComponent = (occurrenceId) => {
        let root = occurrenceId;
        while (true) {
            const parent = lifecycleComponentParents.get(root);
            if (parent === undefined || parent === root)
                break;
            root = parent;
        }
        let cursor = occurrenceId;
        while (cursor !== root) {
            const parent = lifecycleComponentParents.get(cursor);
            if (parent === undefined || parent === cursor)
                break;
            lifecycleComponentParents.set(cursor, root);
            cursor = parent;
        }
        return root;
    };
    const joinLifecycleComponents = (leftOccurrenceId, rightOccurrenceId) => {
        const leftRoot = lifecycleComponent(leftOccurrenceId);
        const rightRoot = lifecycleComponent(rightOccurrenceId);
        if (leftRoot === rightRoot)
            return;
        const [parent, child] = [leftRoot, rightRoot].sort(utf16Compare);
        lifecycleComponentParents.set(child, parent);
    };
    for (const event of lifecycleEdges) {
        if (event.outcome === 'distinct')
            continue;
        const occurrenceIds = [
            ...event.beforeOccurrenceIds,
            ...event.afterOccurrenceIds,
        ];
        const firstOccurrenceId = occurrenceIds[0];
        for (const occurrenceId of occurrenceIds.slice(1)) {
            joinLifecycleComponents(firstOccurrenceId, occurrenceId);
        }
    }
    for (const event of lifecycleEdges) {
        if (event.outcome === 'distinct')
            continue;
        for (const occurrenceId of event.afterOccurrenceIds) {
            const occurrence = index.occurrences.get(occurrenceId);
            if (!occurrence.authoritative)
                continue;
            const affected = affectedCurrentByFinding.get(occurrence.findingId) ??
                new Set();
            affected.add(occurrenceId);
            affectedCurrentByFinding.set(occurrence.findingId, affected);
        }
    }
    const basisIdsForStates = (states) => sortedIds(states.flatMap((state) => state.eventId === null ? state.basisEventIds : [state.eventId]));
    const dispositionRowsForBasis = (basisEventIds) => basisEventIds
        .map((eventId) => index.events.get(eventId))
        .filter((row) => row?.event.type === 'finding-disposition');
    const reconciliationTemplate = (event, priorStates) => {
        const basisEventIds = basisIdsForStates(priorStates);
        if (event.outcome !== 'equivalent' || event.confidence !== 'high') {
            return {
                disposition: 'open',
                blocking: true,
                derivation: 'reconciliation-conflict',
                lifecycle: 'unknown',
                eventId: null,
                basisEventIds,
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            };
        }
        const basisRows = dispositionRowsForBasis(basisEventIds);
        const retainedAction = basisRows.length > 0 &&
            basisRows.every((row) => row.event.action === basisRows[0].event.action) &&
            (basisRows[0].event.action === 'accepted-risk' ||
                basisRows[0].event.action === 'separate-design')
            ? basisRows[0].event.action
            : null;
        const terminalAction = priorStates.length > 0 &&
            priorStates.every((state) => state.disposition === priorStates[0].disposition) &&
            (priorStates[0].disposition === 'remediated' ||
                priorStates[0].disposition === 'false-positive' ||
                priorStates[0].disposition === 'superseded')
            ? priorStates[0].disposition
            : null;
        const allOpen = priorStates.length > 0 &&
            priorStates.every((state) => state.disposition === 'open' || state.disposition === 'reopened');
        if (retainedAction !== null) {
            const owners = new Set(basisRows.map((row) => row.event.owner));
            const contexts = new Set(basisRows.map((row) => `${row.event.reviewContext.ruleset.id}\0` +
                `${row.event.reviewContext.ruleset.digest}\0` +
                row.event.reviewContext.policyDigest));
            const referenceRuleset = basisRows[0]?.event.reviewContext.ruleset;
            const afterContextsMatch = referenceRuleset !== undefined &&
                event.afterOccurrenceIds.every((occurrenceId) => {
                    const occurrence = index.occurrences.get(occurrenceId);
                    return occurrence.closureEligible &&
                        occurrence.ruleset?.id === referenceRuleset.id &&
                        occurrence.ruleset.digest === referenceRuleset.digest;
                });
            const compatible = priorStates.every((state) => state.disposition === retainedAction) &&
                basisRows.every((row) => {
                    const status = policyStatus(row);
                    return row.event.action === retainedAction &&
                        status.contextCurrent &&
                        status.expiryState !== 'expired';
                }) &&
                owners.size === 1 &&
                contexts.size === 1 &&
                afterContextsMatch &&
                event.bindingsCompatible;
            const expiries = basisRows
                .map((row) => row.event.action === 'accepted-risk' ||
                row.event.action === 'separate-design'
                ? row.event.expiresAt
                : null)
                .filter((expiry) => expiry !== null)
                .sort(utf16Compare);
            const expiresAt = expiries[0] ?? null;
            const expiryState = expiresAt === null
                ? 'not-applicable'
                : nowMilliseconds >= Date.parse(expiresAt)
                    ? 'expired'
                    : Date.parse(expiresAt) <=
                        nowMilliseconds + policy.expiry.warningDays * dayMilliseconds
                        ? 'warning'
                        : 'active';
            return compatible
                ? {
                    disposition: retainedAction,
                    blocking: explicitBlocking(retainedAction),
                    derivation: 'carried',
                    lifecycle: 'persisting',
                    eventId: null,
                    basisEventIds,
                    expiresAt,
                    expiryState,
                    reopenAcknowledged: false,
                }
                : event.beforeOccurrenceIds.length > 1
                    ? {
                        disposition: 'open',
                        blocking: true,
                        derivation: 'reconciliation-conflict',
                        lifecycle: 'unknown',
                        eventId: null,
                        basisEventIds,
                        expiresAt: null,
                        expiryState: 'not-applicable',
                        reopenAcknowledged: false,
                    }
                    : {
                        disposition: 'open',
                        blocking: true,
                        derivation: 'carry-invalidated',
                        lifecycle: 'persisting',
                        eventId: null,
                        basisEventIds,
                        expiresAt,
                        expiryState,
                        reopenAcknowledged: false,
                    };
        }
        if (terminalAction !== null) {
            return {
                disposition: 'reopened',
                blocking: true,
                derivation: 'automatic-reopen',
                lifecycle: 'reopened',
                eventId: null,
                basisEventIds,
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            };
        }
        if (allOpen) {
            return {
                disposition: 'open',
                blocking: true,
                derivation: 'carried',
                lifecycle: 'persisting',
                eventId: null,
                basisEventIds,
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            };
        }
        return {
            disposition: 'open',
            blocking: true,
            derivation: 'reconciliation-conflict',
            lifecycle: 'unknown',
            eventId: null,
            basisEventIds,
            expiresAt: null,
            expiryState: 'not-applicable',
            reopenAcknowledged: false,
        };
    };
    const unresolvedBeforeCounts = new Array(lifecycleEdges.length).fill(0);
    const waitingEdgesByOccurrence = new Map();
    const readyEdgeIndexes = [];
    const pushReadyEdge = (edgeIndex) => {
        let position = readyEdgeIndexes.length;
        readyEdgeIndexes.push(edgeIndex);
        while (position > 0) {
            const parent = Math.floor((position - 1) / 2);
            if (readyEdgeIndexes[parent] <= edgeIndex)
                break;
            readyEdgeIndexes[position] = readyEdgeIndexes[parent];
            position = parent;
        }
        readyEdgeIndexes[position] = edgeIndex;
    };
    const popReadyEdge = () => {
        const result = readyEdgeIndexes[0];
        const tail = readyEdgeIndexes.pop();
        if (result === undefined || readyEdgeIndexes.length === 0)
            return result;
        let position = 0;
        while (true) {
            const left = position * 2 + 1;
            if (left >= readyEdgeIndexes.length)
                break;
            const right = left + 1;
            const child = right < readyEdgeIndexes.length &&
                readyEdgeIndexes[right] < readyEdgeIndexes[left]
                ? right
                : left;
            if (readyEdgeIndexes[child] >= tail)
                break;
            readyEdgeIndexes[position] = readyEdgeIndexes[child];
            position = child;
        }
        readyEdgeIndexes[position] = tail;
        return result;
    };
    for (const [edgeIndex, event] of lifecycleEdges.entries()) {
        for (const occurrenceId of event.beforeOccurrenceIds) {
            if (resolvedOccurrenceIds.has(occurrenceId))
                continue;
            unresolvedBeforeCounts[edgeIndex] += 1;
            const waiters = waitingEdgesByOccurrence.get(occurrenceId) ?? [];
            waiters.push(edgeIndex);
            waitingEdgesByOccurrence.set(occurrenceId, waiters);
        }
        if (unresolvedBeforeCounts[edgeIndex] === 0) {
            pushReadyEdge(edgeIndex);
        }
    }
    let processedLifecycleEdges = 0;
    while (readyEdgeIndexes.length > 0) {
        const edgeIndex = popReadyEdge();
        const event = lifecycleEdges[edgeIndex];
        processedLifecycleEdges += 1;
        const priorStates = event.beforeOccurrenceIds.map((occurrenceId) => occurrenceStates.get(occurrenceId));
        const template = event.outcome === 'distinct'
            ? null
            : reconciliationTemplate(event, priorStates);
        for (const occurrenceId of event.afterOccurrenceIds) {
            if (template !== null &&
                !explicitOccurrenceIds.has(occurrenceId)) {
                occurrenceStates.set(occurrenceId, {
                    ...template,
                    currentOccurrenceIds: [occurrenceId],
                });
            }
            const newlyResolved = !resolvedOccurrenceIds.has(occurrenceId);
            resolvedOccurrenceIds.add(occurrenceId);
            if (!newlyResolved)
                continue;
            for (const waitingEdgeIndex of waitingEdgesByOccurrence.get(occurrenceId) ?? []) {
                unresolvedBeforeCounts[waitingEdgeIndex] -= 1;
                if (unresolvedBeforeCounts[waitingEdgeIndex] === 0) {
                    pushReadyEdge(waitingEdgeIndex);
                }
            }
        }
    }
    if (processedLifecycleEdges !== lifecycleEdges.length) {
        throw new Error('active reconciliation graph is cyclic or unresolved');
    }
    const frontierOccurrenceIdsByFinding = new Map();
    const globallyConflictedFindingIds = new Set();
    for (const [findingId, publishedOccurrenceIds] of publishedOccurrenceIdsByFinding) {
        const frontierOccurrenceIds = sortedIds([...publishedOccurrenceIds].filter((occurrenceId) => !lifecycleSuccessorIds.has(occurrenceId)));
        frontierOccurrenceIdsByFinding.set(findingId, frontierOccurrenceIds);
        if (frontierOccurrenceIds.length === 0)
            continue;
        const frontierComponentIds = new Set(frontierOccurrenceIds.map(lifecycleComponent));
        if (frontierComponentIds.size <= 1)
            continue;
        const candidates = frontierOccurrenceIds.map((occurrenceId) => occurrenceStates.get(occurrenceId));
        findings.set(findingId, {
            disposition: 'open',
            blocking: true,
            derivation: 'reconciliation-conflict',
            lifecycle: 'unknown',
            currentOccurrenceIds: sortedIds(index.findings.get(findingId).currentOccurrenceIds),
            eventId: null,
            basisEventIds: basisIdsForStates(candidates),
            expiresAt: null,
            expiryState: 'not-applicable',
            reopenAcknowledged: false,
        });
        globallyConflictedFindingIds.add(findingId);
    }
    for (const [findingId, affectedOccurrenceIds] of affectedCurrentByFinding) {
        if (globallyConflictedFindingIds.has(findingId))
            continue;
        const currentOccurrenceIds = sortedIds(index.findings.get(findingId).currentOccurrenceIds);
        const coveredOccurrenceIds = sortedIds([...affectedOccurrenceIds]);
        const candidates = currentOccurrenceIds.map((occurrenceId) => occurrenceStates.get(occurrenceId));
        const first = candidates[0];
        const allDerivedCompatible = candidates.every((candidate) => candidate.eventId === null &&
            candidate.disposition === first.disposition &&
            candidate.blocking === first.blocking &&
            candidate.derivation === first.derivation &&
            candidate.lifecycle === first.lifecycle &&
            candidate.expiresAt === first.expiresAt &&
            candidate.expiryState === first.expiryState &&
            candidate.reopenAcknowledged === first.reopenAcknowledged);
        if (canonicalJson(coveredOccurrenceIds) !==
            canonicalJson(currentOccurrenceIds) ||
            (currentOccurrenceIds.length > 1 && !allDerivedCompatible)) {
            findings.set(findingId, {
                disposition: 'open',
                blocking: true,
                derivation: 'reconciliation-conflict',
                lifecycle: 'unknown',
                currentOccurrenceIds,
                eventId: null,
                basisEventIds: sortedIds(candidates.flatMap((candidate) => candidate.eventId === null
                    ? candidate.basisEventIds
                    : [candidate.eventId])),
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
            continue;
        }
        if (currentOccurrenceIds.length === 1) {
            findings.set(findingId, {
                ...first,
                currentOccurrenceIds,
            });
            continue;
        }
        findings.set(findingId, {
            ...first,
            currentOccurrenceIds,
            basisEventIds: sortedIds(candidates.flatMap((candidate) => candidate.basisEventIds)),
        });
    }
    for (const [findingId, frontierOccurrenceIds] of frontierOccurrenceIdsByFinding) {
        if (globallyConflictedFindingIds.has(findingId))
            continue;
        const finding = index.findings.get(findingId);
        if (finding.currentOccurrenceIds.length > 0)
            continue;
        if (frontierOccurrenceIds.length === 0)
            continue;
        const candidates = frontierOccurrenceIds.map((occurrenceId) => occurrenceStates.get(occurrenceId));
        if (frontierOccurrenceIds.length === 1 &&
            candidates[0].derivation === 'explicit-event') {
            continue;
        }
        const first = candidates[0];
        const compatible = candidates.every((candidate) => candidate.eventId === null &&
            candidate.disposition === first.disposition &&
            candidate.blocking === first.blocking &&
            candidate.derivation === first.derivation &&
            candidate.lifecycle === first.lifecycle &&
            candidate.expiresAt === first.expiresAt &&
            candidate.expiryState === first.expiryState &&
            candidate.reopenAcknowledged === first.reopenAcknowledged);
        if (!compatible) {
            findings.set(findingId, {
                disposition: 'open',
                blocking: true,
                derivation: 'reconciliation-conflict',
                lifecycle: 'unknown',
                currentOccurrenceIds: [],
                eventId: null,
                basisEventIds: basisIdsForStates(candidates),
                expiresAt: null,
                expiryState: 'not-applicable',
                reopenAcknowledged: false,
            });
            continue;
        }
        findings.set(findingId, {
            ...first,
            currentOccurrenceIds: [],
            basisEventIds: basisIdsForStates(candidates),
        });
    }
    const retirements = new Map();
    for (const event of index.retirementEvents) {
        const proofObservationIds = [event.historyProof.observationId];
        if (event.reason === 'superseded' &&
            event.noReplacementProof !== undefined) {
            proofObservationIds.push(event.noReplacementProof.observationId);
        }
        if (proofObservationIds.some((observationId) => index.observations.get(observationId)?.publicationState === 'history-ahead')) {
            continue;
        }
        if (!policy.retirement.allowedReasons.includes(event.reason)) {
            throw new Error(`retirement ${event.eventId} uses a reason not allowed by policy`);
        }
        if (policy.retirement.historyProofRequired &&
            event.historyProof === undefined) {
            throw new Error(`retirement ${event.eventId} lacks required history proof`);
        }
        retirements.set(`${event.path}\0${event.blob}`, event);
    }
    const aliases = new Map();
    for (const event of index.aliasEvents) {
        for (const alias of event.aliases) {
            aliases.set(`${alias.scheme}:${alias.value}`, {
                findingId: event.findingId,
                occurrenceIds: sortedIds(event.occurrenceIds),
                relationship: event.relationship,
                eventId: event.eventId,
            });
        }
    }
    return { findings, retirements, aliases };
}
