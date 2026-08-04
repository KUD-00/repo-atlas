import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TextDecoder } from 'node:util';
import { canonicalJson, normalizeAuditRepoPath, parseBoundedAuditJsonBytes, readBoundedAuditBytes, readBoundedAuditJsonDocument, } from './audit-core.js';
// Provider orchestration for first-party audit producers.
//
// A provider is never invoked implicitly: the only entry point is
// runAuditProviderInvocation, which requires an explicit
// `audit run security` invocation request. No check/status/build/install path
// imports this module's runner. Clone-local resume/transcript state lives
// under `.atlas/.runtime/audit-runs/<invocationId>/` (gitignored, never
// coverage evidence); run receipts contain no wall-clock fields.
export const AUDIT_PROVIDER_INVOCATION_COMMAND = 'audit run security';
export const AUDIT_PROVIDER_PHASE_ORDER = [
    'inventory',
    'review',
    'verification',
    'synthesis',
];
export const AUDIT_PROVIDER_RUNTIME_PATH = '.atlas/.runtime/audit-runs';
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const INVOCATION_ID_PATTERN = /^arun_[0-9a-f]{24}$/;
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ENV_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SEVERITIES = [
    'critical',
    'high',
    'medium',
    'low',
    'informational',
];
const DISPOSITIONS = [
    'reportable',
    'suppressed',
    'not_applicable',
    'deferred',
];
const CONFIDENCES = ['high', 'medium', 'low'];
const MAX_TEXT_BYTES = 256 * 1024;
const MAX_BINARY_DIGEST_BYTES = 256 * 1024 * 1024;
const MAX_JOURNAL_BYTES = 64 * 1024 * 1024;
export class AuditProviderError extends Error {
    code;
    phase;
    constructor(code, message, phase) {
        super(`audit provider ${code}: ${message}`);
        this.name = 'AuditProviderError';
        this.code = code;
        this.phase = phase;
    }
}
function fail(code, message, phase) {
    throw new AuditProviderError(code, message, phase);
}
function sha256Hex(bytes) {
    return createHash('sha256').update(bytes).digest('hex');
}
export function auditProviderSha256(bytes) {
    return `sha256:${sha256Hex(bytes)}`;
}
function canonicalDigest(value) {
    return auditProviderSha256(canonicalJson(value));
}
function gitBlobId(bytes) {
    const digest = createHash('sha1')
        .update(`blob ${bytes.byteLength}\0`, 'utf8')
        .update(bytes)
        .digest('hex');
    return `git-sha1:${digest}`;
}
function isPlainObject(value) {
    return (value !== null &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        Object.getPrototypeOf(value) === Object.prototype);
}
function boundedText(value, description) {
    if (typeof value !== 'string' || value.length === 0) {
        fail('output-invalid', `${description} must be a nonempty string`);
    }
    if (value.includes('\0') || Buffer.byteLength(value, 'utf8') > MAX_TEXT_BYTES) {
        fail('output-invalid', `${description} exceeds the ${MAX_TEXT_BYTES}-byte limit`);
    }
    return value;
}
function optionalBoundedText(value, description) {
    if (value === undefined)
        return undefined;
    return boundedText(value, description);
}
// ---------------------------------------------------------------------------
// Provider policy
// ---------------------------------------------------------------------------
function policyInteger(input, name, fallback, minimum, maximum) {
    if (input === undefined)
        return fallback;
    if (typeof input !== 'number' ||
        !Number.isSafeInteger(input) ||
        input < minimum ||
        input > maximum) {
        fail('policy-invalid', `provider policy ${name} must be an integer between ${minimum} and ${maximum}`);
    }
    return input;
}
export function resolveAuditProviderPolicy(input) {
    if (!isPlainObject(input)) {
        fail('policy-invalid', 'provider policy must be a plain object');
    }
    const values = input;
    const command = values.command ?? 'grok';
    if (typeof command !== 'string' || command.length === 0 || command.includes('\0')) {
        fail('policy-invalid', 'provider policy command must be a nonempty path or name');
    }
    if (typeof values.model !== 'string' ||
        values.model.length === 0 ||
        values.model.includes('\0') ||
        Buffer.byteLength(values.model, 'utf8') > 1024) {
        fail('policy-invalid', 'provider policy requires an explicit model identifier');
    }
    const model = values.model;
    const concurrency = policyInteger(values.concurrency, 'concurrency', Math.max(1, Math.min(4, os.cpus().length)), 1, 64);
    // Attempts, not retries: 1 reproduces the previous abort-on-first-failure.
    const maxAttempts = policyInteger(values.maxAttempts, 'maxAttempts', 3, 1, 5);
    const policy = {
        command,
        model,
        concurrency,
        maxAttempts,
        maxBatchFiles: policyInteger(values.maxBatchFiles, 'maxBatchFiles', 8, 1, 500),
        maxVerificationCandidates: policyInteger(values.maxVerificationCandidates, 'maxVerificationCandidates', 10, 1, 500),
        timeoutMs: policyInteger(values.timeoutMs, 'timeoutMs', 600_000, 50, 3_600_000),
        killGraceMs: policyInteger(values.killGraceMs, 'killGraceMs', 5_000, 50, 60_000),
        maxFileBytes: policyInteger(values.maxFileBytes, 'maxFileBytes', 4 * 1024 * 1024, 1, 64 * 1024 * 1024),
        maxSnapshotFiles: policyInteger(values.maxSnapshotFiles, 'maxSnapshotFiles', 4_096, 1, 100_000),
        maxStdoutBytes: policyInteger(values.maxStdoutBytes, 'maxStdoutBytes', 8 * 1024 * 1024, 1_024, 64 * 1024 * 1024),
        maxStderrBytes: policyInteger(values.maxStderrBytes, 'maxStderrBytes', 1024 * 1024, 1_024, 16 * 1024 * 1024),
        maxResponseBytes: policyInteger(values.maxResponseBytes, 'maxResponseBytes', 1024 * 1024, 1_024, 16 * 1024 * 1024),
        maxResponseDepth: policyInteger(values.maxResponseDepth, 'maxResponseDepth', 48, 4, 256),
        maxTranscriptBytes: policyInteger(values.maxTranscriptBytes, 'maxTranscriptBytes', 16 * 1024 * 1024, 1_024, 64 * 1024 * 1024),
        maxTranscriptEvents: policyInteger(values.maxTranscriptEvents, 'maxTranscriptEvents', 8_192, 1, 1_000_000),
        maxPromptBytes: policyInteger(values.maxPromptBytes, 'maxPromptBytes', 512 * 1024, 1_024, 4 * 1024 * 1024),
        maxFindingsPerFile: policyInteger(values.maxFindingsPerFile, 'maxFindingsPerFile', 64, 1, 1_024),
        authRecordPath: '.grok/auth.json',
        approvedConfigDigests: [],
    };
    if (values.apiKeyEnv !== undefined) {
        if (!ENV_NAME_PATTERN.test(values.apiKeyEnv)) {
            fail('policy-invalid', 'provider policy apiKeyEnv must be an environment variable name');
        }
        policy.apiKeyEnv = values.apiKeyEnv;
    }
    if (values.authRecordPath !== undefined) {
        try {
            normalizeAuditRepoPath(values.authRecordPath);
        }
        catch {
            fail('policy-invalid', 'provider policy authRecordPath must be a safe home-relative path');
        }
        policy.authRecordPath = values.authRecordPath;
    }
    if (values.approvedConfigDigests !== undefined) {
        if (!Array.isArray(values.approvedConfigDigests) ||
            values.approvedConfigDigests.length > 1_024 ||
            values.approvedConfigDigests.some((digest) => typeof digest !== 'string' || !SHA256_PATTERN.test(digest))) {
            fail('policy-invalid', 'provider policy approvedConfigDigests must be a bounded list of sha256 digests');
        }
        policy.approvedConfigDigests = [...values.approvedConfigDigests];
    }
    return policy;
}
const PROVIDER_POLICY_PATH = '.atlas/audit-providers.json';
const PROVIDER_POLICY_KEYS = new Set([
    'formatVersion',
    'format',
    'provider',
    'command',
    'model',
    'concurrency',
    'maxAttempts',
    'maxBatchFiles',
    'maxVerificationCandidates',
    'timeoutMs',
    'killGraceMs',
    'maxFileBytes',
    'maxSnapshotFiles',
    'maxStdoutBytes',
    'maxStderrBytes',
    'maxResponseBytes',
    'maxResponseDepth',
    'maxTranscriptBytes',
    'maxTranscriptEvents',
    'maxPromptBytes',
    'maxFindingsPerFile',
    'apiKeyEnv',
    'authRecordPath',
    'approvedConfigDigests',
]);
export function loadAuditProviderPolicy(root) {
    let document;
    try {
        document = readBoundedAuditJsonDocument(root, PROVIDER_POLICY_PATH, 1024 * 1024);
    }
    catch (error) {
        const code = error && typeof error === 'object' && 'code' in error
            ? String(error.code)
            : undefined;
        if (code === 'ENOENT' ||
            code === 'ENOTDIR' ||
            (error instanceof Error &&
                (error.message.includes('is missing or not a safe regular file') ||
                    error.message.includes('audit parent is missing')))) {
            return null;
        }
        throw error;
    }
    const value = document.value;
    if (!isPlainObject(value)) {
        fail('policy-invalid', `${PROVIDER_POLICY_PATH} must be a plain JSON object`);
    }
    for (const key of Object.keys(value)) {
        if (!PROVIDER_POLICY_KEYS.has(key)) {
            fail('policy-invalid', `${PROVIDER_POLICY_PATH} has unknown field ${key}`);
        }
    }
    if (value.formatVersion !== 1 || value.format !== 'atlas-audit-providers/v1') {
        fail('policy-invalid', `${PROVIDER_POLICY_PATH} must declare format atlas-audit-providers/v1`);
    }
    if (value.provider !== 'grok') {
        fail('policy-invalid', `${PROVIDER_POLICY_PATH} provider must be "grok"`);
    }
    if (typeof value.model !== 'string' || value.model.length === 0) {
        fail('policy-invalid', `${PROVIDER_POLICY_PATH} requires an explicit model`);
    }
    const input = { model: value.model };
    for (const key of [
        'command',
        'apiKeyEnv',
        'authRecordPath',
    ]) {
        if (value[key] !== undefined) {
            if (typeof value[key] !== 'string') {
                fail('policy-invalid', `${PROVIDER_POLICY_PATH} ${key} must be a string`);
            }
            input[key] = value[key];
        }
    }
    for (const key of [
        'concurrency',
        'maxAttempts',
        'maxBatchFiles',
        'maxVerificationCandidates',
        'timeoutMs',
        'killGraceMs',
        'maxFileBytes',
        'maxSnapshotFiles',
        'maxStdoutBytes',
        'maxStderrBytes',
        'maxResponseBytes',
        'maxResponseDepth',
        'maxTranscriptBytes',
        'maxTranscriptEvents',
        'maxPromptBytes',
        'maxFindingsPerFile',
    ]) {
        if (value[key] !== undefined)
            input[key] = value[key];
    }
    if (value.approvedConfigDigests !== undefined) {
        input.approvedConfigDigests = value.approvedConfigDigests;
    }
    // Reuse the resolver for range/shape validation, then return the sparse input.
    resolveAuditProviderPolicy(input);
    return input;
}
// ---------------------------------------------------------------------------
// Invocation request validation (structural explicitness)
// ---------------------------------------------------------------------------
function validateResolvedPolicy(policy) {
    if (!isPlainObject(policy)) {
        fail('policy-invalid', 'resolved provider policy must be a plain object');
    }
    resolveAuditProviderPolicy(policy);
}
function validateInvocationRequest(request) {
    if (!isPlainObject(request)) {
        fail('invalid-request', 'provider invocation must be an explicit request object');
    }
    if (request.command !== AUDIT_PROVIDER_INVOCATION_COMMAND) {
        fail('invalid-request', `providers run only through an explicit \`${AUDIT_PROVIDER_INVOCATION_COMMAND}\` request`);
    }
    if (request.provider !== 'grok') {
        fail('invalid-request', 'the only first-party provider is "grok"');
    }
    if (typeof request.repoRoot !== 'string' ||
        request.repoRoot.length === 0 ||
        request.repoRoot.includes('\0')) {
        fail('invalid-request', 'provider invocation repoRoot must be a nonempty path');
    }
    validateResolvedPolicy(request.policy);
    if (!Array.isArray(request.targets) || request.targets.length === 0) {
        fail('invalid-request', 'provider invocation requires an explicit nonempty target list');
    }
    if (request.targets.length > request.policy.maxSnapshotFiles) {
        fail('invalid-request', `provider invocation exceeds the ${request.policy.maxSnapshotFiles}-file snapshot limit`);
    }
    const seen = new Set();
    const targets = [];
    for (const rawTarget of request.targets) {
        if (!isPlainObject(rawTarget)) {
            fail('invalid-request', 'provider invocation targets must be plain objects');
        }
        const target = rawTarget;
        let normalized;
        try {
            normalized = normalizeAuditRepoPath(typeof target.path === 'string' ? target.path : '');
        }
        catch {
            fail('invalid-request', `provider target path is unsafe: ${String(target.path)}`);
        }
        if (seen.has(normalized)) {
            fail('invalid-request', `provider target path is duplicated: ${normalized}`);
        }
        seen.add(normalized);
        const role = target.role ?? 'review';
        if (role !== 'review' && role !== 'context') {
            fail('invalid-request', `provider target role is unsupported: ${String(target.role)}`);
        }
        targets.push({ path: normalized, role });
    }
    if (!targets.some((target) => target.role === 'review')) {
        fail('invalid-request', 'provider invocation requires at least one review target');
    }
    if (request.extraPrompt !== undefined) {
        if (typeof request.extraPrompt !== 'string' ||
            request.extraPrompt.includes('\0') ||
            Buffer.byteLength(request.extraPrompt, 'utf8') > request.policy.maxPromptBytes) {
            fail('invalid-request', 'provider invocation extraPrompt is not bounded text');
        }
    }
    if (request.resumeInvocationId !== undefined &&
        !INVOCATION_ID_PATTERN.test(request.resumeInvocationId)) {
        fail('invalid-request', 'provider resume id must be an atlas run id (arun_...)');
    }
    if (request.reuseUnchangedReceipts !== undefined &&
        typeof request.reuseUnchangedReceipts !== 'boolean') {
        fail('invalid-request', 'provider reuseUnchangedReceipts must be a boolean when present');
    }
    return targets;
}
function validateProviderShape(provider, requestProvider) {
    if (!isPlainObject(provider) || typeof provider.run !== 'function') {
        fail('invalid-request', 'provider must implement the AuditProvider interface');
    }
    if (provider.name !== requestProvider) {
        fail('invalid-request', `provider ${String(provider.name)} does not match the explicit request for ${requestProvider}`);
    }
    const descriptor = provider.descriptor;
    if (!isPlainObject(descriptor) || descriptor.provider !== requestProvider) {
        fail('invalid-request', 'provider descriptor does not match the explicit request');
    }
    if (typeof descriptor.adapter !== 'string' ||
        typeof descriptor.adapterVersion !== 'string' ||
        typeof descriptor.rulesetId !== 'string' ||
        typeof descriptor.promptBuiltinVersion !== 'string' ||
        typeof descriptor.promptTemplateDigest !== 'string' ||
        !SHA256_PATTERN.test(descriptor.promptTemplateDigest) ||
        !Array.isArray(descriptor.tools) ||
        descriptor.tools.some((tool) => typeof tool !== 'string') ||
        !Array.isArray(descriptor.permissionFlags) ||
        descriptor.permissionFlags.some((flag) => typeof flag !== 'string')) {
        fail('invalid-request', 'provider descriptor is incomplete');
    }
}
function countLines(bytes, repoPath) {
    let text;
    try {
        text = UTF8.decode(bytes);
    }
    catch {
        fail('invalid-request', `provider target is not strict UTF-8 text: ${repoPath}`);
    }
    if (text.length === 0)
        return 0;
    let lines = 0;
    for (let index = 0; index < text.length; index += 1) {
        if (text.charCodeAt(index) === 0x0a)
            lines += 1;
    }
    return text.endsWith('\n') ? lines : lines + 1;
}
function createProviderSnapshot(repoRoot, targets, snapshotRoot, policy) {
    const directories = [snapshotRoot];
    fs.mkdirSync(snapshotRoot, { recursive: true, mode: 0o755 });
    const entries = [];
    for (const target of targets) {
        const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes);
        const destination = path.join(snapshotRoot, ...target.path.split('/'));
        const parent = path.dirname(destination);
        if (!fs.existsSync(parent)) {
            fs.mkdirSync(parent, { recursive: true, mode: 0o755 });
            let current = parent;
            while (current !== snapshotRoot && current.startsWith(snapshotRoot)) {
                directories.push(current);
                current = path.dirname(current);
            }
        }
        fs.writeFileSync(destination, bytes, { mode: 0o444 });
        fs.chmodSync(destination, 0o444);
        entries.push({
            path: target.path,
            role: target.role ?? 'review',
            sha256: auditProviderSha256(bytes),
            blob: gitBlobId(bytes),
            bytes: bytes.byteLength,
            lines: countLines(bytes, target.path),
        });
    }
    entries.sort((left, right) => left.path.localeCompare(right.path));
    for (const directory of directories) {
        fs.chmodSync(directory, 0o555);
    }
    return entries;
}
function buildSnapshotManifest(entries) {
    return {
        formatVersion: 1,
        format: 'atlas-audit-snapshot/v1',
        files: [...entries],
    };
}
function assertSnapshotIntact(snapshotRoot, manifest, policy) {
    const discovered = [];
    const walk = (directory, relative) => {
        let children;
        try {
            children = fs.readdirSync(directory, { withFileTypes: true });
        }
        catch {
            fail('snapshot-mismatch', `snapshot directory is unreadable: ${relative || '.'}`);
        }
        if (discovered.length + children.length > policy.maxSnapshotFiles + 64) {
            fail('snapshot-mismatch', 'snapshot contains unexpected extra entries');
        }
        for (const child of children) {
            const childRelative = relative ? `${relative}/${child.name}` : child.name;
            const childPath = path.join(directory, child.name);
            if (child.isDirectory()) {
                const stat = fs.lstatSync(childPath);
                if ((stat.mode & 0o222) !== 0) {
                    fail('snapshot-mismatch', `snapshot directory became writable: ${childRelative}`);
                }
                walk(childPath, childRelative);
            }
            else if (child.isFile()) {
                discovered.push(childRelative);
            }
            else {
                fail('snapshot-mismatch', `snapshot entry is not a regular file: ${childRelative}`);
            }
        }
    };
    walk(snapshotRoot, '');
    const expected = new Map(manifest.files.map((entry) => [entry.path, entry]));
    if (discovered.length !== expected.size) {
        fail('snapshot-mismatch', 'snapshot file count differs from the canonical manifest');
    }
    for (const repoPath of discovered) {
        const entry = expected.get(repoPath);
        if (entry === undefined) {
            fail('snapshot-mismatch', `snapshot contains an unexpected file: ${repoPath}`);
        }
        const absolute = path.join(snapshotRoot, ...repoPath.split('/'));
        const stat = fs.lstatSync(absolute);
        if (stat.isSymbolicLink() || !stat.isFile()) {
            fail('snapshot-mismatch', `snapshot file changed type: ${repoPath}`);
        }
        if ((stat.mode & 0o222) !== 0) {
            fail('snapshot-mismatch', `snapshot file became writable: ${repoPath}`);
        }
        if (Number(stat.size) !== entry.bytes) {
            fail('snapshot-mismatch', `snapshot file changed size: ${repoPath}`);
        }
        const bytes = fs.readFileSync(absolute);
        if (auditProviderSha256(bytes) !== entry.sha256) {
            fail('snapshot-mismatch', `snapshot bytes changed for ${repoPath}`);
        }
    }
}
function hashOriginalTargets(repoRoot, targets, policy) {
    const hashes = new Map();
    for (const target of targets) {
        const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes);
        hashes.set(target.path, auditProviderSha256(bytes));
    }
    return hashes;
}
function assertOriginalsUnchanged(repoRoot, targets, policy, before) {
    for (const target of targets) {
        let digest;
        try {
            const bytes = readBoundedAuditBytes(repoRoot, target.path, policy.maxFileBytes);
            digest = auditProviderSha256(bytes);
        }
        catch {
            fail('source-mutation', `tracked source ${target.path} became unreadable during the provider run`);
        }
        if (digest !== before.get(target.path)) {
            fail('source-mutation', `tracked source bytes changed during the provider run: ${target.path}`);
        }
    }
}
function journalPath(resumeDir) {
    return path.join(resumeDir, 'journal.json');
}
function chunkFilePath(resumeDir, chunkId) {
    return path.join(resumeDir, 'chunks', `${chunkId}.json`);
}
function writeJournalFile(resumeDir, journal) {
    const destination = journalPath(resumeDir);
    const temporary = `${destination}.tmp-${process.pid}`;
    fs.writeFileSync(temporary, `${canonicalJson(journal)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, destination);
    fs.chmodSync(destination, 0o600);
}
function writeChunkRecord(resumeDir, chunk, output) {
    const chunksDir = path.join(resumeDir, 'chunks');
    fs.mkdirSync(chunksDir, { recursive: true, mode: 0o700 });
    const destination = chunkFilePath(resumeDir, chunk.chunkId);
    const record = {
        formatVersion: 1,
        format: 'atlas-audit-provider-chunk/v1',
        chunk,
        output,
    };
    const temporary = `${destination}.tmp-${process.pid}`;
    fs.writeFileSync(temporary, `${canonicalJson(record)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, destination);
    fs.chmodSync(destination, 0o600);
}
function readChunkRecord(resumeDir, chunkId) {
    let bytes;
    try {
        bytes = fs.readFileSync(chunkFilePath(resumeDir, chunkId));
    }
    catch {
        return null;
    }
    if (bytes.byteLength > MAX_JOURNAL_BYTES)
        return null;
    let value;
    try {
        value = parseBoundedAuditJsonBytes(bytes, MAX_JOURNAL_BYTES, 'provider chunk');
    }
    catch {
        return null;
    }
    if (!isPlainObject(value))
        return null;
    if (value.formatVersion !== 1 || value.format !== 'atlas-audit-provider-chunk/v1') {
        return null;
    }
    if (!isPlainObject(value.chunk) || value.output === undefined)
        return null;
    return {
        chunk: value.chunk,
        output: value.output,
    };
}
function validateResumeSource(resumeSourceDir, invocationId) {
    let bytes;
    try {
        bytes = fs.readFileSync(journalPath(resumeSourceDir));
    }
    catch {
        fail('resume-invalid', `resume source ${invocationId} has no readable clone-local journal`);
    }
    let value;
    try {
        value = parseBoundedAuditJsonBytes(bytes, MAX_JOURNAL_BYTES, 'provider journal');
    }
    catch {
        fail('resume-invalid', `resume source ${invocationId} journal is not valid JSON`);
    }
    if (!isPlainObject(value) ||
        value.formatVersion !== 1 ||
        value.format !== 'atlas-audit-provider-journal/v1' ||
        value.invocationId !== invocationId) {
        fail('resume-invalid', `resume source ${invocationId} journal is not a matching run`);
    }
}
// ---------------------------------------------------------------------------
// Chunk digests and resume
// ---------------------------------------------------------------------------
function chunkContentDigest(chunk) {
    return canonicalDigest(chunk);
}
function makeChunk(phase, unit, inputDigest, execution) {
    const chunkId = `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}`;
    const base = {
        chunkId,
        phase,
        unit,
        inputDigest,
        outputDigest: canonicalDigest(execution.output),
        processCount: execution.processCount,
        sessionIds: [...execution.sessionIds],
        transcriptDigests: [...execution.transcriptDigests],
    };
    return { ...base, digest: chunkContentDigest(base) };
}
function verifyChunkRecord(record, phase, unit, inputDigest) {
    const { chunk, output } = record;
    if (chunk.chunkId !== `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}` ||
        chunk.phase !== phase ||
        chunk.unit !== unit ||
        chunk.inputDigest !== inputDigest ||
        !SHA256_PATTERN.test(chunk.digest) ||
        !SHA256_PATTERN.test(chunk.outputDigest) ||
        !Array.isArray(chunk.sessionIds) ||
        !Array.isArray(chunk.transcriptDigests)) {
        return false;
    }
    const { digest, ...rest } = chunk;
    if (chunkContentDigest(rest) !== digest)
        return false;
    return canonicalDigest(output) === chunk.outputDigest;
}
// ---------------------------------------------------------------------------
// Unit output validation (fail-closed, reused for fresh and resumed outputs)
// ---------------------------------------------------------------------------
export function validateAuditProviderReviewUnitOutput(output, files, policy, 
/**
 * Resolves a path against the run's inventory. Without it every off-batch
 * receipt is treated as unverifiable, which is the conservative default for
 * callers that cannot check.
 */
inventoryHas) {
    if (!isPlainObject(output) || !Array.isArray(output.receipts)) {
        fail('output-invalid', 'review unit output must be an object with a receipts array', 'review');
    }
    const expected = new Map(files.map((file) => [file.path, file]));
    const seen = new Set();
    const receipts = [];
    /** Real files this batch did not own; kept, and owned by whichever batch has them. */
    const offBatchReceipts = [];
    /** Paths that exist nowhere. Rejected individually and reported. */
    const fabricatedReceipts = [];
    for (const raw of output.receipts) {
        if (!isPlainObject(raw)) {
            fail('output-invalid', 'review receipt must be a plain object', 'review');
        }
        const receiptPath = typeof raw.path === 'string' ? raw.path : '';
        const file = expected.get(receiptPath);
        if (file === undefined) {
            // Two very different things used to share one hard failure.
            //
            // A receipt for a REAL file outside this batch is a genuine review of a
            // genuine file — another batch owns its coverage, so this one keeps the
            // observation and moves on. Discarding it would throw away work; failing
            // on it aborts a completed run over a bookkeeping detail.
            //
            // A receipt for a path that exists nowhere in the inventory is a
            // fabrication, and it is the one case that must not be absorbed quietly:
            // the generator invented `capabilities/devices/index.ts`,
            // `capabilities/packets/index.ts`, and `capabilities/votes.test.ts` on
            // three separate runs, none of which exist. That single receipt is
            // rejected and recorded; the rest of the unit still stands or falls on its
            // own proof.
            if (receiptPath !== '' && inventoryHas?.(receiptPath) === true) {
                offBatchReceipts.push(receiptPath);
                continue;
            }
            fabricatedReceipts.push(receiptPath || '<missing>');
            continue;
        }
        if (seen.has(receiptPath)) {
            fail('missing-file-receipt', `duplicate review receipt for ${receiptPath}`, 'review');
        }
        seen.add(receiptPath);
        if (raw.status !== 'reviewed') {
            fail('output-invalid', `review receipt for ${receiptPath} is not marked reviewed`, 'review');
        }
        if (raw.outcome !== 'clean' && raw.outcome !== 'findings') {
            fail('output-invalid', `review receipt for ${receiptPath} has an invalid outcome`, 'review');
        }
        if (!Array.isArray(raw.findings) || raw.findings.length > policy.maxFindingsPerFile) {
            fail('output-invalid', `review receipt for ${receiptPath} has unbounded findings`, 'review');
        }
        if (raw.outcome === 'findings' && raw.findings.length === 0) {
            fail('output-invalid', `findings review receipt for ${receiptPath} carries none`, 'review');
        }
        // A clean receipt may still list the candidates the model evaluated:
        // every listed candidate flows to independent verification, and the
        // terminal disposition decides. Synthesis rejects a candidate the fact
        // checker confirms reportable on a clean receipt as a contradiction;
        // terminally non-reportable candidates are preserved as evidence.
        const findings = [];
        for (const rawFinding of raw.findings) {
            if (!isPlainObject(rawFinding)) {
                fail('output-invalid', `finding on ${receiptPath} must be a plain object`, 'review');
            }
            const severity = rawFinding.severity;
            if (!SEVERITIES.includes(severity)) {
                fail('output-invalid', `finding on ${receiptPath} has an invalid severity`, 'review');
            }
            const confidence = rawFinding.confidence;
            if (!CONFIDENCES.includes(confidence)) {
                fail('output-invalid', `finding on ${receiptPath} has an invalid confidence`, 'review');
            }
            const startLine = rawFinding.startLine;
            if (typeof startLine !== 'number' || !Number.isSafeInteger(startLine) || startLine < 1 || startLine > Math.max(1, file.lines)) {
                // Carry the numbers: "out of range" alone cannot tell a hallucinated
                // citation from an off-by-one at EOF, and re-running a provider to find
                // out costs a whole audit run.
                fail('output-invalid', `finding on ${receiptPath} has an out-of-range startLine (observed ${String(startLine)}, file has ${String(file.lines)} lines)`, 'review');
            }
            let endLine;
            if (rawFinding.endLine !== undefined) {
                if (typeof rawFinding.endLine !== 'number' ||
                    !Number.isSafeInteger(rawFinding.endLine) ||
                    rawFinding.endLine < startLine ||
                    rawFinding.endLine > Math.max(1, file.lines)) {
                    fail('output-invalid', `finding on ${receiptPath} has an out-of-range endLine (observed ${String(rawFinding.endLine)}, startLine ${String(startLine)}, file has ${String(file.lines)} lines)`, 'review');
                }
                endLine = rawFinding.endLine;
            }
            findings.push({
                ruleId: boundedText(rawFinding.ruleId, `finding ruleId on ${receiptPath}`),
                title: boundedText(rawFinding.title, `finding title on ${receiptPath}`),
                severity,
                confidence,
                summary: boundedText(rawFinding.summary, `finding summary on ${receiptPath}`),
                startLine,
                ...(endLine !== undefined ? { endLine } : {}),
                detail: boundedText(rawFinding.detail, `finding detail on ${receiptPath}`),
                fix: boundedText(rawFinding.fix, `finding fix on ${receiptPath}`),
            });
        }
        receipts.push({
            path: receiptPath,
            status: 'reviewed',
            outcome: raw.outcome,
            summary: boundedText(raw.summary, `review summary for ${receiptPath}`),
            findings,
        });
    }
    // Visible, not swallowed: an inventory-absent path is a fabrication, and the
    // operator has to be able to see that a unit produced one even though the run
    // continued past it.
    if (fabricatedReceipts.length > 0) {
        process.stderr.write(`audit provider warning: rejected ${String(fabricatedReceipts.length)} receipt(s) for path(s) absent from the inventory: ${fabricatedReceipts.join(', ')}\n`);
    }
    if (offBatchReceipts.length > 0) {
        process.stderr.write(`audit provider note: ${String(offBatchReceipts.length)} receipt(s) named real files owned by another batch, which covers them: ${offBatchReceipts.join(', ')}\n`);
    }
    for (const file of files) {
        if (!seen.has(file.path)) {
            fail('missing-file-receipt', `review output is missing the required receipt for ${file.path}`, 'review');
        }
    }
    return { receipts };
}
export function validateAuditProviderVerificationUnitOutput(output, candidates, policy) {
    void policy;
    if (!isPlainObject(output) || !Array.isArray(output.dispositions)) {
        fail('output-invalid', 'verification unit output must be an object with a dispositions array', 'verification');
    }
    const expected = new Set(candidates.map((candidate) => candidate.fingerprint));
    const seen = new Set();
    const dispositions = [];
    for (const raw of output.dispositions) {
        if (!isPlainObject(raw)) {
            fail('output-invalid', 'verification disposition must be a plain object', 'verification');
        }
        const fingerprint = typeof raw.fingerprint === 'string' ? raw.fingerprint : '';
        if (!expected.has(fingerprint)) {
            fail('output-invalid', `verification output references an unknown candidate: ${fingerprint || '<missing>'}`, 'verification');
        }
        if (seen.has(fingerprint)) {
            fail('output-invalid', `duplicate verification disposition for ${fingerprint}`, 'verification');
        }
        seen.add(fingerprint);
        if (!DISPOSITIONS.includes(raw.disposition)) {
            fail('output-invalid', `verification disposition for ${fingerprint} is not terminal`, 'verification');
        }
        dispositions.push({
            fingerprint,
            disposition: raw.disposition,
            rationale: boundedText(raw.rationale, `verification rationale for ${fingerprint}`),
        });
    }
    for (const candidate of candidates) {
        if (!seen.has(candidate.fingerprint)) {
            fail('output-invalid', `verification output is missing a terminal disposition for ${candidate.fingerprint}`, 'verification');
        }
    }
    return { dispositions };
}
// ---------------------------------------------------------------------------
// Finding identity
// ---------------------------------------------------------------------------
/**
 * Stable anchor for a finding: the normalized SOURCE TEXT it points at.
 *
 * Identity used to hash `startLine`, `endLine` and the generator's `title`. Both
 * are unstable across runs for an unchanged issue — any edit or reformat above a
 * finding shifts its lines, and the title is model prose that gets reworded — so
 * every scan minted a fresh id and no disposition ever carried. Measured on a
 * real repository: of 169 findings carrying a canonical fingerprint, ZERO matched
 * a prior decision, which turned "prove one fix" into "re-disposition everything".
 *
 * Hashing the flagged text instead gives the identity the properties it needs:
 *  - lines shift, text does not      -> same id, disposition carries
 *  - the model rewords the title     -> same id
 *  - the flagged code actually changes -> NEW id, which is correct: a changed
 *    construct deserves a fresh review rather than an inherited verdict
 *
 * Whitespace is collapsed so a formatter cannot rotate identity. When the range
 * cannot be read (out-of-range line, unreadable snapshot) this falls back to the
 * line numbers so identity stays deterministic instead of throwing — that case is
 * no more stable than the old scheme, but it is no less.
 */
function findingAnchorDigest(snapshotRoot, repoPath, startLine, endLine) {
    const absolute = path.join(snapshotRoot, ...repoPath.split('/'));
    let text;
    try {
        const lines = fs.readFileSync(absolute, 'utf8').split('\n');
        const from = Math.max(1, startLine);
        const to = Math.max(from, endLine ?? startLine);
        const slice = lines.slice(from - 1, to);
        if (slice.length === 0)
            throw new Error('range outside file');
        text = slice
            .map((line) => line.trim().replace(/\s+/gu, ' '))
            .filter((line) => line.length > 0)
            .join('\n');
        if (text.length === 0)
            throw new Error('range is blank');
    }
    catch {
        text = `unresolved-range:${String(startLine)}:${String(endLine ?? startLine)}`;
    }
    return sha256Hex(text);
}
/**
 * The producer-side candidate id. ONE implementation on purpose: a fresh review
 * and a carried receipt must derive byte-identical ids from identical bytes, and
 * two copies of this formula would drift apart silently — the failure mode being
 * that an unchanged file's findings come back with new ids and lose their
 * dispositions, which is precisely what content anchoring exists to prevent.
 */
function candidateFingerprint(snapshotRoot, repoPath, ruleId, startLine, endLine) {
    return `cand_${sha256Hex(canonicalJson({
        // v2: anchored to normalized source text instead of line numbers and
        // the model's title, so an unchanged issue keeps its identity.
        namespace: 'repo-atlas/provider-candidate/v2',
        ruleId,
        path: repoPath,
        anchor: findingAnchorDigest(snapshotRoot, repoPath, startLine, endLine),
    })).slice(0, 24)}`;
}
// ---------------------------------------------------------------------------
// Cross-run receipt reuse
// ---------------------------------------------------------------------------
//
// An observation is whole-unit: publishing one requires a receipt for every file
// the unit owns, so a one-line fix used to cost a unit-sized re-audit (measured:
// 4 changed files -> 112 files re-reviewed, one provider process each).
//
// Evidence is already blob-bound. A published receipt states that these exact
// bytes were fully read under a named ruleset; re-reading the same bytes under
// the same ruleset, model, prompt, CLI configuration and sandbox policy cannot
// produce different evidence. So the receipt is carried forward instead of being
// re-earned — the same reasoning `--resume` uses within a run, applied across
// runs.
//
// Everything here fails closed: any missing, malformed, ambiguous or
// unverifiable input means the file is reviewed again. A wrongly carried receipt
// is a silent coverage lie, so "unsure" must always cost a provider call rather
// than an unproven claim.
const AUDIT_LEDGER_DIR = '.atlas/audits';
const AUDIT_LEDGER_BYTE_LIMIT = 8 * 1024 * 1024;
const OBSERVATION_ID_PATTERN = /^aobs_[0-9a-f]{24}$/;
const GIT_BLOB_PATTERN = /^(?:git-sha1:[0-9a-f]{40}|git-sha256:[0-9a-f]{64})$/;
const EMPTY_CARRY_PLAN = {
    receipts: new Map(),
    findings: [],
};
function optionalPlainString(value) {
    return typeof value === 'string' && value.length > 0 && !value.includes('\0')
        ? value
        : undefined;
}
function readPriorFinding(value) {
    if (!isPlainObject(value))
        return null;
    const identity = value.identity;
    const severity = isPlainObject(value.severity) ? value.severity.level : undefined;
    const confidence = isPlainObject(value.confidence) ? value.confidence.level : undefined;
    const validation = isPlainObject(value.validation) ? value.validation : undefined;
    const attackPath = isPlainObject(value.attackPath) ? value.attackPath : undefined;
    const locations = Array.isArray(value.locations) ? value.locations : [];
    // Exactly one location: a carried receipt is per-file, and a finding that
    // spans two files cannot be attributed to one file's unchanged bytes.
    if (locations.length !== 1 || !isPlainObject(locations[0]))
        return null;
    const location = locations[0];
    const anchor = isPlainObject(identity) ? optionalPlainString(identity.anchor) : undefined;
    const repoPath = optionalPlainString(location.path);
    const ruleId = optionalPlainString(value.ruleId);
    const occurrenceId = optionalPlainString(value.occurrenceId);
    const startLine = location.startLine;
    if (anchor === undefined ||
        repoPath === undefined ||
        ruleId === undefined ||
        occurrenceId === undefined ||
        typeof startLine !== 'number' ||
        !Number.isSafeInteger(startLine) ||
        startLine < 1 ||
        validation === undefined ||
        attackPath === undefined ||
        !SEVERITIES.includes(severity) ||
        !CONFIDENCES.includes(confidence) ||
        !DISPOSITIONS.includes(validation.disposition)) {
        return null;
    }
    const endLine = location.endLine;
    if (endLine !== undefined &&
        (typeof endLine !== 'number' || !Number.isSafeInteger(endLine) || endLine < startLine)) {
        return null;
    }
    const title = optionalPlainString(value.title);
    const summary = optionalPlainString(value.summary);
    const detail = optionalPlainString(attackPath.summary);
    const fix = optionalPlainString(value.remediation);
    const rationale = optionalPlainString(validation.summary);
    if (title === undefined ||
        summary === undefined ||
        detail === undefined ||
        fix === undefined ||
        rationale === undefined) {
        return null;
    }
    return {
        path: repoPath,
        finding: {
            fingerprint: anchor,
            occurrenceId,
            ruleId,
            title,
            severity: severity,
            confidence: confidence,
            summary,
            path: repoPath,
            startLine,
            ...(endLine !== undefined ? { endLine } : {}),
            detail,
            fix,
            disposition: validation.disposition,
            dispositionRationale: rationale,
        },
    };
}
function readPriorFileReceipt(value) {
    if (!isPlainObject(value))
        return null;
    const repoPath = optionalPlainString(value.path);
    const blob = optionalPlainString(value.blob);
    if (repoPath === undefined ||
        blob === undefined ||
        !GIT_BLOB_PATTERN.test(blob) ||
        typeof value.lines !== 'number' ||
        !Number.isSafeInteger(value.lines) ||
        value.lines < 0 ||
        // A receipt that does not claim a completed full read proves nothing worth
        // carrying, and `unknown` is not an outcome a provider run may publish.
        value.status !== 'reviewed' ||
        (value.outcome !== 'clean' && value.outcome !== 'findings') ||
        !Array.isArray(value.receiptRefs) ||
        value.receiptRefs.some((ref) => optionalPlainString(ref) === undefined) ||
        !Array.isArray(value.findingOccurrenceIds) ||
        value.findingOccurrenceIds.some((id) => optionalPlainString(id) === undefined)) {
        return null;
    }
    const reviewedAt = optionalPlainString(value.reviewedAt);
    const precision = value.reviewedAtPrecision;
    if ((reviewedAt === undefined) !== (precision === undefined) ||
        (precision !== undefined && precision !== 'timestamp' && precision !== 'date')) {
        return null;
    }
    return {
        path: repoPath,
        blob: blob,
        lines: value.lines,
        outcome: value.outcome,
        ...(reviewedAt !== undefined
            ? { reviewedAt, reviewedAtPrecision: precision }
            : {}),
        ...(optionalPlainString(value.reviewedBy) !== undefined
            ? { reviewedBy: value.reviewedBy }
            : {}),
        ...(optionalPlainString(value.ruleset) !== undefined
            ? { ruleset: value.ruleset }
            : {}),
        receiptRefs: [...value.receiptRefs],
        findingOccurrenceIds: [...value.findingOccurrenceIds],
    };
}
function readPriorObservation(slug, ledger) {
    // `.atlas/audits/` also holds legacy ledgers and, in principle, other
    // domains. Only a current V3 security ledger is understood here; anything
    // else is not "no receipt", it is "not a ledger this may reason about".
    if (!isPlainObject(ledger) ||
        ledger.formatVersion !== 3 ||
        ledger.format !== 'atlas-audit-v3' ||
        ledger.domain !== 'security' ||
        ledger.slug !== slug ||
        !isPlainObject(ledger.current)) {
        return null;
    }
    const current = ledger.current;
    const producer = isPlainObject(current.producer) ? current.producer : undefined;
    const scope = isPlainObject(current.scope) ? current.scope : undefined;
    const ruleset = producer !== undefined && isPlainObject(producer.ruleset)
        ? producer.ruleset
        : undefined;
    const observationId = optionalPlainString(current.observationId);
    if (observationId === undefined ||
        !OBSERVATION_ID_PATTERN.test(observationId) ||
        producer === undefined ||
        scope === undefined ||
        ruleset === undefined ||
        // Only an exact-inventory scope carries per-file receipts at all; a
        // semantic-declaration scope has no blob to key on.
        scope.identityBasis !== 'exact-inventory' ||
        !Array.isArray(scope.files) ||
        !Array.isArray(current.findings)) {
        return null;
    }
    const rulesetDigest = optionalPlainString(ruleset.digest);
    const effectiveConfigDigest = optionalPlainString(producer.effectiveConfigDigest);
    const environmentPolicyDigest = optionalPlainString(producer.environmentPolicyDigest);
    const producerVersion = optionalPlainString(producer.version);
    if (rulesetDigest === undefined ||
        !SHA256_PATTERN.test(rulesetDigest) ||
        effectiveConfigDigest === undefined ||
        !SHA256_PATTERN.test(effectiveConfigDigest) ||
        environmentPolicyDigest === undefined ||
        !SHA256_PATTERN.test(environmentPolicyDigest) ||
        producerVersion === undefined) {
        return null;
    }
    const receipts = new Map();
    for (const raw of scope.files) {
        const receipt = readPriorFileReceipt(raw);
        // One unreadable receipt discards the whole observation: a partial index
        // would silently look like "this unit never covered that file", and reuse
        // decisions must not be taken against a half-understood ledger.
        if (receipt === null || receipts.has(receipt.path))
            return null;
        receipts.set(receipt.path, receipt);
    }
    const findingsByPath = new Map();
    for (const raw of current.findings) {
        const parsed = readPriorFinding(raw);
        if (parsed === null)
            return null;
        const group = findingsByPath.get(parsed.path) ?? [];
        group.push(parsed.finding);
        findingsByPath.set(parsed.path, group);
    }
    return {
        slug,
        observationId,
        rulesetDigest: rulesetDigest,
        effectiveConfigDigest: effectiveConfigDigest,
        environmentPolicyDigest: environmentPolicyDigest,
        producerVersion,
        receipts,
        findingsByPath,
    };
}
/**
 * Every published security observation whose receipts are structurally sound
 * enough to reason about. A ledger that cannot be read, parsed, or fully
 * understood is simply absent from the result, which means "review that file
 * again".
 */
export function readAuditProviderPriorObservations(repoRoot) {
    let names;
    try {
        names = fs
            .readdirSync(path.join(repoRoot, ...AUDIT_LEDGER_DIR.split('/')))
            .filter((name) => name.endsWith('.json'))
            .sort();
    }
    catch {
        return [];
    }
    const observations = [];
    for (const name of names) {
        const slug = name.slice(0, -'.json'.length);
        let document;
        try {
            document = readBoundedAuditJsonDocument(repoRoot, `${AUDIT_LEDGER_DIR}/${name}`, AUDIT_LEDGER_BYTE_LIMIT);
        }
        catch {
            continue;
        }
        const observation = readPriorObservation(slug, document.value);
        if (observation !== null)
            observations.push(observation);
    }
    return observations;
}
/**
 * Decides, per review target, whether a published receipt still proves the file.
 *
 * The reuse key is the file's blob plus every input that could change a verdict
 * for those same bytes:
 *
 *  - `rulesetDigest` — prompt (including any repository-specific extra prompt),
 *    model, adapter and adapter version;
 *  - `effectiveConfigDigest` — the provider CLI's own effective configuration:
 *    hooks, plugins, MCP servers, project instructions, permission sources;
 *  - `environmentPolicyDigest` — the sandbox the reviewer ran in: tool set,
 *    permission flags, environment allowlist, and the batch/response limits that
 *    decide how much context one review call sees;
 *  - `producerVersion` — the provider binary generation.
 *
 * Any mismatch, on any one of them, means the whole observation is unusable and
 * every one of its files is reviewed again. The check is observation-wide on
 * purpose: those inputs describe the run, not the file.
 */
function planCarriedReceipts(context, key) {
    const priors = context.priorObservations;
    if (priors === undefined || priors.length === 0)
        return EMPTY_CARRY_PLAN;
    const usable = priors.filter((prior) => prior.rulesetDigest === key.rulesetDigest &&
        prior.effectiveConfigDigest === key.effectiveConfigDigest &&
        prior.environmentPolicyDigest === key.environmentPolicyDigest &&
        prior.producerVersion === key.producerVersion);
    if (usable.length === 0)
        return EMPTY_CARRY_PLAN;
    const receipts = new Map();
    const findings = [];
    for (const target of context.targets) {
        if (target.role !== 'review')
            continue;
        const claimants = usable.filter((prior) => prior.receipts.has(target.path));
        // Two observations claiming one path is an ambiguity this layer must not
        // resolve by guessing: carrying the wrong unit's receipt would publish a
        // verdict taken under another unit's scope.
        if (claimants.length !== 1)
            continue;
        const prior = claimants[0];
        const receipt = prior.receipts.get(target.path);
        if (receipt.blob !== target.blob || receipt.lines !== target.lines)
            continue;
        const priorFindings = prior.findingsByPath.get(target.path) ?? [];
        // The published receipt and the published findings must already agree with
        // each other, or the observation is internally inconsistent and nothing
        // about it can be trusted for this file.
        if (receipt.findingOccurrenceIds.length !== priorFindings.length)
            continue;
        const occurrenceIds = new Set(receipt.findingOccurrenceIds);
        if (priorFindings.some((finding) => !occurrenceIds.has(finding.occurrenceId)))
            continue;
        if ((receipt.outcome === 'findings') !== (priorFindings.length > 0))
            continue;
        // The load-bearing invariant: recomputing each finding's identity against
        // the bytes in THIS run's snapshot has to land on the id the observation
        // published. When it does, the carried findings keep their finding ids and
        // their dispositions carry. When it does not — an older, line-anchored
        // identity scheme, say — the file is reviewed again rather than republished
        // under ids nothing would match.
        const carried = [];
        let identityStable = true;
        for (const finding of priorFindings) {
            // Publication emits only reportable occurrences, so a published finding
            // that claims anything else did not come from this pipeline and its
            // occurrence list cannot be reconstructed from the carried receipt.
            if (finding.disposition !== 'reportable') {
                identityStable = false;
                break;
            }
            const recomputed = candidateFingerprint(context.snapshotRoot, finding.path, finding.ruleId, finding.startLine, finding.endLine);
            if (recomputed !== finding.fingerprint) {
                identityStable = false;
                break;
            }
            carried.push({
                fingerprint: finding.fingerprint,
                ruleId: finding.ruleId,
                title: finding.title,
                severity: finding.severity,
                confidence: finding.confidence,
                summary: finding.summary,
                path: finding.path,
                startLine: finding.startLine,
                ...(finding.endLine !== undefined ? { endLine: finding.endLine } : {}),
                detail: finding.detail,
                fix: finding.fix,
                disposition: finding.disposition,
                dispositionRationale: finding.dispositionRationale,
            });
        }
        if (!identityStable)
            continue;
        receipts.set(target.path, {
            path: target.path,
            blob: target.blob,
            lines: target.lines,
            outcome: receipt.outcome,
            observationId: prior.observationId,
            slug: prior.slug,
            ...(receipt.reviewedAt !== undefined
                ? {
                    reviewedAt: receipt.reviewedAt,
                    reviewedAtPrecision: receipt.reviewedAtPrecision ?? 'timestamp',
                }
                : {}),
            ...(receipt.reviewedBy !== undefined ? { reviewedBy: receipt.reviewedBy } : {}),
            ...(receipt.ruleset !== undefined ? { ruleset: receipt.ruleset } : {}),
            receiptRefs: [...receipt.receiptRefs],
            findingFingerprints: carried.map((finding) => finding.fingerprint),
        });
        findings.push(...carried);
    }
    return { receipts, findings };
}
// ---------------------------------------------------------------------------
// Bounded parallel dispatch
// ---------------------------------------------------------------------------
/**
 * Provider failures that a second attempt can legitimately clear: the model
 * produced output this run could not validate. Every attempt is validated
 * identically, so a retry never accepts something the first attempt rejected —
 * it only gives a nondeterministic generator another chance to emit a fully
 * proven transcript.
 *
 * Deliberately narrow. `timeout` is excluded because an attempt already burned
 * the full per-process budget and the usual cause (a credential that needs
 * re-auth) does not clear by trying again; `spawn-failed` and policy/inventory
 * errors are deterministic.
 */
const RETRYABLE_PROVIDER_CODES = new Set([
    'transcript-invalid',
    'output-invalid',
    // Receipts that do not match the requested file set — an extra file, or a
    // missing one — are the same failure in a different shape: the generator
    // answered a question other than the one asked. Leaving this out meant a
    // model naming one file outside its batch still aborted a completed run.
    'missing-file-receipt',
]);
function isRetryableProviderFailure(error) {
    return (error instanceof AuditProviderError && RETRYABLE_PROVIDER_CODES.has(error.code));
}
async function boundedMapUnits(items, concurrency, signal, fn, maxAttempts = 1) {
    const results = new Array(items.length);
    let next = 0;
    let firstFailure;
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (next < items.length && firstFailure === undefined && !signal.aborted) {
            const index = next;
            next += 1;
            let attempt = 0;
            for (;;) {
                attempt += 1;
                try {
                    results[index] = await fn(items[index], index, attempt);
                    break;
                }
                catch (error) {
                    // One unit's unvalidatable output used to abort the whole run, so a
                    // corpus large enough to make model variance likely could never
                    // finish: every remaining unit had to succeed on the same pass.
                    if (attempt < maxAttempts &&
                        !signal.aborted &&
                        isRetryableProviderFailure(error)) {
                        continue;
                    }
                    if (firstFailure === undefined)
                        firstFailure = error;
                    break;
                }
            }
        }
    });
    await Promise.all(workers);
    if (firstFailure !== undefined)
        throw firstFailure;
    if (signal.aborted) {
        fail('spawn-failed', 'provider run was aborted');
    }
    return results;
}
export async function runAuditProviderPhases(context, handlers) {
    const journal = {
        formatVersion: 1,
        format: 'atlas-audit-provider-journal/v1',
        invocationId: context.invocationId,
        provider: 'grok',
        status: 'running',
        chunks: [],
    };
    writeJournalFile(context.resumeDir, journal);
    const slots = [];
    const reusedChunks = [];
    const executedChunks = [];
    const persistChunk = (chunk, output, reused) => {
        writeChunkRecord(context.resumeDir, chunk, output);
        journal.chunks.push(chunk.chunkId);
        writeJournalFile(context.resumeDir, journal);
        slots.push({ chunk, reused });
        if (reused)
            reusedChunks.push(chunk.chunkId);
        else
            executedChunks.push(chunk.chunkId);
    };
    const descriptor = context.providerDescriptor;
    const policy = context.policy;
    const resumeSourceDir = context.resumeSourceDir;
    const tryResume = (phase, unit, inputDigest, revalidate) => {
        if (resumeSourceDir === undefined)
            return null;
        const chunkId = `${unit.replaceAll(':', '-')}-${inputDigest.slice(7, 23)}`;
        const record = readChunkRecord(resumeSourceDir, chunkId);
        if (record === null)
            return null;
        if (!verifyChunkRecord(record, phase, unit, inputDigest))
            return null;
        let output;
        try {
            output = revalidate(record.output);
        }
        catch {
            return null;
        }
        return { chunk: record.chunk, output };
    };
    // Phase 1: inventory — always executed fresh so the binary, version, and
    // effective configuration are established in this environment.
    context.assertSnapshotIntact();
    const inventory = await handlers.inventory(context);
    if (!isPlainObject(inventory.output) ||
        typeof inventory.output.binaryVersion !== 'string' ||
        inventory.output.binaryVersion.length === 0 ||
        !SHA256_PATTERN.test(inventory.output.binaryDigest) ||
        !SHA256_PATTERN.test(inventory.output.effectiveConfigDigest) ||
        !Array.isArray(inventory.output.probeDigests)) {
        fail('output-invalid', 'inventory facts are incomplete', 'inventory');
    }
    const inventoryFacts = inventory.output;
    const inventoryInputDigest = canonicalDigest({
        namespace: 'repo-atlas/provider-chunk-input/v1',
        phase: 'inventory',
        unit: 'inventory',
        snapshotManifestDigest: context.snapshotManifestDigest,
        adapter: descriptor.adapter,
        adapterVersion: descriptor.adapterVersion,
        model: policy.model,
        binaryVersion: inventoryFacts.binaryVersion,
        binaryDigest: inventoryFacts.binaryDigest,
        effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
    });
    persistChunk(makeChunk('inventory', 'inventory', inventoryInputDigest, inventory), inventory.output, false);
    context.assertSnapshotIntact();
    const sharedKeyMaterial = {
        promptDigest: context.promptReceipt.digest,
        promptTemplateDigest: descriptor.promptTemplateDigest,
        model: policy.model,
        adapter: descriptor.adapter,
        adapterVersion: descriptor.adapterVersion,
        binaryVersion: inventoryFacts.binaryVersion,
        effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
        environmentPolicyDigest: context.environmentPolicyDigest,
    };
    // Receipts a previously published observation still proves. These files are
    // removed from batching entirely — that is the whole saving — so everything
    // downstream (synthesis, the receipt chain, publication) has to learn about
    // them from the plan rather than from a review chunk.
    const carryPlan = planCarriedReceipts(context, {
        rulesetDigest: context.ruleset.digest,
        effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
        environmentPolicyDigest: context.environmentPolicyDigest,
        producerVersion: inventoryFacts.binaryVersion,
    });
    // Phase 2: parallel bounded review — one bounded process per batch.
    const reviewFiles = context.targets.filter((target) => target.role === 'review' && !carryPlan.receipts.has(target.path));
    // Slicing the sorted inventory groups siblings, and siblings share basenames:
    // this repository has 23 `index.ts` files under one directory and 147 overall,
    // so a batch could be eight files distinguishable only by parent directory.
    // Asking a generator to keep those apart is a prompt defect, and it showed as
    // one — a batch of same-named files kept emitting a receipt for the wrong
    // sibling, six attempts in a row across two runs, after the whole review phase
    // had otherwise completed.
    //
    // Files are placed into batches largest-basename-group first, each into the
    // emptiest batch that does not already hold its basename. A flat round-robin
    // is not enough: it front-loads the diverse groups and leaves the big group's
    // tail bunched in the final batches. Where a corpus cannot satisfy the
    // constraint — every file sharing one name — placement falls back to the
    // emptiest batch and simply batches as before.
    //
    // This changes no validation: every file is reviewed exactly once, and the
    // batch digest still pins its exact contents.
    //
    // Zero batches, not one empty batch: when every file's receipt carried
    // forward there is nothing to ask a provider about, and a batch of no files
    // would spawn a process to review nothing.
    const batchCount = reviewFiles.length === 0
        ? 0
        : Math.max(1, Math.ceil(reviewFiles.length / policy.maxBatchFiles));
    const batches = Array.from({ length: batchCount }, () => []);
    const basenameOf = (file) => file.path.slice(file.path.lastIndexOf('/') + 1);
    const dirnameOf = (file) => {
        const cut = file.path.lastIndexOf('/');
        return cut === -1 ? '' : file.path.slice(0, cut);
    };
    const byBasename = new Map();
    for (const file of reviewFiles) {
        const group = byBasename.get(basenameOf(file)) ?? [];
        group.push(file);
        byBasename.set(basenameOf(file), group);
    }
    const takenNames = batches.map(() => new Set());
    const takenDirs = batches.map(() => new Set());
    const ordered = [...byBasename.values()].sort((left, right) => right.length - left.length);
    // Two files look alike to a generator when they share a name OR sit in one
    // directory under a shared naming template. Both produce the same symptom: a
    // receipt for a plausible sibling that does not exist. A directory of 43
    // `<capability>.ts` / `<capability>.test.ts` pairs got a receipt for
    // `votes.test.ts` — there is no `votes` capability anywhere in the tree — in
    // place of the `artifacts.test.ts` it was given, identically on all three
    // attempts. Basename spreading alone does not reach that: those siblings have
    // distinct basenames.
    //
    // Placement therefore prefers a batch sharing neither the basename nor the
    // directory, falls back to one sharing only the directory, and finally to the
    // emptiest batch when a corpus leaves no choice.
    const place = (file) => {
        const name = basenameOf(file);
        const dir = dirnameOf(file);
        const pick = (allow) => {
            let chosen = -1;
            for (let index = 0; index < batches.length; index += 1) {
                if (batches[index].length >= policy.maxBatchFiles)
                    continue;
                if (!allow(index))
                    continue;
                if (chosen === -1 || batches[index].length < batches[chosen].length)
                    chosen = index;
            }
            return chosen;
        };
        const strict = pick((index) => !takenNames[index].has(name) && !takenDirs[index].has(dir));
        if (strict !== -1)
            return strict;
        const byName = pick((index) => !takenNames[index].has(name));
        if (byName !== -1)
            return byName;
        return pick(() => true);
    };
    for (const group of ordered) {
        for (const file of group) {
            const chosen = place(file);
            batches[chosen].push(file);
            takenNames[chosen].add(basenameOf(file));
            takenDirs[chosen].add(dirnameOf(file));
        }
    }
    const inventoryHas = (candidate) => context.targets.some((target) => target.path === candidate);
    const reviewKey = (unit, files) => canonicalDigest({
        namespace: 'repo-atlas/provider-chunk-input/v1',
        phase: 'review',
        unit,
        files: files.map((file) => ({
            path: file.path,
            sha256: file.sha256,
            lines: file.lines,
        })),
        ...sharedKeyMaterial,
    });
    const reviewUnitByPath = {};
    batches.forEach((files, index) => {
        for (const file of files)
            reviewUnitByPath[file.path] = `review:${index}`;
    });
    const reviewExecutions = await boundedMapUnits(batches, policy.concurrency, context.signal, async (files, index, attempt) => {
        const unit = `review:${index}`;
        const inputDigest = reviewKey(unit, files);
        const resumed = tryResume('review', unit, inputDigest, (output) => validateAuditProviderReviewUnitOutput(output, files, policy, inventoryHas));
        if (resumed !== null) {
            persistChunk(resumed.chunk, resumed.output, true);
            return resumed.output;
        }
        // `attempt` deliberately does NOT enter `inputDigest`: the chunk identity
        // must stay the input identity, so a corrected retry resumes as the same
        // chunk instead of forking a second cache entry for the same batch.
        const execution = await handlers.review(context, { unit, index, files, attempt });
        const output = validateAuditProviderReviewUnitOutput(execution.output, files, policy, inventoryHas);
        persistChunk(makeChunk('review', unit, inputDigest, { ...execution, output }), output, false);
        return output;
    }, policy.maxAttempts);
    context.assertSnapshotIntact();
    // Deterministic candidate identity/dedupe between review and verification.
    const candidates = [];
    const seenFingerprints = new Set();
    for (const output of reviewExecutions) {
        const receipts = [...output.receipts].sort((left, right) => left.path.localeCompare(right.path));
        for (const receipt of receipts) {
            for (const finding of receipt.findings) {
                const fingerprint = candidateFingerprint(context.snapshotRoot, receipt.path, finding.ruleId, finding.startLine, finding.endLine);
                if (seenFingerprints.has(fingerprint))
                    continue;
                seenFingerprints.add(fingerprint);
                candidates.push({
                    fingerprint,
                    ruleId: finding.ruleId,
                    title: finding.title,
                    severity: finding.severity,
                    confidence: finding.confidence,
                    summary: finding.summary,
                    path: receipt.path,
                    startLine: finding.startLine,
                    ...(finding.endLine !== undefined ? { endLine: finding.endLine } : {}),
                    detail: finding.detail,
                    fix: finding.fix,
                });
            }
        }
    }
    // Phase 3: independent verification — bounded parallel fact checking.
    //
    // Carried findings are deliberately absent from `candidates`: their terminal
    // disposition was reached by an independent verification against these exact
    // bytes and is carried with the receipt. Re-verifying them would be the
    // provider cost this whole mechanism exists to avoid.
    const verificationOutputs = [];
    const verificationUnitByFingerprint = {};
    if (candidates.length === 0) {
        const output = { dispositions: [] };
        const inputDigest = canonicalDigest({
            namespace: 'repo-atlas/provider-chunk-input/v1',
            phase: 'verification',
            unit: 'verification',
            candidates: [],
            files: [],
            ...sharedKeyMaterial,
        });
        persistChunk(makeChunk('verification', 'verification', inputDigest, {
            output,
            processCount: 0,
            sessionIds: [],
            transcriptDigests: [],
        }), output, false);
        verificationOutputs.push(output);
    }
    else {
        const units = [];
        for (let index = 0; index < candidates.length; index += policy.maxVerificationCandidates) {
            const slice = candidates.slice(index, index + policy.maxVerificationCandidates);
            const unitIndex = units.length;
            const files = [
                ...new Map(slice.map((candidate) => {
                    const entry = context.manifestEntry(candidate.path);
                    if (entry === undefined) {
                        fail('output-invalid', `candidate references a file outside the snapshot: ${candidate.path}`, 'verification');
                    }
                    return [candidate.path, entry];
                })).values(),
            ];
            units.push({ unit: `verification:${unitIndex}`, index: unitIndex, candidates: slice, files });
        }
        for (const unit of units) {
            for (const candidate of unit.candidates) {
                verificationUnitByFingerprint[candidate.fingerprint] = unit.unit;
            }
        }
        const verificationKey = (unit) => canonicalDigest({
            namespace: 'repo-atlas/provider-chunk-input/v1',
            phase: 'verification',
            unit: unit.unit,
            candidates: unit.candidates.map((candidate) => candidate.fingerprint),
            files: unit.files.map((file) => ({
                path: file.path,
                sha256: file.sha256,
                lines: file.lines,
            })),
            ...sharedKeyMaterial,
        });
        const executions = await boundedMapUnits(units, policy.concurrency, context.signal, async (unit) => {
            const inputDigest = verificationKey(unit);
            const resumed = tryResume('verification', unit.unit, inputDigest, (output) => validateAuditProviderVerificationUnitOutput(output, unit.candidates, policy));
            if (resumed !== null) {
                persistChunk(resumed.chunk, resumed.output, true);
                return resumed.output;
            }
            const execution = await handlers.verification(context, unit);
            const output = validateAuditProviderVerificationUnitOutput(execution.output, unit.candidates, policy);
            persistChunk(makeChunk('verification', unit.unit, inputDigest, { ...execution, output }), output, false);
            return output;
        }, policy.maxAttempts);
        verificationOutputs.push(...executions);
    }
    context.assertSnapshotIntact();
    // Phase 4: deterministic synthesis.
    const synthesis = handlers.synthesize(context, {
        reviewOutputs: reviewExecutions,
        verificationOutputs,
        candidates,
        carried: carryPlan,
    });
    validateSynthesisOutput(context, synthesis, candidates, carryPlan);
    const carriedChunkInput = [...carryPlan.receipts.values()]
        .map((receipt) => ({
        path: receipt.path,
        blob: receipt.blob,
        outcome: receipt.outcome,
        observationId: receipt.observationId,
        findingFingerprints: [...receipt.findingFingerprints].sort(),
    }))
        .sort((left, right) => left.path.localeCompare(right.path));
    const synthesisInputDigest = canonicalDigest({
        namespace: 'repo-atlas/provider-chunk-input/v1',
        phase: 'synthesis',
        unit: 'synthesis',
        reviewChunkDigests: slots
            .filter((slot) => slot.chunk.phase === 'review')
            .map((slot) => slot.chunk.digest),
        verificationChunkDigests: slots
            .filter((slot) => slot.chunk.phase === 'verification')
            .map((slot) => slot.chunk.digest),
        // Absent when nothing carried, so a run that reviews everything keeps the
        // digest it has always had. When something did carry, the receipt chain has
        // to name it: the proof for those files lives in another observation, and a
        // transcript digest that ignored them would look like a full review.
        ...(carriedChunkInput.length > 0 ? { carried: carriedChunkInput } : {}),
        ...sharedKeyMaterial,
    });
    const synthesisOutput = {
        files: synthesis.files,
        findings: synthesis.findings,
    };
    persistChunk(makeChunk('synthesis', 'synthesis', synthesisInputDigest, {
        output: synthesisOutput,
        processCount: 0,
        sessionIds: [],
        transcriptDigests: [],
    }), synthesisOutput, false);
    context.assertSnapshotIntact();
    const orderedChunks = slots
        .map((slot) => slot.chunk)
        .sort((left, right) => AUDIT_PROVIDER_PHASE_ORDER.indexOf(left.phase) -
        AUDIT_PROVIDER_PHASE_ORDER.indexOf(right.phase) ||
        left.chunkId.localeCompare(right.chunkId));
    const transcriptDigest = canonicalDigest(orderedChunks.map((chunk) => ({ chunkId: chunk.chunkId, digest: chunk.digest })));
    const receiptBase = {
        formatVersion: 1,
        format: 'atlas-audit-provider-run/v1',
        provider: 'grok',
        adapter: descriptor.adapter,
        adapterVersion: descriptor.adapterVersion,
        invocationId: context.invocationId,
        ruleset: context.ruleset,
        prompt: context.promptReceipt,
        model: policy.model,
        effectiveConfigDigest: inventoryFacts.effectiveConfigDigest,
        environmentPolicyDigest: context.environmentPolicyDigest,
        snapshotManifestDigest: context.snapshotManifestDigest,
        inventoryDigest: context.inventoryDigest,
        chunks: orderedChunks,
        transcriptDigest,
    };
    const receipt = {
        ...receiptBase,
        receiptDigest: canonicalDigest(receiptBase),
    };
    journal.status = 'completed';
    writeJournalFile(context.resumeDir, journal);
    return {
        status: 'completed',
        invocationId: context.invocationId,
        files: synthesis.files,
        findings: synthesis.findings,
        receipt,
        reusedChunks,
        executedChunks,
        carriedReceipts: [...carryPlan.receipts.values()].sort((left, right) => left.path.localeCompare(right.path)),
        reviewUnitByPath,
        verificationUnitByFingerprint,
    };
}
function validateSynthesisOutput(context, synthesis, candidates, carried) {
    const reviewTargets = context.targets.filter((target) => target.role === 'review');
    const byPath = new Map(synthesis.files.map((file) => [file.path, file]));
    if (byPath.size !== reviewTargets.length) {
        fail('missing-file-receipt', 'synthesis does not cover every review target exactly once', 'synthesis');
    }
    // A carried receipt is the one thing synthesis cannot re-derive, so it is the
    // one thing synthesis is not allowed to restate. Both directions are checked:
    // a carried file must publish exactly the carried outcome and exactly the
    // carried findings, and a carried finding must not go missing.
    const emittedFindings = new Map(synthesis.findings.map((finding) => [finding.fingerprint, finding]));
    for (const receipt of carried.receipts.values()) {
        const file = byPath.get(receipt.path);
        if (file === undefined) {
            fail('missing-file-receipt', `synthesis dropped the carried receipt for ${receipt.path}`, 'synthesis');
        }
        if (file.outcome !== receipt.outcome) {
            fail('output-invalid', `synthesis restated the carried outcome for ${receipt.path} as ${file.outcome} instead of ${receipt.outcome}`, 'synthesis');
        }
        if (canonicalJson([...file.findingFingerprints].sort()) !==
            canonicalJson([...receipt.findingFingerprints].sort())) {
            fail('output-invalid', `synthesis restated the carried findings for ${receipt.path}`, 'synthesis');
        }
    }
    for (const finding of carried.findings) {
        const emitted = emittedFindings.get(finding.fingerprint);
        if (emitted === undefined) {
            fail('output-invalid', `synthesis dropped carried finding ${finding.fingerprint} on ${finding.path}`, 'synthesis');
        }
        if (canonicalJson(emitted) !== canonicalJson(finding)) {
            fail('output-invalid', `synthesis altered carried finding ${finding.fingerprint} on ${finding.path}`, 'synthesis');
        }
    }
    const knownFingerprints = new Set([
        ...candidates.map((candidate) => candidate.fingerprint),
        ...carried.findings.map((finding) => finding.fingerprint),
    ]);
    for (const target of reviewTargets) {
        const file = byPath.get(target.path);
        if (file === undefined) {
            fail('missing-file-receipt', `synthesis is missing ${target.path}`, 'synthesis');
        }
        if (file.blob !== target.blob || file.lines !== target.lines) {
            fail('output-invalid', `synthesis receipt drifted from the snapshot for ${target.path}`, 'synthesis');
        }
        for (const fingerprint of file.findingFingerprints) {
            if (!knownFingerprints.has(fingerprint)) {
                fail('output-invalid', `synthesis references an unknown finding on ${target.path}`, 'synthesis');
            }
        }
    }
    for (const finding of synthesis.findings) {
        if (!knownFingerprints.has(finding.fingerprint)) {
            fail('output-invalid', 'synthesis emitted an unknown finding', 'synthesis');
        }
    }
}
// ---------------------------------------------------------------------------
// Invocation entry point — the only way a provider process can start
// ---------------------------------------------------------------------------
export async function runAuditProviderInvocation(request, provider) {
    const targets = validateInvocationRequest(request);
    validateProviderShape(provider, request.provider);
    const policy = request.policy;
    const repoRoot = path.resolve(request.repoRoot);
    const rootStat = fs.lstatSync(repoRoot, { throwIfNoEntry: false });
    if (!rootStat || rootStat.isSymbolicLink() || !rootStat.isDirectory()) {
        fail('invalid-request', 'provider invocation repoRoot must be an existing safe directory');
    }
    const originalsBefore = hashOriginalTargets(repoRoot, targets, policy);
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-audit-run-'));
    fs.chmodSync(tempRoot, 0o700);
    const controller = new AbortController();
    let resumeDir;
    let journalFailure;
    try {
        const snapshotRoot = path.join(tempRoot, 'snapshot');
        const entries = createProviderSnapshot(repoRoot, targets, snapshotRoot, policy);
        const manifest = buildSnapshotManifest(entries);
        fs.writeFileSync(path.join(tempRoot, 'snapshot-manifest.json'), `${canonicalJson(manifest)}\n`, { mode: 0o444 });
        const snapshotManifestDigest = canonicalDigest(manifest);
        const inventoryDigest = canonicalDigest({
            namespace: 'repo-atlas/provider-inventory/v1',
            files: entries.map((entry) => ({ path: entry.path, blob: entry.blob })),
        });
        const descriptor = provider.descriptor;
        const extraPrompt = request.extraPrompt ?? '';
        const extraDigest = extraPrompt.length > 0 ? auditProviderSha256(extraPrompt) : undefined;
        const promptDigest = canonicalDigest({
            namespace: 'repo-atlas/provider-prompt/v1',
            builtinVersion: descriptor.promptBuiltinVersion,
            templateDigest: descriptor.promptTemplateDigest,
            extraDigest: extraDigest ?? null,
        });
        const promptReceipt = extraDigest !== undefined
            ? {
                builtinVersion: descriptor.promptBuiltinVersion,
                digest: promptDigest,
                extraPath: '.atlas/pipeline/security.extra.md',
                extraDigest,
            }
            : {
                builtinVersion: descriptor.promptBuiltinVersion,
                digest: promptDigest,
            };
        // The ruleset identifies *how* a review was conducted — prompt, model, and
        // adapter. It deliberately excludes the run's file inventory: a decision
        // carries forward only while the ruleset digest matches, so folding the
        // inventory in here voided every disposition in a unit as soon as any file
        // in it was added, removed, or edited. Whether a specific finding still
        // describes its file is already answered by that finding's exact blob
        // binding, which is the check that actually protects the evidence. The
        // inventory stays recorded on the observation scope for provenance.
        const ruleset = {
            id: descriptor.rulesetId,
            digest: canonicalDigest({
                namespace: 'repo-atlas/ruleset/v1',
                id: descriptor.rulesetId,
                domain: 'security',
                promptDigest,
                model: policy.model,
                adapter: descriptor.adapter,
                adapterVersion: descriptor.adapterVersion,
            }),
        };
        const environmentPolicyDigest = canonicalDigest({
            namespace: 'repo-atlas/provider-environment/v1',
            envAllowlist: [
                'LANG',
                'LC_ALL',
                'LC_CTYPE',
                'PATH',
                'TZ',
                ...(policy.apiKeyEnv !== undefined ? [policy.apiKeyEnv] : []),
            ].sort(),
            isolatedHome: true,
            homeMode: '0700',
            snapshotReadOnly: true,
            hardlinks: false,
            shell: false,
            tools: [...descriptor.tools].sort(),
            permissionFlags: [...descriptor.permissionFlags].sort(),
            limits: {
                concurrency: policy.concurrency,
                maxBatchFiles: policy.maxBatchFiles,
                timeoutMs: policy.timeoutMs,
                maxStdoutBytes: policy.maxStdoutBytes,
                maxStderrBytes: policy.maxStderrBytes,
                maxResponseBytes: policy.maxResponseBytes,
                maxTranscriptBytes: policy.maxTranscriptBytes,
            },
        });
        const invocationId = `arun_${sha256Hex(canonicalJson({
            namespace: 'repo-atlas/provider-run/v1',
            ruleset: ruleset.digest,
            snapshot: snapshotManifestDigest,
        })).slice(0, 24)}`;
        resumeDir = path.join(repoRoot, AUDIT_PROVIDER_RUNTIME_PATH, invocationId);
        fs.mkdirSync(resumeDir, { recursive: true, mode: 0o700 });
        fs.chmodSync(resumeDir, 0o700);
        let resumeSourceDir;
        if (request.resumeInvocationId !== undefined) {
            resumeSourceDir = path.join(repoRoot, AUDIT_PROVIDER_RUNTIME_PATH, request.resumeInvocationId);
            validateResumeSource(resumeSourceDir, request.resumeInvocationId);
        }
        const manifestByPath = new Map(entries.map((entry) => [entry.path, entry]));
        const context = {
            repoRoot,
            snapshotRoot,
            invocationId,
            policy,
            prompt: extraPrompt,
            targets: entries,
            resumeDir,
            tempRoot,
            snapshotManifestDigest,
            inventoryDigest,
            ruleset,
            promptReceipt,
            environmentPolicyDigest,
            providerDescriptor: descriptor,
            signal: controller.signal,
            assertSnapshotIntact: () => assertSnapshotIntact(snapshotRoot, manifest, policy),
            manifestEntry: (repoPath) => manifestByPath.get(repoPath),
            ...(resumeSourceDir !== undefined ? { resumeSourceDir } : {}),
            // Read before the provider starts, from the tracked ledgers only. The
            // absence of this field is what makes a default run a full review.
            ...(request.reuseUnchangedReceipts === true
                ? { priorObservations: readAuditProviderPriorObservations(repoRoot) }
                : {}),
        };
        try {
            const result = await provider.run(context);
            if (!isPlainObject(result) || result.status !== 'completed') {
                fail('output-invalid', 'provider returned an incomplete result');
            }
            if (result.invocationId !== invocationId) {
                fail('output-invalid', 'provider result does not match the allocated invocation id');
            }
            context.assertSnapshotIntact();
            assertOriginalsUnchanged(repoRoot, targets, policy, originalsBefore);
            fs.writeFileSync(path.join(resumeDir, 'receipt.json'), `${canonicalJson(result.receipt)}\n`, { mode: 0o600 });
            if (request.resumeInvocationId !== undefined) {
                result.resumedFromInvocationId = request.resumeInvocationId;
            }
            return result;
        }
        catch (error) {
            controller.abort();
            assertOriginalsUnchanged(repoRoot, targets, policy, originalsBefore);
            const providerError = error instanceof AuditProviderError
                ? error
                : new AuditProviderError('spawn-failed', error instanceof Error ? error.message : String(error));
            journalFailure = { code: providerError.code, message: providerError.message };
            throw providerError;
        }
        finally {
            if (journalFailure !== undefined && resumeDir !== undefined) {
                try {
                    writeJournalFile(resumeDir, {
                        formatVersion: 1,
                        format: 'atlas-audit-provider-journal/v1',
                        invocationId,
                        provider: 'grok',
                        status: 'failed',
                        chunks: listExistingChunkIds(resumeDir),
                        failure: journalFailure,
                    });
                }
                catch {
                    // The clone-local journal must never mask the primary failure.
                }
            }
        }
    }
    finally {
        removeProviderTempRoot(tempRoot);
    }
}
// Snapshot directories are read-only by design; restore writability before
// recursive deletion so cleanup cannot fail on our own isolation bits.
function removeProviderTempRoot(tempRoot) {
    const restore = (directory) => {
        let children;
        try {
            children = fs.readdirSync(directory, { withFileTypes: true });
        }
        catch {
            return;
        }
        for (const child of children) {
            if (child.isDirectory())
                restore(path.join(directory, child.name));
        }
        try {
            fs.chmodSync(directory, 0o755);
        }
        catch {
            // Best effort; the rmSync below reports any remaining failure.
        }
    };
    // A failed run's evidence lives here and nowhere else: the prompts sent, the
    // session transcripts, and the isolated home. Deleting it on the way out means
    // the only way to ask "why did the generator answer that" is to reproduce and
    // race the cleanup. Set ATLAS_AUDIT_KEEP_RUN=1 to keep it.
    if (process.env.ATLAS_AUDIT_KEEP_RUN === '1') {
        process.stderr.write(`audit provider: keeping run root at ${tempRoot}\n`);
        return;
    }
    try {
        restore(tempRoot);
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
    catch {
        // A stale temp root is clone-local scratch; never mask the run outcome.
    }
}
function listExistingChunkIds(resumeDir) {
    const chunksDir = path.join(resumeDir, 'chunks');
    try {
        return fs
            .readdirSync(chunksDir)
            .filter((name) => name.endsWith('.json'))
            .map((name) => name.slice(0, -'.json'.length))
            .sort();
    }
    catch {
        return [];
    }
}
