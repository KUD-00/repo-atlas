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
    const policy = {
        command,
        model,
        concurrency,
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
export function validateAuditProviderReviewUnitOutput(output, files, policy) {
    if (!isPlainObject(output) || !Array.isArray(output.receipts)) {
        fail('output-invalid', 'review unit output must be an object with a receipts array', 'review');
    }
    const expected = new Map(files.map((file) => [file.path, file]));
    const seen = new Set();
    const receipts = [];
    for (const raw of output.receipts) {
        if (!isPlainObject(raw)) {
            fail('output-invalid', 'review receipt must be a plain object', 'review');
        }
        const receiptPath = typeof raw.path === 'string' ? raw.path : '';
        const file = expected.get(receiptPath);
        if (file === undefined) {
            fail('missing-file-receipt', `review output references a file outside the unit: ${receiptPath || '<missing>'}`, 'review');
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
        if (raw.outcome === 'clean' && raw.findings.length > 0) {
            fail('output-invalid', `clean review receipt for ${receiptPath} carries findings`, 'review');
        }
        if (raw.outcome === 'findings' && raw.findings.length === 0) {
            fail('output-invalid', `findings review receipt for ${receiptPath} carries none`, 'review');
        }
        const findings = [];
        for (const rawFinding of raw.findings) {
            if (!isPlainObject(rawFinding)) {
                fail('output-invalid', `finding on ${receiptPath} must be a plain object`, 'review');
            }
            const severity = rawFinding.severity;
            if (!SEVERITIES.includes(severity)) {
                fail('output-invalid', `finding on ${receiptPath} has an invalid severity`, 'review');
            }
            const startLine = rawFinding.startLine;
            if (typeof startLine !== 'number' || !Number.isSafeInteger(startLine) || startLine < 1 || startLine > Math.max(1, file.lines)) {
                fail('output-invalid', `finding on ${receiptPath} has an out-of-range startLine`, 'review');
            }
            let endLine;
            if (rawFinding.endLine !== undefined) {
                if (typeof rawFinding.endLine !== 'number' ||
                    !Number.isSafeInteger(rawFinding.endLine) ||
                    rawFinding.endLine < startLine ||
                    rawFinding.endLine > Math.max(1, file.lines)) {
                    fail('output-invalid', `finding on ${receiptPath} has an out-of-range endLine`, 'review');
                }
                endLine = rawFinding.endLine;
            }
            findings.push({
                ruleId: boundedText(rawFinding.ruleId, `finding ruleId on ${receiptPath}`),
                title: boundedText(rawFinding.title, `finding title on ${receiptPath}`),
                severity,
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
// Bounded parallel dispatch
// ---------------------------------------------------------------------------
async function boundedMapUnits(items, concurrency, signal, fn) {
    const results = new Array(items.length);
    let next = 0;
    let firstFailure;
    const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
        while (next < items.length && firstFailure === undefined && !signal.aborted) {
            const index = next;
            next += 1;
            try {
                results[index] = await fn(items[index], index);
            }
            catch (error) {
                if (firstFailure === undefined)
                    firstFailure = error;
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
    // Phase 2: parallel bounded review — one bounded process per batch.
    const reviewFiles = context.targets.filter((target) => target.role === 'review');
    const batches = [];
    for (let index = 0; index < reviewFiles.length; index += policy.maxBatchFiles) {
        batches.push(reviewFiles.slice(index, index + policy.maxBatchFiles));
    }
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
    const reviewExecutions = await boundedMapUnits(batches, policy.concurrency, context.signal, async (files, index) => {
        const unit = `review:${index}`;
        const inputDigest = reviewKey(unit, files);
        const resumed = tryResume('review', unit, inputDigest, (output) => validateAuditProviderReviewUnitOutput(output, files, policy));
        if (resumed !== null) {
            persistChunk(resumed.chunk, resumed.output, true);
            return resumed.output;
        }
        const execution = await handlers.review(context, { unit, index, files });
        const output = validateAuditProviderReviewUnitOutput(execution.output, files, policy);
        persistChunk(makeChunk('review', unit, inputDigest, { ...execution, output }), output, false);
        return output;
    });
    context.assertSnapshotIntact();
    // Deterministic candidate identity/dedupe between review and verification.
    const candidates = [];
    const seenFingerprints = new Set();
    for (const output of reviewExecutions) {
        const receipts = [...output.receipts].sort((left, right) => left.path.localeCompare(right.path));
        for (const receipt of receipts) {
            for (const finding of receipt.findings) {
                const fingerprint = `cand_${sha256Hex(canonicalJson({
                    namespace: 'repo-atlas/provider-candidate/v1',
                    ruleId: finding.ruleId,
                    path: receipt.path,
                    startLine: finding.startLine,
                    endLine: finding.endLine ?? null,
                    title: finding.title,
                })).slice(0, 24)}`;
                if (seenFingerprints.has(fingerprint))
                    continue;
                seenFingerprints.add(fingerprint);
                candidates.push({
                    fingerprint,
                    ruleId: finding.ruleId,
                    title: finding.title,
                    severity: finding.severity,
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
    const verificationOutputs = [];
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
        });
        verificationOutputs.push(...executions);
    }
    context.assertSnapshotIntact();
    // Phase 4: deterministic synthesis.
    const synthesis = handlers.synthesize(context, {
        reviewOutputs: reviewExecutions,
        verificationOutputs,
        candidates,
    });
    validateSynthesisOutput(context, synthesis, candidates);
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
    };
}
function validateSynthesisOutput(context, synthesis, candidates) {
    const reviewTargets = context.targets.filter((target) => target.role === 'review');
    const byPath = new Map(synthesis.files.map((file) => [file.path, file]));
    if (byPath.size !== reviewTargets.length) {
        fail('missing-file-receipt', 'synthesis does not cover every review target exactly once', 'synthesis');
    }
    const knownFingerprints = new Set(candidates.map((candidate) => candidate.fingerprint));
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
                inventoryDigest,
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
