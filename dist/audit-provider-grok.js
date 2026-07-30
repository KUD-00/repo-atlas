import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalJson, normalizeAuditRepoPath, parseBoundedAuditJsonBytes, } from './audit-core.js';
import { AuditProviderError, auditProviderSha256, runAuditProviderPhases, validateAuditProviderReviewUnitOutput, validateAuditProviderVerificationUnitOutput, } from './audit-providers.js';
// Isolated first-party Grok CLI adapter (repo-atlas/grok-v1).
//
// Grok is never invoked implicitly: this adapter only runs inside
// runAuditProviderInvocation, which requires an explicit
// `audit run security` request. Every process runs with shell:false, exact
// argv, an allowlisted environment, an isolated mode-0700 HOME/XDG home, a
// read-only byte-copy source snapshot, bounded stdout/stderr, and an abort
// controller timeout. Session transcripts are parsed and validated before any
// output is accepted; failures stay clone-local and never publish.
export const GROK_ADAPTER_ID = 'repo-atlas/grok-v1';
export const GROK_ADAPTER_VERSION = '0.1.0';
export const GROK_SUPPORTED_CLI_VERSION = '0.2.82';
export const GROK_RULESET_ID = 'atlas-security-v3';
export const GROK_PROMPT_BUILTIN_VERSION = 'atlas-security-prompt-v1';
export const GROK_VALIDATION_RUBRIC_VERSION = 'atlas-security-validation-rubric-v1';
const GROK_TOOLS = ['Read', 'Grep', 'Glob'];
const GROK_PERMISSION_FLAGS = [
    '--single',
    '--no-plan',
    '--permission-mode',
    '--tools',
    '--no-memory',
    '--no-subagents',
    '--disable-web-search',
    '--output-format',
    '--model',
    '--session-id',
    '--cwd',
    '--prompt-file',
];
const AMBIENT_PROBE_ENV_KEYS = [
    'PATH',
    'HOME',
    'LANG',
    'LC_ALL',
    'LC_CTYPE',
    'TZ',
    'TMPDIR',
];
const ISOLATED_PASSTHROUGH_ENV_KEYS = ['PATH', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ'];
const MAX_BINARY_BYTES = 256 * 1024 * 1024;
const MAX_PROBE_OUTPUT_BYTES = 1024 * 1024;
const MAX_AUTH_RECORD_BYTES = 64 * 1024;
const MAX_STDOUT_LINES = 65_536;
const PROBE_TIMEOUT_CAP_MS = 60_000;
const GROK_REVIEW_PROMPT = `You are performing a READ-ONLY security audit of an exact byte snapshot of repository source files. This prompt is one bounded sub-review dispatched by the Repo Atlas orchestrator; sibling sub-reviews cover other files in parallel. The ruleset is atlas-security-v3.

## Hard constraints
- READ-ONLY. Use only the Read, Grep, and Glob tools. Never create, modify, or delete anything. Do not spawn subagents.
- Audit exactly the files listed in the ATLAS-UNIT block at the end of this prompt. Paths are relative to the snapshot root, which is your working directory.
- You must Read every listed file completely, from line 1 to its final line; use offset/limit chunks for long files so the transcript proves full-range coverage.

## Method
1. Read each listed file fully before judging it.
2. For suspicious dataflows, follow a small number of call sites with Grep and Read; do not audit those neighboring files themselves.
3. Classify findings against the ruleset categories: authn-authz, crypto-signing, injection-sql-cmd-path-ssrf, template-injection-proto-pollution, input-validation-deserialization, secret-leakage, info-disclosure, webhook-idempotency-replay, money-integrity, rate-limiting-dos.

## Calibration
- Severities: informational (noteworthy, no action needed), low (defense-in-depth; unreachable from untrusted input today), medium (exploitable under realistic conditions), high (directly exploitable), critical (active compromise, RCE, or auth bypass).
- Only report issues with a concrete abuse path. No style nitpicks and no hypothetical framework CVEs.
- If a file is clean, mark it clean with a one-line summary of what you checked.

## Output contract
Your FINAL message must be ONLY a JSON object (no prose, no markdown fences) of this exact shape:
{"receipts":[{"path":"<file>","status":"reviewed","outcome":"clean"|"findings","summary":"<what you checked>","findings":[{"ruleId":"<category>/<rule>","title":"<one line>","severity":"informational"|"low"|"medium"|"high"|"critical","summary":"<short>","startLine":<n>,"endLine":<n>,"detail":"<abuse path>","fix":"<concrete fix>"}]}]}
Exactly one receipt per listed file; echo each path exactly as listed; every listed file must appear exactly once.`;
const GROK_VERIFICATION_PROMPT = `You are an independent security fact checker working inside the same read-only snapshot discipline as the discovery pass. You receive candidate findings, the exact file inventory, and the validation rubric atlas-security-validation-rubric-v1. You do NOT receive the discovery transcript or its hidden reasoning; construct your own evidence trace.

## Hard constraints
- READ-ONLY. Use only the Read, Grep, and Glob tools. Never create, modify, or delete anything. Do not spawn subagents.
- Read every file listed in the ATLAS-UNIT block completely, from line 1 to its final line, before deciding any candidate that touches it.
- Verify each candidate against the exact snapshot bytes: confirm the code, the dataflow, and the preconditions yourself.

## Output contract
Give every candidate exactly one terminal disposition: reportable (the abuse path is real and in scope), suppressed (real but excluded by policy), not_applicable (the claim does not hold against these bytes), or deferred (cannot be decided within the budget).
Your FINAL message must be ONLY a JSON object (no prose, no markdown fences) of this exact shape:
{"dispositions":[{"fingerprint":"<candidate id>","disposition":"reportable"|"suppressed"|"not_applicable"|"deferred","rationale":"<grounded in your own reads>"}]}
Every candidate in the ATLAS-UNIT block must appear exactly once.`;
function canonicalDigest(value) {
    return auditProviderSha256(canonicalJson(value));
}
const GROK_PROMPT_TEMPLATE_DIGEST = canonicalDigest({
    namespace: 'repo-atlas/grok-prompt-templates/v1',
    builtinVersion: GROK_PROMPT_BUILTIN_VERSION,
    rubricVersion: GROK_VALIDATION_RUBRIC_VERSION,
    review: GROK_REVIEW_PROMPT,
    verification: GROK_VERIFICATION_PROMPT,
});
function isPlainObject(value) {
    return (value !== null &&
        typeof value === 'object' &&
        !Array.isArray(value) &&
        Object.getPrototypeOf(value) === Object.prototype);
}
function redactSecrets(text, secrets) {
    let redacted = text;
    for (const secret of secrets) {
        if (secret.length === 0)
            continue;
        redacted = redacted.split(secret).join('<redacted>');
    }
    return redacted;
}
function spawnGrokProcess(options) {
    return new Promise((resolve, reject) => {
        let child;
        try {
            child = spawn(options.command, [...options.argv], {
                shell: false,
                cwd: options.cwd,
                env: options.env,
                stdio: ['ignore', 'pipe', 'pipe'],
            });
        }
        catch (error) {
            reject(new AuditProviderError('spawn-failed', `unable to start the grok executable: ${error instanceof Error ? error.message : String(error)}`, options.phase));
            return;
        }
        const stdoutChunks = [];
        const stderrChunks = [];
        let stdoutBytes = 0;
        let stderrBytes = 0;
        let timedOut = false;
        let settled = false;
        let killTimer;
        const kill = () => {
            try {
                child.kill('SIGTERM');
            }
            catch {
                // The process may already be gone.
            }
            killTimer = setTimeout(() => {
                try {
                    child.kill('SIGKILL');
                }
                catch {
                    // The process may already be gone.
                }
            }, options.killGraceMs);
            killTimer.unref();
        };
        const timeout = setTimeout(() => {
            timedOut = true;
            kill();
        }, options.timeoutMs);
        timeout.unref();
        const onRunAbort = () => {
            if (!settled)
                kill();
        };
        options.runSignal.addEventListener('abort', onRunAbort, { once: true });
        const cleanup = () => {
            clearTimeout(timeout);
            if (killTimer !== undefined)
                clearTimeout(killTimer);
            options.runSignal.removeEventListener('abort', onRunAbort);
        };
        child.stdout.on('data', (chunk) => {
            stdoutBytes += chunk.byteLength;
            if (stdoutBytes > options.maxStdoutBytes) {
                if (!settled) {
                    settled = true;
                    cleanup();
                    kill();
                    reject(new AuditProviderError('output-limit', `grok stdout exceeds the ${options.maxStdoutBytes}-byte limit`, options.phase));
                }
                return;
            }
            stdoutChunks.push(chunk);
        });
        child.stderr.on('data', (chunk) => {
            stderrBytes += chunk.byteLength;
            if (stderrBytes > options.maxStderrBytes) {
                if (!settled) {
                    settled = true;
                    cleanup();
                    kill();
                    reject(new AuditProviderError('output-limit', `grok stderr exceeds the ${options.maxStderrBytes}-byte limit`, options.phase));
                }
                return;
            }
            stderrChunks.push(chunk);
        });
        child.on('error', (error) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            reject(new AuditProviderError('spawn-failed', redactSecrets(`grok process failed to start: ${error.message}`, options.secrets), options.phase));
        });
        child.on('close', (code, signal) => {
            if (settled)
                return;
            settled = true;
            cleanup();
            resolve({
                code,
                signal,
                stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                stderr: Buffer.concat(stderrChunks).toString('utf8'),
                timedOut,
            });
        });
    });
}
function classifyProcessResult(result, description, secrets, phase) {
    if (result.timedOut) {
        throw new AuditProviderError('timeout', `${description} exceeded its timeout`, phase);
    }
    if (result.signal !== null) {
        throw new AuditProviderError('signal', `${description} was killed by signal ${result.signal}`, phase);
    }
    if (result.code !== 0) {
        const stderrTail = redactSecrets(result.stderr.slice(-2_048), secrets);
        throw new AuditProviderError('exit-code', `${description} exited with code ${String(result.code)}: ${stderrTail}`, phase);
    }
}
// ---------------------------------------------------------------------------
// Environments
// ---------------------------------------------------------------------------
function ambientProbeEnvironment() {
    const env = {};
    for (const key of AMBIENT_PROBE_ENV_KEYS) {
        if (process.env[key] !== undefined)
            env[key] = process.env[key];
    }
    return env;
}
function isolatedEnvironment(context, home) {
    const env = {};
    for (const key of ISOLATED_PASSTHROUGH_ENV_KEYS) {
        if (process.env[key] !== undefined)
            env[key] = process.env[key];
    }
    env.HOME = home;
    env.XDG_CONFIG_HOME = path.join(home, 'config');
    env.XDG_DATA_HOME = path.join(home, 'data');
    env.XDG_STATE_HOME = path.join(home, 'state');
    env.XDG_CACHE_HOME = path.join(home, 'cache');
    env.TMPDIR = path.join(context.tempRoot, 'tmp');
    const apiKeyEnv = context.policy.apiKeyEnv;
    if (apiKeyEnv !== undefined && process.env[apiKeyEnv] !== undefined) {
        env[apiKeyEnv] = process.env[apiKeyEnv];
    }
    return env;
}
function collectSecrets(context) {
    const secrets = [];
    const apiKeyEnv = context.policy.apiKeyEnv;
    if (apiKeyEnv !== undefined && process.env[apiKeyEnv] !== undefined) {
        secrets.push(process.env[apiKeyEnv]);
    }
    return secrets;
}
function resolveGrokCommand(command, phase) {
    const candidates = [];
    if (command.includes('/') || command.includes(path.sep)) {
        candidates.push(path.resolve(command));
    }
    else {
        const pathValue = process.env.PATH ?? '';
        for (const directory of pathValue.split(path.delimiter)) {
            if (directory.length > 0)
                candidates.push(path.join(directory, command));
        }
    }
    for (const candidate of candidates) {
        try {
            const stat = fs.statSync(candidate);
            if (stat.isFile()) {
                fs.accessSync(candidate, fs.constants.X_OK);
                return candidate;
            }
        }
        catch {
            // Try the next candidate.
        }
    }
    throw new AuditProviderError('preflight-rejected', 'the explicit grok executable could not be resolved', phase);
}
function createIsolatedHome(context) {
    const home = path.join(context.tempRoot, 'home');
    fs.mkdirSync(home, { recursive: true, mode: 0o700 });
    fs.chmodSync(home, 0o700);
    for (const child of ['config', 'data', 'state', 'cache']) {
        const directory = path.join(home, child);
        fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
        fs.chmodSync(directory, 0o700);
    }
    const tmp = path.join(context.tempRoot, 'tmp');
    fs.mkdirSync(tmp, { recursive: true, mode: 0o700 });
    fs.chmodSync(tmp, 0o700);
    return home;
}
// Copy only the existing Grok authentication record, with mode 0600. Config,
// hooks, plugins, MCP, memory, and sessions are never copied. The bytes never
// enter logs, journals, receipts, or error messages.
function copyAuthenticationRecord(context, home) {
    const policy = context.policy;
    if (policy.apiKeyEnv !== undefined && process.env[policy.apiKeyEnv] !== undefined) {
        return;
    }
    const source = path.join(os.homedir(), ...policy.authRecordPath.split('/'));
    let stat;
    try {
        stat = fs.lstatSync(source);
    }
    catch {
        return;
    }
    if (stat.isSymbolicLink() || !stat.isFile() || Number(stat.size) > MAX_AUTH_RECORD_BYTES) {
        return;
    }
    const bytes = fs.readFileSync(source);
    const destination = path.join(home, ...policy.authRecordPath.split('/'));
    fs.mkdirSync(path.dirname(destination), { recursive: true, mode: 0o700 });
    fs.writeFileSync(destination, bytes, { mode: 0o600 });
    fs.chmodSync(destination, 0o600);
}
// ---------------------------------------------------------------------------
// Preflight probes and inspect validation
// ---------------------------------------------------------------------------
function validateInspectPayload(value, context) {
    if (!isPlainObject(value)) {
        throw new AuditProviderError('preflight-rejected', 'grok inspect did not return a JSON object', 'inventory');
    }
    if (value.version !== undefined && value.version !== GROK_SUPPORTED_CLI_VERSION) {
        throw new AuditProviderError('preflight-rejected', 'grok inspect reports an unsupported CLI version', 'inventory');
    }
    for (const key of ['hooks', 'plugins', 'mcpServers', 'projectInstructions']) {
        const member = value[key];
        if (member === undefined)
            continue;
        if (!Array.isArray(member) || member.length > 0) {
            throw new AuditProviderError('preflight-rejected', `ambient grok ${key} are present in the isolated environment`, 'inventory');
        }
    }
    const permissionSources = value.permissionSources;
    if (permissionSources !== undefined) {
        if (!Array.isArray(permissionSources) ||
            permissionSources.some((source) => source !== 'default' && source !== 'command-line')) {
            throw new AuditProviderError('preflight-rejected', 'grok reports an unexpected permission source', 'inventory');
        }
    }
    const effectiveConfig = value.effectiveConfig === undefined ? {} : value.effectiveConfig;
    if (!isPlainObject(effectiveConfig)) {
        throw new AuditProviderError('preflight-rejected', 'grok inspect returned an invalid effective configuration', 'inventory');
    }
    const digest = canonicalDigest(effectiveConfig);
    if (Object.keys(effectiveConfig).length > 0 &&
        !context.policy.approvedConfigDigests.includes(digest)) {
        throw new AuditProviderError('preflight-rejected', 'grok effective configuration drifted and its digest is not approved', 'inventory');
    }
    return digest;
}
const resolvedCommands = new WeakMap();
async function grokInventory(context) {
    const policy = context.policy;
    const secrets = collectSecrets(context);
    const probeTimeout = Math.min(policy.timeoutMs, PROBE_TIMEOUT_CAP_MS);
    // Resolve the executable and record its binary/version before changing the
    // environment.
    const command = resolveGrokCommand(policy.command, 'inventory');
    resolvedCommands.set(context, command);
    const binaryStat = fs.statSync(command);
    if (Number(binaryStat.size) > MAX_BINARY_BYTES) {
        throw new AuditProviderError('preflight-rejected', 'the grok executable exceeds the binary digest limit', 'inventory');
    }
    const binaryDigest = auditProviderSha256(fs.readFileSync(command));
    const probesEnv = ambientProbeEnvironment();
    const versionProbe = await spawnGrokProcess({
        command,
        argv: ['--version'],
        cwd: context.tempRoot,
        env: probesEnv,
        timeoutMs: probeTimeout,
        killGraceMs: policy.killGraceMs,
        maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
        maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
        secrets,
        runSignal: context.signal,
        phase: 'inventory',
    });
    classifyProcessResult(versionProbe, 'grok --version', secrets, 'inventory');
    const versionMatch = /(\d+\.\d+\.\d+)/.exec(versionProbe.stdout);
    if (versionMatch === null || versionMatch[1] !== GROK_SUPPORTED_CLI_VERSION) {
        throw new AuditProviderError('preflight-rejected', `grok CLI version is unsupported by ${GROK_ADAPTER_ID}`, 'inventory');
    }
    const binaryVersion = versionMatch[1];
    const helpProbe = await spawnGrokProcess({
        command,
        argv: ['--help'],
        cwd: context.tempRoot,
        env: probesEnv,
        timeoutMs: probeTimeout,
        killGraceMs: policy.killGraceMs,
        maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
        maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
        secrets,
        runSignal: context.signal,
        phase: 'inventory',
    });
    classifyProcessResult(helpProbe, 'grok --help', secrets, 'inventory');
    for (const flag of GROK_PERMISSION_FLAGS) {
        if (!helpProbe.stdout.includes(flag)) {
            throw new AuditProviderError('preflight-rejected', `grok --help does not advertise the required flag ${flag}`, 'inventory');
        }
    }
    // The isolated home and the preflight share one environment.
    const home = createIsolatedHome(context);
    copyAuthenticationRecord(context, home);
    const isolatedEnv = isolatedEnvironment(context, home);
    const inspectProbe = await spawnGrokProcess({
        command,
        argv: ['inspect', '--json'],
        cwd: context.snapshotRoot,
        env: isolatedEnv,
        timeoutMs: probeTimeout,
        killGraceMs: policy.killGraceMs,
        maxStdoutBytes: MAX_PROBE_OUTPUT_BYTES,
        maxStderrBytes: MAX_PROBE_OUTPUT_BYTES,
        secrets,
        runSignal: context.signal,
        phase: 'inventory',
    });
    classifyProcessResult(inspectProbe, 'grok inspect --json', secrets, 'inventory');
    let inspectValue;
    try {
        inspectValue = parseBoundedAuditJsonBytes(new Uint8Array(Buffer.from(inspectProbe.stdout, 'utf8')), MAX_PROBE_OUTPUT_BYTES, 'grok inspect --json');
    }
    catch {
        throw new AuditProviderError('preflight-rejected', 'grok inspect --json did not return bounded JSON', 'inventory');
    }
    const effectiveConfigDigest = validateInspectPayload(inspectValue, context);
    return {
        output: {
            binaryVersion,
            binaryDigest,
            effectiveConfigDigest,
            probeDigests: [
                auditProviderSha256(versionProbe.stdout),
                auditProviderSha256(helpProbe.stdout),
                auditProviderSha256(inspectProbe.stdout),
            ],
        },
        processCount: 3,
        sessionIds: [],
        transcriptDigests: [],
    };
}
// ---------------------------------------------------------------------------
// Prompts
// ---------------------------------------------------------------------------
function renderUnitPrompt(context, unitBlock, template) {
    const sections = [
        template,
        '',
        '## Repository threat context',
        '',
        context.prompt.trim().length > 0 ? context.prompt.trim() : 'None supplied.',
        '',
        'ATLAS-UNIT',
        JSON.stringify(unitBlock),
        '',
    ];
    const prompt = sections.join('\n');
    if (Buffer.byteLength(prompt, 'utf8') > context.policy.maxPromptBytes) {
        throw new AuditProviderError('output-invalid', `rendered prompt exceeds the ${context.policy.maxPromptBytes}-byte limit`);
    }
    return prompt;
}
// ---------------------------------------------------------------------------
// Stdout and transcript proof
// ---------------------------------------------------------------------------
function parseStreamingStdout(stdout, context, phase) {
    const lines = stdout.split('\n').filter((line) => line.trim().length > 0);
    if (lines.length === 0 || lines.length > MAX_STDOUT_LINES) {
        throw new AuditProviderError('output-invalid', 'grok stdout is not a bounded streaming-json sequence', phase);
    }
    let terminal;
    for (const line of lines) {
        let event;
        try {
            event = JSON.parse(line);
        }
        catch {
            throw new AuditProviderError('output-invalid', 'grok stdout contains a non-JSON streaming line', phase);
        }
        if (!isPlainObject(event) || typeof event.type !== 'string') {
            throw new AuditProviderError('output-invalid', 'grok stdout streaming event is malformed', phase);
        }
        terminal = event;
    }
    if (terminal === undefined ||
        terminal.type !== 'result' ||
        terminal.status !== 'success' ||
        typeof terminal.response !== 'string' ||
        terminal.response.length === 0) {
        throw new AuditProviderError('output-invalid', 'grok stdout has no successful terminal result', phase);
    }
    if (Buffer.byteLength(terminal.response, 'utf8') > context.policy.maxResponseBytes) {
        throw new AuditProviderError('output-invalid', 'grok final response exceeds the size bound', phase);
    }
    return terminal.response;
}
function normalizeTranscriptPath(value, context, phase) {
    if (typeof value !== 'string' || value.length === 0) {
        throw new AuditProviderError('transcript-invalid', 'transcript tool call is missing a path', phase);
    }
    let relative = value;
    if (path.isAbsolute(value)) {
        const snapshotPrefix = context.snapshotRoot + path.sep;
        if (!value.startsWith(snapshotPrefix)) {
            throw new AuditProviderError('transcript-invalid', 'transcript tool path escapes the snapshot', phase);
        }
        relative = value.slice(snapshotPrefix.length).split(path.sep).join('/');
    }
    let normalized;
    try {
        normalized = normalizeAuditRepoPath(relative);
    }
    catch {
        throw new AuditProviderError('transcript-invalid', 'transcript tool path is not a safe snapshot-relative path', phase);
    }
    if (context.manifestEntry(normalized) === undefined) {
        throw new AuditProviderError('transcript-invalid', `transcript tool path is outside the snapshot inventory: ${normalized}`, phase);
    }
    return normalized;
}
function validateSessionTranscript(events, context, claimedFiles, phase) {
    if (events.length === 0 || events.length > context.policy.maxTranscriptEvents) {
        throw new AuditProviderError('transcript-invalid', 'transcript event count is out of bounds', phase);
    }
    const calls = new Map();
    const reads = new Map();
    let terminalResponse;
    for (const [index, rawEvent] of events.entries()) {
        if (!isPlainObject(rawEvent) || typeof rawEvent.type !== 'string') {
            throw new AuditProviderError('transcript-invalid', `transcript event ${index} is malformed`, phase);
        }
        if (rawEvent.type === 'tool_call') {
            if (terminalResponse !== undefined) {
                throw new AuditProviderError('transcript-invalid', 'transcript continues after its terminal result', phase);
            }
            const id = rawEvent.id;
            const tool = rawEvent.tool;
            if (typeof id !== 'string' || id.length === 0 || calls.has(id)) {
                throw new AuditProviderError('transcript-invalid', 'transcript tool call id is missing or duplicated', phase);
            }
            if (typeof tool !== 'string' || !GROK_TOOLS.includes(tool)) {
                throw new AuditProviderError('transcript-invalid', `transcript used a forbidden tool: ${String(tool)}`, phase);
            }
            const input = rawEvent.input;
            if (!isPlainObject(input)) {
                throw new AuditProviderError('transcript-invalid', 'transcript tool call input is malformed', phase);
            }
            let toolPath;
            if (input.path !== undefined) {
                toolPath = normalizeTranscriptPath(input.path, context, phase);
            }
            if (tool === 'Read') {
                if (toolPath === undefined) {
                    throw new AuditProviderError('transcript-invalid', 'transcript Read call is missing a path', phase);
                }
                const offset = input.offset === undefined ? 1 : input.offset;
                const limit = input.limit === undefined ? Number.MAX_SAFE_INTEGER : input.limit;
                if (typeof offset !== 'number' ||
                    !Number.isSafeInteger(offset) ||
                    offset < 1 ||
                    typeof limit !== 'number' ||
                    !Number.isSafeInteger(limit) ||
                    limit < 1) {
                    throw new AuditProviderError('transcript-invalid', 'transcript Read call has an invalid offset/limit', phase);
                }
                calls.set(id, { tool, path: toolPath, offset, limit });
            }
            else {
                calls.set(id, { tool, path: toolPath, offset: 1, limit: 1 });
            }
            continue;
        }
        if (rawEvent.type === 'tool_result') {
            const id = rawEvent.id;
            if (typeof id !== 'string' || !calls.has(id)) {
                throw new AuditProviderError('transcript-invalid', 'transcript tool result is not linked to a tool call', phase);
            }
            const call = calls.get(id);
            calls.delete(id);
            if (rawEvent.ok !== true) {
                throw new AuditProviderError('transcript-invalid', 'transcript contains a tool error', phase);
            }
            if (call.tool === 'Read' && call.path !== undefined) {
                const output = rawEvent.output;
                if (!isPlainObject(output)) {
                    throw new AuditProviderError('transcript-invalid', 'transcript Read result is malformed', phase);
                }
                const resultPath = normalizeTranscriptPath(output.path, context, phase);
                if (resultPath !== call.path) {
                    throw new AuditProviderError('transcript-invalid', 'transcript Read result path differs from its call', phase);
                }
                const startLine = output.startLine;
                const endLine = output.endLine;
                const entry = context.manifestEntry(call.path);
                if (typeof startLine !== 'number' ||
                    !Number.isSafeInteger(startLine) ||
                    typeof endLine !== 'number' ||
                    !Number.isSafeInteger(endLine) ||
                    startLine !== call.offset ||
                    endLine < startLine ||
                    endLine > call.offset + call.limit - 1 ||
                    endLine > entry.lines) {
                    throw new AuditProviderError('transcript-invalid', 'transcript Read result does not prove its returned range', phase);
                }
                const intervals = reads.get(call.path) ?? [];
                intervals.push({ start: startLine, end: endLine });
                reads.set(call.path, intervals);
            }
            continue;
        }
        if (rawEvent.type === 'result') {
            if (terminalResponse !== undefined || index !== events.length - 1) {
                throw new AuditProviderError('transcript-invalid', 'transcript must contain exactly one terminal result at the end', phase);
            }
            if (rawEvent.status !== 'success' || typeof rawEvent.response !== 'string') {
                throw new AuditProviderError('transcript-invalid', 'transcript terminal result is not successful', phase);
            }
            if (Buffer.byteLength(rawEvent.response, 'utf8') > context.policy.maxResponseBytes) {
                throw new AuditProviderError('transcript-invalid', 'transcript final response exceeds the size bound', phase);
            }
            terminalResponse = rawEvent.response;
            continue;
        }
        throw new AuditProviderError('transcript-invalid', `transcript contains an unsupported event: ${rawEvent.type}`, phase);
    }
    if (terminalResponse === undefined) {
        throw new AuditProviderError('transcript-invalid', 'transcript has no terminal result', phase);
    }
    if (calls.size > 0) {
        throw new AuditProviderError('transcript-invalid', 'transcript has tool calls without results', phase);
    }
    // Complete contiguous line-range coverage for every file claimed reviewed.
    for (const file of claimedFiles) {
        if (file.lines === 0)
            continue;
        const intervals = (reads.get(file.path) ?? []).sort((left, right) => left.start - right.start);
        let covered = 0;
        for (const interval of intervals) {
            if (interval.start > covered + 1)
                break;
            covered = Math.max(covered, interval.end);
        }
        if (covered < file.lines) {
            throw new AuditProviderError('transcript-invalid', `transcript does not prove full-range reads for ${file.path}`, phase);
        }
    }
    return terminalResponse;
}
function checkJsonDepth(value, depth, maxDepth) {
    if (depth > maxDepth)
        return false;
    if (Array.isArray(value)) {
        return value.every((entry) => checkJsonDepth(entry, depth + 1, maxDepth));
    }
    if (value !== null && typeof value === 'object') {
        return Object.values(value).every((entry) => checkJsonDepth(entry, depth + 1, maxDepth));
    }
    return true;
}
function parseFinalJsonBlock(response, context, phase) {
    let text = response.trim();
    const fenced = /^```(?:json)?\s*\r?\n([\s\S]*?)```\s*$/.exec(text);
    if (fenced !== null) {
        text = fenced[1].trim();
    }
    else if (!(text.startsWith('{') && text.endsWith('}'))) {
        const start = text.indexOf('{');
        const end = text.lastIndexOf('}');
        if (start < 0 || end <= start) {
            throw new AuditProviderError('output-invalid', 'grok final response contains no JSON block', phase);
        }
        text = text.slice(start, end + 1);
    }
    let value;
    try {
        value = parseBoundedAuditJsonBytes(new Uint8Array(Buffer.from(text, 'utf8')), context.policy.maxResponseBytes, 'grok final response');
    }
    catch {
        throw new AuditProviderError('output-invalid', 'grok final response is not bounded valid JSON', phase);
    }
    if (!checkJsonDepth(value, 0, context.policy.maxResponseDepth)) {
        throw new AuditProviderError('output-invalid', 'grok final response exceeds the depth bound', phase);
    }
    return value;
}
// ---------------------------------------------------------------------------
// Analysis units (review + verification): one bounded grok process each
// ---------------------------------------------------------------------------
async function runGrokAnalysisUnit(context, options) {
    const policy = context.policy;
    const phase = options.kind;
    const secrets = collectSecrets(context);
    const command = resolvedCommands.get(context) ?? resolveGrokCommand(policy.command, phase);
    const unitBlock = options.kind === 'review'
        ? {
            kind: 'review',
            unit: options.unit.unit,
            ruleset: context.ruleset.id,
            files: options.unit.files.map((file) => ({
                path: file.path,
                lines: file.lines,
                sha256: file.sha256,
            })),
        }
        : {
            kind: 'verification',
            unit: options.unit.unit,
            candidates: options.unit.candidates.map((candidate) => ({
                fingerprint: candidate.fingerprint,
                ruleId: candidate.ruleId,
                path: candidate.path,
                startLine: candidate.startLine,
                ...(candidate.endLine !== undefined ? { endLine: candidate.endLine } : {}),
                title: candidate.title,
                severity: candidate.severity,
                summary: candidate.summary,
            })),
            files: options.unit.files.map((file) => ({
                path: file.path,
                lines: file.lines,
                sha256: file.sha256,
            })),
        };
    const prompt = renderUnitPrompt(context, unitBlock, options.kind === 'review' ? GROK_REVIEW_PROMPT : GROK_VERIFICATION_PROMPT);
    const promptsDir = path.join(context.tempRoot, 'prompts');
    fs.mkdirSync(promptsDir, { recursive: true, mode: 0o700 });
    const promptFile = path.join(promptsDir, `${options.unit.unit.replaceAll(':', '-')}-${randomUUID().slice(0, 8)}.md`);
    fs.writeFileSync(promptFile, prompt, { mode: 0o600 });
    const home = path.join(context.tempRoot, 'home');
    const env = isolatedEnvironment(context, home);
    const sessionId = randomUUID();
    const argv = [
        '--single',
        '--no-plan',
        '--permission-mode',
        'dontAsk',
        '--tools',
        GROK_TOOLS.join(','),
        '--no-memory',
        '--no-subagents',
        '--disable-web-search',
        '--output-format',
        'streaming-json',
        '--model',
        policy.model,
        '--session-id',
        sessionId,
        '--cwd',
        context.snapshotRoot,
        '--prompt-file',
        promptFile,
    ];
    const result = await spawnGrokProcess({
        command,
        argv,
        cwd: context.snapshotRoot,
        env,
        timeoutMs: policy.timeoutMs,
        killGraceMs: policy.killGraceMs,
        maxStdoutBytes: policy.maxStdoutBytes,
        maxStderrBytes: policy.maxStderrBytes,
        secrets,
        runSignal: context.signal,
        phase,
    });
    classifyProcessResult(result, `grok ${options.kind} unit ${options.unit.unit}`, secrets, phase);
    const stdoutResponse = parseStreamingStdout(result.stdout, context, phase);
    const transcriptPath = path.join(env.XDG_DATA_HOME ?? path.join(home, 'data'), 'grok', 'sessions', sessionId, 'chat_history.jsonl');
    let transcriptBytes;
    try {
        const stat = fs.lstatSync(transcriptPath);
        if (stat.isSymbolicLink() ||
            !stat.isFile() ||
            Number(stat.size) > policy.maxTranscriptBytes) {
            throw new Error('unsafe transcript');
        }
        transcriptBytes = fs.readFileSync(transcriptPath);
    }
    catch {
        throw new AuditProviderError('transcript-invalid', 'the isolated session transcript is missing or unsafe', phase);
    }
    let events;
    try {
        const text = transcriptBytes.toString('utf8');
        const lines = text.split('\n').filter((line) => line.trim().length > 0);
        if (lines.length > policy.maxTranscriptEvents)
            throw new Error('too many events');
        events = lines.map((line) => JSON.parse(line));
    }
    catch {
        throw new AuditProviderError('transcript-invalid', 'the session transcript is not bounded JSONL', phase);
    }
    // Parse and validate the final JSON block first so the transcript can be
    // checked against exactly the files the model claims to have reviewed.
    const outputValue = parseFinalJsonBlock(stdoutResponse, context, phase);
    let output;
    let claimedFiles;
    if (options.kind === 'review') {
        output = validateAuditProviderReviewUnitOutput(outputValue, options.unit.files, policy);
        const entries = [];
        for (const receipt of output.receipts) {
            const entry = context.manifestEntry(receipt.path);
            if (entry === undefined) {
                throw new AuditProviderError('missing-file-receipt', `review receipt references a file outside the snapshot: ${receipt.path}`, phase);
            }
            entries.push(entry);
        }
        claimedFiles = entries;
    }
    else {
        output = validateAuditProviderVerificationUnitOutput(outputValue, options.unit.candidates, policy);
        claimedFiles = options.unit.files;
    }
    const transcriptResponse = validateSessionTranscript(events, context, claimedFiles, phase);
    if (transcriptResponse !== stdoutResponse) {
        throw new AuditProviderError('transcript-mismatch', 'the streaming stdout terminal response differs from the session transcript', phase);
    }
    return {
        output,
        processCount: 1,
        sessionIds: [sessionId],
        transcriptDigests: [auditProviderSha256(new Uint8Array(transcriptBytes))],
    };
}
// ---------------------------------------------------------------------------
// Deterministic synthesis
// ---------------------------------------------------------------------------
function grokSynthesize(context, input) {
    const dispositions = new Map();
    for (const output of input.verificationOutputs) {
        for (const disposition of output.dispositions) {
            dispositions.set(disposition.fingerprint, {
                disposition: disposition.disposition,
                rationale: disposition.rationale,
            });
        }
    }
    const findings = input.candidates.map((candidate) => {
        const disposition = dispositions.get(candidate.fingerprint);
        if (disposition === undefined) {
            throw new AuditProviderError('output-invalid', `candidate ${candidate.fingerprint} has no terminal validation disposition`, 'synthesis');
        }
        return {
            ...candidate,
            disposition: disposition.disposition,
            dispositionRationale: disposition.rationale,
        };
    });
    const files = [];
    for (const target of context.targets) {
        if (target.role !== 'review')
            continue;
        let outcome = 'clean';
        for (const reviewOutput of input.reviewOutputs) {
            const receipt = reviewOutput.receipts.find((entry) => entry.path === target.path);
            if (receipt !== undefined)
                outcome = receipt.outcome;
        }
        files.push({
            path: target.path,
            blob: target.blob,
            lines: target.lines,
            status: 'reviewed',
            outcome,
            findingFingerprints: findings
                .filter((finding) => finding.path === target.path)
                .map((finding) => finding.fingerprint),
        });
    }
    return { files, findings };
}
export function createGrokAuditProvider() {
    return {
        name: 'grok',
        descriptor: {
            provider: 'grok',
            adapter: GROK_ADAPTER_ID,
            adapterVersion: GROK_ADAPTER_VERSION,
            rulesetId: GROK_RULESET_ID,
            promptBuiltinVersion: GROK_PROMPT_BUILTIN_VERSION,
            promptTemplateDigest: GROK_PROMPT_TEMPLATE_DIGEST,
            tools: [...GROK_TOOLS],
            permissionFlags: [...GROK_PERMISSION_FLAGS],
        },
        run(context) {
            return runAuditProviderPhases(context, {
                inventory: grokInventory,
                review: (ctx, unit) => runGrokAnalysisUnit(ctx, { kind: 'review', unit }),
                verification: (ctx, unit) => runGrokAnalysisUnit(ctx, { kind: 'verification', unit }),
                synthesize: grokSynthesize,
            });
        },
    };
}
