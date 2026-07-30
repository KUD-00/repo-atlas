import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import path from 'node:path';
import { TextDecoder, types as utilTypes } from 'node:util';
import { AUDIT_LIMITS, canonicalJson, normalizeAuditRepoPath, readBoundedAuditJsonDocument, withAnchoredAuditGitCapability, } from './audit-core.js';
import { parseAuditDecisionPolicy } from './audit-decisions.js';
const picomatch = createRequire(import.meta.url)('picomatch');
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const POLICY_PATH = '.atlas/review-policy.json';
const POLICY_BYTES = 8 * 1024 * 1024;
const MAX_POLICY_ROWS = 10_000;
const MAX_GLOBS = 50_000;
const MAX_GLOB_CODE_UNITS = 4_096;
const MAX_TEXT_CODE_UNITS = 256 * 1024;
const MAX_GIT_OUTPUT_BYTES = 512 * 1024 * 1024;
const MAX_TRACKED_FILES = 1_000_000;
const MAX_TRACKED_FILE_BYTES = 512 * 1024 * 1024;
export const AUDIT_MATCH_OPERATION_LIMIT = 5000000n;
const ZERO_POLICY_DIGEST = `sha256:${'0'.repeat(64)}`;
const DOMAINS = ['security', 'test'];
const IDENTIFIER_RE = /^[a-z0-9](?:[a-z0-9._-]{0,127})$/;
const ROUTE_SLUG_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const OBJECT_FORMATS = new Set(['sha1', 'sha256']);
const REGULAR_GIT_MODES = new Set(['100644', '100755']);
const EXECUTABLE_OR_CONFIG_EXTENSIONS = new Set([
    '.bash', '.c', '.cc', '.cjs', '.cpp', '.cts', '.fish', '.go', '.graphql',
    '.h', '.hcl', '.hpp', '.java', '.js', '.jsx', '.kt', '.kts', '.mjs',
    '.mts', '.key', '.keystore', '.nix', '.p12', '.pem', '.pfx', '.proto',
    '.ps1', '.py', '.rb', '.rs', '.sh', '.sql', '.swift', '.tf', '.tfvars',
    '.toml', '.ts', '.tsx', '.yaml', '.yml', '.zsh',
]);
const GENERATED_LOCKFILES = new Set([
    'bun.lock',
    'bun.lockb',
    'cargo.lock',
    'composer.lock',
    'gemfile.lock',
    'go.sum',
    'package-lock.json',
    'pipfile.lock',
    'pnpm-lock.yaml',
    'poetry.lock',
    'yarn.lock',
]);
const INERT_TEXT_EXTENSIONS = new Set(['.md', '.mdx']);
const OPERATIONAL_FILENAMES = new Set([
    '.dockerignore',
    '.gitignore',
    '.npmrc',
    '.nvmrc',
    '.sops.yaml',
    '.sops.yml',
    'agents.md',
    'claude.md',
    'codeowners',
    'composer.json',
    'containerfile',
    'deno.json',
    'deno.jsonc',
    'dockerfile',
    'gemfile',
    'go.mod',
    'gradle.properties',
    'makefile',
    'package.json',
    'pipfile',
    'pnpm-workspace.yaml',
    'pom.xml',
    'requirements.txt',
    'review-policy.json',
    'settings.gradle',
    'build.gradle',
    'turbo.json',
]);
class PolicyValidationError extends Error {
    code;
    constructor(code, message) {
        super(message);
        this.code = code;
    }
}
function fail(code, message) {
    throw new PolicyValidationError(code, message);
}
function compareText(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
function hasOwn(value, key) {
    return Object.prototype.hasOwnProperty.call(value, key);
}
function dataRecord(value, pointer) {
    if (value === null ||
        typeof value !== 'object' ||
        Array.isArray(value) ||
        (Object.getPrototypeOf(value) !== Object.prototype &&
            Object.getPrototypeOf(value) !== null)) {
        fail('invalid-policy-type', `${pointer} must be a plain object`);
    }
    return value;
}
function exactKeys(value, required, optional, pointer) {
    const allowed = new Set([...required, ...optional]);
    for (const key of Object.keys(value)) {
        if (!allowed.has(key)) {
            fail('unknown-policy-field', `${pointer}/${key} is not allowed`);
        }
    }
    for (const key of required) {
        if (!hasOwn(value, key)) {
            fail('missing-policy-field', `${pointer}/${key} is required`);
        }
    }
}
function dataArray(value, pointer) {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
        fail('invalid-policy-type', `${pointer} must be an array`);
    }
    if (value.length > MAX_POLICY_ROWS) {
        fail('policy-limit', `${pointer} exceeds the ${MAX_POLICY_ROWS}-item policy limit`);
    }
    return value;
}
function text(value, pointer, options = {}) {
    if (typeof value !== 'string' ||
        value.length > MAX_TEXT_CODE_UNITS ||
        value.includes('\0') ||
        (options.nonempty !== false && value.trim().length === 0) ||
        value !== value.trim()) {
        fail('invalid-policy-text', `${pointer} must be nonempty bounded text without NUL`);
    }
    if (options.identifier && !IDENTIFIER_RE.test(value)) {
        fail('invalid-policy-identifier', `${pointer} must be a canonical lowercase identifier`);
    }
    if (options.routeSlug && !ROUTE_SLUG_RE.test(value)) {
        fail('invalid-policy-slug', `${pointer} must be a route-safe lowercase kebab-case slug`);
    }
    return value;
}
function uniqueSortedStrings(value, pointer, parse, nonempty) {
    const rows = dataArray(value, pointer);
    if (nonempty && rows.length === 0) {
        fail('empty-policy-array', `${pointer} must be nonempty`);
    }
    const parsed = rows.map((candidate, index) => parse(candidate, `${pointer}/${index}`));
    const seen = new Set();
    for (const item of parsed) {
        if (seen.has(item)) {
            fail('duplicate-policy-value', `${pointer} contains duplicate ${item}`);
        }
        seen.add(item);
    }
    return parsed.sort(compareText);
}
function compileGlob(glob, pointer) {
    try {
        return picomatch(glob, { dot: true });
    }
    catch (error) {
        fail('invalid-policy-glob', `${pointer} is not a valid glob: ${error instanceof Error ? error.message : String(error)}`);
    }
}
function glob(value, pointer) {
    if (typeof value !== 'string' ||
        value.length === 0 ||
        value.length > MAX_GLOB_CODE_UNITS ||
        value.includes('\0') ||
        value.includes('\\') ||
        value.startsWith('!') ||
        path.posix.isAbsolute(value) ||
        /^[A-Za-z]:($|\/)/.test(value) ||
        value.split('/').some((segment) => segment.length === 0 || segment === '.' || segment === '..')) {
        fail('invalid-policy-glob', `${pointer} must be a bounded nonempty POSIX glob`);
    }
    compileGlob(value, pointer);
    return value;
}
function globs(value, pointer, nonempty) {
    return uniqueSortedStrings(value, pointer, glob, nonempty);
}
function isUniversalGlob(pattern) {
    const compact = pattern.replace(/(?:\/\*\*)+$/u, '/**');
    return (/^(?:\*\*\/)*\*\*$/u.test(pattern) ||
        /^(?:\*\*\/)+\*$/u.test(pattern) ||
        compact === '**' ||
        pattern === '**/{*,.*}' ||
        pattern === '{*,.*}' ||
        pattern === '**/@(*)');
}
function parseDomains(value, pointer) {
    const selected = uniqueSortedStrings(value, pointer, (candidate, itemPointer) => {
        if (candidate !== 'security' && candidate !== 'test') {
            fail('invalid-policy-domain', `${itemPointer} must be security or test`);
        }
        return candidate;
    }, true);
    return DOMAINS.filter((domain) => selected.includes(domain));
}
function parseRule(value, index) {
    const pointer = `/rules/${index}`;
    const rule = dataRecord(value, pointer);
    exactKeys(rule, ['id', 'include', 'rationale'], ['except', 'domains', 'excluded'], pointer);
    const hasDomains = hasOwn(rule, 'domains');
    const hasExcluded = hasOwn(rule, 'excluded');
    if (hasDomains === hasExcluded) {
        fail('invalid-policy-rule-kind', `${pointer} must contain exactly one of domains or excluded`);
    }
    const common = {
        id: text(rule.id, `${pointer}/id`, { identifier: true }),
        include: globs(rule.include, `${pointer}/include`, true),
        except: hasOwn(rule, 'except')
            ? globs(rule.except, `${pointer}/except`, false)
            : [],
        rationale: text(rule.rationale, `${pointer}/rationale`),
    };
    if (hasDomains) {
        return {
            ...common,
            domains: parseDomains(rule.domains, `${pointer}/domains`),
        };
    }
    const excluded = dataRecord(rule.excluded, `${pointer}/excluded`);
    exactKeys(excluded, ['category', 'reason'], ['owner'], `${pointer}/excluded`);
    for (const pattern of common.include) {
        if (isUniversalGlob(pattern)) {
            fail('universal-exclusion', `excluded rule ${common.id} contains universal include glob ${pattern}`);
        }
    }
    return {
        ...common,
        excluded: {
            category: text(excluded.category, `${pointer}/excluded/category`, { identifier: true }),
            reason: text(excluded.reason, `${pointer}/excluded/reason`),
            ...(hasOwn(excluded, 'owner')
                ? { owner: text(excluded.owner, `${pointer}/excluded/owner`) }
                : {}),
        },
    };
}
function parseUnit(value, index) {
    const pointer = `/units/${index}`;
    const unit = dataRecord(value, pointer);
    exactKeys(unit, ['domain', 'slug', 'title', 'include'], ['except', 'context'], pointer);
    if (unit.domain !== 'security' && unit.domain !== 'test') {
        fail('invalid-policy-domain', `${pointer}/domain must be security or test`);
    }
    return {
        domain: unit.domain,
        slug: text(unit.slug, `${pointer}/slug`, { routeSlug: true }),
        title: text(unit.title, `${pointer}/title`),
        include: globs(unit.include, `${pointer}/include`, true),
        except: hasOwn(unit, 'except')
            ? globs(unit.except, `${pointer}/except`, false)
            : [],
        context: hasOwn(unit, 'context')
            ? globs(unit.context, `${pointer}/context`, false)
            : [],
    };
}
function parseHistoricalAssignment(value, index) {
    const pointer = `/historicalUnitAssignments/${index}`;
    const assignment = dataRecord(value, pointer);
    exactKeys(assignment, ['id', 'sourceKind', 'domain', 'unit', 'include'], [], pointer);
    if (assignment.sourceKind !== 'relayos-security-scan/v1') {
        fail('invalid-historical-source', `${pointer}/sourceKind must be relayos-security-scan/v1`);
    }
    if (assignment.domain !== 'security') {
        fail('invalid-historical-domain', `${pointer}/domain must be security`);
    }
    return {
        id: text(assignment.id, `${pointer}/id`, { identifier: true }),
        sourceKind: assignment.sourceKind,
        domain: assignment.domain,
        unit: text(assignment.unit, `${pointer}/unit`, { routeSlug: true }),
        include: globs(assignment.include, `${pointer}/include`, true),
    };
}
function withoutPolicyDigest(policy) {
    const { policyDigest: _policyDigest, ...input } = policy;
    return input;
}
function parsePolicy(value) {
    const root = dataRecord(value, '/');
    exactKeys(root, [
        'formatVersion',
        'format',
        'rules',
        'units',
        'securityDecisions',
    ], ['historicalUnitAssignments'], '/');
    if (root.formatVersion !== 1 ||
        root.format !== 'atlas-review-policy-v1') {
        fail('invalid-policy-envelope', 'review policy must be atlas-review-policy-v1 formatVersion 1');
    }
    let globCount = 0;
    const rules = dataArray(root.rules, '/rules')
        .map(parseRule)
        .sort((left, right) => compareText(left.id, right.id));
    const ruleIds = new Set();
    for (const rule of rules) {
        if (ruleIds.has(rule.id)) {
            fail('duplicate-policy-id', `duplicate rule ID ${rule.id}`);
        }
        ruleIds.add(rule.id);
        const reservedId = rule.id === 'generated-proof';
        const reservedCategory = 'excluded' in rule &&
            rule.excluded.category === 'generated-proof';
        if (reservedId || reservedCategory) {
            if (!reservedId ||
                !reservedCategory ||
                rule.include.length !== 1 ||
                rule.include[0] !== '.atlas/review-coverage.json' ||
                rule.except.length !== 0) {
                fail('invalid-generated-proof-rule', 'generated-proof is reserved for the exact ' +
                    '.atlas/review-coverage.json exclusion');
            }
        }
        globCount += rule.include.length + rule.except.length;
    }
    const units = dataArray(root.units, '/units')
        .map(parseUnit)
        .sort((left, right) => compareText(left.domain, right.domain) ||
        compareText(left.slug, right.slug));
    const unitIds = new Set();
    for (const unit of units) {
        const id = `${unit.domain}/${unit.slug}`;
        if (unitIds.has(id)) {
            fail('duplicate-policy-id', `duplicate unit ID ${id}`);
        }
        unitIds.add(id);
        globCount += unit.include.length + unit.except.length + unit.context.length;
    }
    const historicalUnitAssignments = hasOwn(root, 'historicalUnitAssignments')
        ? dataArray(root.historicalUnitAssignments, '/historicalUnitAssignments')
            .map(parseHistoricalAssignment)
            .sort((left, right) => compareText(left.id, right.id))
        : [];
    const historicalIds = new Set();
    for (const assignment of historicalUnitAssignments) {
        if (historicalIds.has(assignment.id)) {
            fail('duplicate-policy-id', `duplicate historical assignment ID ${assignment.id}`);
        }
        historicalIds.add(assignment.id);
        if (!unitIds.has(`${assignment.domain}/${assignment.unit}`)) {
            fail('invalid-historical-unit', `historical assignment ${assignment.id} names missing current unit ` +
                `${assignment.domain}/${assignment.unit}`);
        }
        globCount += assignment.include.length;
    }
    if (globCount > MAX_GLOBS) {
        fail('policy-limit', `review policy exceeds the ${MAX_GLOBS}-glob limit`);
    }
    let decisionInput;
    try {
        const provisional = parseAuditDecisionPolicy(root.securityDecisions, ZERO_POLICY_DIGEST);
        if (provisional.acceptedRulesets.includes('codex-contract')) {
            fail('invalid-policy-ruleset', 'acceptedRulesets must contain producer.ruleset IDs; ' +
                'codex-contract is an identity basis, not a ruleset');
        }
        decisionInput = withoutPolicyDigest(provisional);
    }
    catch (error) {
        if (error instanceof PolicyValidationError)
            throw error;
        fail('invalid-security-decision-policy', `securityDecisions is invalid: ${error instanceof Error ? error.message : String(error)}`);
    }
    const hashInput = {
        formatVersion: 1,
        format: 'atlas-review-policy-v1',
        rules,
        units,
        historicalUnitAssignments,
        securityDecisions: decisionInput,
    };
    const policyHash = createHash('sha256')
        .update(canonicalJson(hashInput))
        .digest('hex');
    const securityDecisions = parseAuditDecisionPolicy(decisionInput, `sha256:${policyHash}`);
    return {
        policy: {
            ...hashInput,
            securityDecisions,
        },
        policyHash,
    };
}
export function loadAuditReviewPolicy(root) {
    try {
        const document = readBoundedAuditJsonDocument(root, POLICY_PATH, POLICY_BYTES);
        const parsed = parsePolicy(document.value);
        return { ...parsed, diagnostics: [] };
    }
    catch (error) {
        return {
            policy: null,
            policyHash: null,
            diagnostics: [{
                    code: error instanceof PolicyValidationError
                        ? error.code
                        : 'invalid-review-policy',
                    message: error instanceof Error ? error.message : String(error),
                }],
        };
    }
}
function validateTrackedPath(repoPath) {
    const normalized = normalizeAuditRepoPath(repoPath);
    if (normalized.normalize('NFC') !== normalized) {
        throw new Error('tracked path must be stored in NFC normalization');
    }
    return normalized;
}
function diagnostic(code, message, repoPath) {
    return {
        code,
        message,
        ...(repoPath === undefined ? {} : { path: repoPath }),
    };
}
function readAuditTrackedInventoryWithCapability(capability) {
    const diagnostics = [];
    let objectFormat;
    let stageBytes;
    try {
        const rawFormat = UTF8.decode(capability.gitBytes(['rev-parse', '--show-object-format=storage'], MAX_GIT_OUTPUT_BYTES)).trim();
        if (!OBJECT_FORMATS.has(rawFormat)) {
            throw new Error(`unsupported Git object format ${rawFormat}`);
        }
        objectFormat = rawFormat;
        stageBytes = capability.gitBytes(['ls-files', '--stage', '-z', '--'], MAX_GIT_OUTPUT_BYTES);
    }
    catch (error) {
        return {
            objectFormat: null,
            files: [],
            diagnostics: [diagnostic('git-inventory-failed', `unable to read tracked Git inventory: ${error instanceof Error ? error.message : String(error)}`)],
        };
    }
    let stageText;
    try {
        stageText = UTF8.decode(stageBytes);
    }
    catch {
        return {
            objectFormat,
            files: [],
            diagnostics: [diagnostic('invalid-git-path-encoding', 'tracked Git inventory is not strict UTF-8')],
        };
    }
    const records = stageText.split('\0');
    if (records.at(-1) === '')
        records.pop();
    if (records.length > MAX_TRACKED_FILES) {
        return {
            objectFormat,
            files: [],
            diagnostics: [diagnostic('inventory-limit', `tracked inventory exceeds the ${MAX_TRACKED_FILES}-file limit`)],
        };
    }
    const expectedHashLength = objectFormat === 'sha1' ? 40 : 64;
    const files = [];
    const rawPaths = new Set();
    const collisionPaths = new Map();
    for (const record of records) {
        const match = /^([0-9]{6}) ([0-9a-f]+) ([0-3])\t([\s\S]*)$/.exec(record);
        if (!match) {
            diagnostics.push(diagnostic('invalid-git-index-record', 'Git index returned a malformed stage record'));
            continue;
        }
        const [, indexMode, indexBlob, stage, rawPath] = match;
        let repoPath;
        try {
            repoPath = validateTrackedPath(rawPath);
        }
        catch (error) {
            diagnostics.push(diagnostic('invalid-tracked-path', `${JSON.stringify(rawPath)} is not a safe tracked path: ${error instanceof Error ? error.message : String(error)}`));
            continue;
        }
        if (rawPaths.has(repoPath)) {
            diagnostics.push(diagnostic('duplicate-index-path', `tracked path has duplicate or unresolved index entries: ${JSON.stringify(repoPath)}`, repoPath));
            continue;
        }
        rawPaths.add(repoPath);
        const collisionKey = repoPath.normalize('NFC').toLowerCase();
        const collision = collisionPaths.get(collisionKey);
        if (collision !== undefined && collision !== repoPath) {
            diagnostics.push(diagnostic('tracked-path-collision', `tracked paths collide by case or NFC normalization: ` +
                `${JSON.stringify(collision)} and ${JSON.stringify(repoPath)}`, repoPath));
        }
        else {
            collisionPaths.set(collisionKey, repoPath);
        }
        if (stage !== '0') {
            diagnostics.push(diagnostic('unmerged-index-entry', `tracked path has unresolved index stage ${stage}: ${JSON.stringify(repoPath)}`, repoPath));
            continue;
        }
        if (indexBlob.length !== expectedHashLength ||
            !/^[0-9a-f]+$/.test(indexBlob)) {
            diagnostics.push(diagnostic('invalid-index-object', `tracked path has an invalid ${objectFormat} blob ID: ${JSON.stringify(repoPath)}`, repoPath));
            continue;
        }
        if (!REGULAR_GIT_MODES.has(indexMode)) {
            diagnostics.push(diagnostic('unsafe-index-mode', `tracked path has unsupported non-regular Git mode ${indexMode}: ` +
                `${JSON.stringify(repoPath)}`, repoPath));
            continue;
        }
        try {
            const currentFile = capability.hashWorktreeFile(repoPath, objectFormat, MAX_TRACKED_FILE_BYTES);
            const current = currentFile === null
                ? { blob: null, mode: null, deleted: true }
                : {
                    blob: currentFile.blob,
                    mode: currentFile.mode,
                    deleted: false,
                };
            if (current.mode !== null &&
                current.mode !== indexMode) {
                diagnostics.push(diagnostic('executable-mode-drift', `tracked path executable mode drifted from ${indexMode} to ` +
                    `${current.mode}: ${JSON.stringify(repoPath)}`, repoPath));
            }
            files.push({
                path: repoPath,
                indexBlob,
                currentBlob: current.blob,
                indexMode,
                currentMode: current.mode,
                deleted: current.deleted,
            });
            if (current.deleted) {
                diagnostics.push(diagnostic('tracked-deletion', `tracked path is deleted from the worktree: ${JSON.stringify(repoPath)}`, repoPath));
            }
        }
        catch (error) {
            diagnostics.push(diagnostic('unsafe-worktree-file', `unable to hash tracked path ${JSON.stringify(repoPath)} safely: ${error instanceof Error ? error.message : String(error)}`, repoPath));
        }
    }
    files.sort((left, right) => compareText(left.path, right.path));
    diagnostics.sort((left, right) => compareText(left.path ?? '', right.path ?? '') ||
        compareText(left.code, right.code) ||
        compareText(left.message, right.message));
    return { objectFormat, files, diagnostics };
}
export function readAuditTrackedInventory(root) {
    try {
        return withAnchoredAuditGitCapability(root, readAuditTrackedInventoryWithCapability);
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
            objectFormat: null,
            files: [],
            diagnostics: [diagnostic(/repository root.*(?:must|existing|safe)/i.test(message)
                    ? 'invalid-repository-root'
                    : 'git-inventory-failed', `unable to read one anchored tracked Git inventory: ${message}`)],
        };
    }
}
function matcher(include, except) {
    const includes = include.map((pattern) => picomatch(pattern, { dot: true }));
    const exceptions = except.map((pattern) => picomatch(pattern, { dot: true }));
    return (repoPath) => includes.some((match) => match(repoPath)) &&
        !exceptions.some((match) => match(repoPath));
}
function isExclusionRule(rule) {
    return 'excluded' in rule;
}
function hasGlobMagic(pattern) {
    return /[*?[\]{}()!+@]/.test(pattern);
}
function hazardousExclusionPath(file) {
    if (file.indexMode === '100755' || file.currentMode === '100755')
        return true;
    const lower = file.path.toLowerCase();
    const base = path.posix.basename(lower);
    if (GENERATED_LOCKFILES.has(base))
        return false;
    if (base === '.env' || base.startsWith('.env.'))
        return true;
    if (lower.startsWith('.agents-src/'))
        return true;
    if (lower.startsWith('.github/workflows/'))
        return true;
    const extension = path.posix.extname(lower);
    if (INERT_TEXT_EXTENSIONS.has(extension))
        return false;
    if (OPERATIONAL_FILENAMES.has(base))
        return true;
    if (/^(?:dockerfile|containerfile)(?:\..+)?$/u.test(base))
        return true;
    if (/^(?:tsconfig|eslint|prettier|vitest|vite|playwright|babel|jest)(?:\.[^.]+)*\.json$/u.test(base)) {
        return true;
    }
    if (/(?:^|[-.])(?:config|manifest|schema)\.json$/u.test(base)) {
        return true;
    }
    return EXECUTABLE_OR_CONFIG_EXTENSIONS.has(extension);
}
function exclusionIsExactAndOwned(rule, repoPath) {
    return (typeof rule.excluded.owner === 'string' &&
        rule.excluded.owner.length > 0 &&
        rule.except.length === 0 &&
        rule.include.some((pattern) => !hasGlobMagic(pattern) && pattern === repoPath));
}
function snapshotPlainData(value, pointer, depth = 0, arrayLimits = {
    root: MAX_POLICY_ROWS,
    nested: MAX_POLICY_ROWS,
}, budget = {
    nodes: 0,
    text: 0,
}) {
    if (depth > 128) {
        throw new Error(`${pointer} exceeds the public input depth limit`);
    }
    budget.nodes += 1;
    const nodeLimit = arrayLimits.nodes ?? AUDIT_LIMITS.collectionItems;
    if (budget.nodes > nodeLimit) {
        throw new Error(`${pointer} exceeds the aggregate ${nodeLimit}-node limit`);
    }
    const chargeText = (text, kind) => {
        if (text.length > MAX_TEXT_CODE_UNITS) {
            throw new Error(`${pointer} ${kind} exceeds the ${MAX_TEXT_CODE_UNITS}-code-unit limit`);
        }
        budget.text += text.length;
        const textLimit = arrayLimits.text ?? AUDIT_LIMITS.textTotalCodeUnits;
        if (budget.text > textLimit) {
            throw new Error(`${pointer} exceeds the aggregate string limit of ` +
                `${textLimit} code units`);
        }
    };
    if (value === null ||
        typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'number') {
        if (!Number.isFinite(value) ||
            (Number.isInteger(value) && !Number.isSafeInteger(value))) {
            throw new Error(`${pointer} must be a finite safe JSON number`);
        }
        return value;
    }
    if (typeof value === 'string') {
        chargeText(value, 'string');
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
        const descriptors = Object.getOwnPropertyDescriptors(value);
        const lengthDescriptor = descriptors.length;
        const arrayLimit = depth === 0
            ? arrayLimits.root
            : arrayLimits.nested;
        if (!lengthDescriptor ||
            !('value' in lengthDescriptor) ||
            typeof lengthDescriptor.value !== 'number' ||
            !Number.isSafeInteger(lengthDescriptor.value) ||
            lengthDescriptor.value < 0 ||
            lengthDescriptor.value > arrayLimit) {
            throw new Error(`${pointer} has an invalid array length or exceeds the ` +
                `${arrayLimit}-item limit`);
        }
        const arrayLength = lengthDescriptor.value;
        const ownKeys = Reflect.ownKeys(value);
        if (ownKeys.some((key) => typeof key === 'symbol')) {
            throw new Error(`${pointer} plain array must not contain symbol properties`);
        }
        for (const key of ownKeys) {
            if (key === 'length')
                continue;
            const index = Number(key);
            if (!/^(?:0|[1-9][0-9]*)$/u.test(key) ||
                !Number.isSafeInteger(index) ||
                index < 0 ||
                index >= arrayLength) {
                throw new Error(`${pointer} plain array has unexpected own property ${JSON.stringify(key)}`);
            }
        }
        if (ownKeys.length !== arrayLength + 1) {
            throw new Error(`${pointer} plain array must contain every indexed data property`);
        }
        const output = [];
        for (let index = 0; index < arrayLength; index += 1) {
            const descriptor = descriptors[String(index)];
            if (!descriptor ||
                !descriptor.enumerable ||
                !('value' in descriptor)) {
                throw new Error(`${pointer}/${index} must be an enumerable data property`);
            }
            output.push(snapshotPlainData(descriptor.value, `${pointer}/${index}`, depth + 1, arrayLimits, budget));
        }
        return output;
    }
    if (typeof value !== 'object' ||
        value === null ||
        (Object.getPrototypeOf(value) !== Object.prototype &&
            Object.getPrototypeOf(value) !== null)) {
        throw new Error(`${pointer} must contain only plain data`);
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
        throw new Error(`${pointer} must not contain symbol properties`);
    }
    const output = Object.create(null);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(value)) {
        if (typeof key === 'symbol') {
            throw new Error(`${pointer} must not contain symbol properties`);
        }
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            throw new Error(`${pointer}/${key} is a prohibited prototype key`);
        }
        const descriptor = descriptors[key];
        if (!descriptor?.enumerable) {
            throw new Error(`${pointer}/${key} must be an enumerable own property`);
        }
        if (!('value' in descriptor)) {
            throw new Error(`${pointer}/${key} must not be an accessor`);
        }
        chargeText(key, 'property name');
        output[key] = snapshotPlainData(descriptor.value, `${pointer}/${key}`, depth + 1, arrayLimits, budget);
    }
    return output;
}
function snapshotPublicPolicy(value) {
    const snapshot = dataRecord(snapshotPlainData(value, '/policy'), '/policy');
    const decisions = dataRecord(snapshot.securityDecisions, '/policy/securityDecisions');
    const { policyDigest: _policyDigest, ...decisionInput } = decisions;
    return parsePolicy({
        ...snapshot,
        securityDecisions: decisionInput,
    });
}
export function normalizeAuditReviewPolicy(value) {
    return snapshotPublicPolicy(value);
}
function historicalExpansionDigest(sourceKind, historicalUnitAssignments, assignments, unmapped) {
    return `sha256:${createHash('sha256')
        .update(canonicalJson({
        sourceKind,
        historicalUnitAssignments,
        assignments,
        unmapped,
    }))
        .digest('hex')}`;
}
function emptyHistoricalExpansion(message) {
    const sourceKind = 'relayos-security-scan/v1';
    return {
        assignments: [],
        unmapped: [],
        diagnostics: [diagnostic('invalid-historical-expansion-input', message)],
        expansionDigest: historicalExpansionDigest(sourceKind, [], [], []),
    };
}
function historicalResourceLimitExpansion(sourceKind, historicalUnitAssignments, historicalPaths, operations) {
    return {
        assignments: [],
        unmapped: historicalPaths,
        diagnostics: [diagnostic('historical-resource-limit', `historical expansion requires ${operations.toString()} ` +
                `worst-case match operations; limit is ` +
                `${AUDIT_MATCH_OPERATION_LIMIT.toString()}`)],
        expansionDigest: historicalExpansionDigest(sourceKind, historicalUnitAssignments, [], historicalPaths),
    };
}
function historicalExpansionPaths(value, pointer) {
    const parsed = dataArray(value, pointer).map((candidate, index) => {
        if (typeof candidate !== 'string') {
            fail('invalid-historical-path', `${pointer}/${index} must be a repository path`);
        }
        try {
            return validateTrackedPath(candidate);
        }
        catch (error) {
            fail('invalid-historical-path', `${pointer}/${index} is invalid: ${error instanceof Error ? error.message : String(error)}`);
        }
    }).sort(compareText);
    for (let index = 1; index < parsed.length; index += 1) {
        if (parsed[index] === parsed[index - 1]) {
            fail('duplicate-historical-path', `${pointer} contains duplicate path ${JSON.stringify(parsed[index])}`);
        }
    }
    return parsed;
}
/**
 * Expands policy patterns over caller-validated historical path facts. This
 * primitive deliberately does not decide whether a legacy row is sealed,
 * retired, or otherwise migration-eligible; the Task 6 source importer owns
 * those proofs before supplying `historicalPaths`.
 */
export function expandAuditHistoricalUnitAssignments(unsafeInput) {
    let snapshot;
    try {
        snapshot = snapshotPlainData(unsafeInput, '/historicalExpansion');
    }
    catch (error) {
        return emptyHistoricalExpansion(error instanceof Error ? error.message : String(error));
    }
    try {
        const input = dataRecord(snapshot, '/historicalExpansion');
        exactKeys(input, [
            'policy',
            'sourceKind',
            'historicalPaths',
            'currentPaths',
            'activeReceiptPaths',
        ], [], '/historicalExpansion');
        if (input.sourceKind !== 'relayos-security-scan/v1') {
            fail('invalid-historical-source', 'historical expansion sourceKind must be relayos-security-scan/v1');
        }
        const sourceKind = input.sourceKind;
        const policy = snapshotPublicPolicy(input.policy).policy;
        const historicalPaths = historicalExpansionPaths(input.historicalPaths, '/historicalExpansion/historicalPaths');
        const currentPaths = historicalExpansionPaths(input.currentPaths, '/historicalExpansion/currentPaths');
        const activeReceiptPaths = historicalExpansionPaths(input.activeReceiptPaths, '/historicalExpansion/activeReceiptPaths');
        const pathCount = historicalPaths.length +
            currentPaths.length +
            activeReceiptPaths.length;
        const historicalGlobCount = policy.historicalUnitAssignments.reduce((count, assignment) => count + assignment.include.length, 0);
        const matchOperations = BigInt(pathCount) * BigInt(historicalGlobCount);
        if (matchOperations > AUDIT_MATCH_OPERATION_LIMIT) {
            return historicalResourceLimitExpansion(sourceKind, policy.historicalUnitAssignments, historicalPaths, matchOperations);
        }
        const diagnostics = [];
        const compiled = policy.historicalUnitAssignments.map((assignment) => ({
            assignment,
            matches: matcher(assignment.include, []),
            paths: [],
        }));
        const unitIds = new Set(policy.units.map((unit) => `${unit.domain}:${unit.slug}`));
        for (const candidate of compiled) {
            const unitId = `${candidate.assignment.domain}:${candidate.assignment.unit}`;
            if (!unitIds.has(unitId)) {
                diagnostics.push(diagnostic('historical-unit-domain-mismatch', `historical assignment ${candidate.assignment.id} names missing ` +
                    `same-domain unit ${unitId}`, undefined));
            }
            for (const currentPath of currentPaths) {
                if (candidate.matches(currentPath)) {
                    diagnostics.push(diagnostic('historical-current-overlap', `historical assignment ${candidate.assignment.id} matches ` +
                        `current path ${JSON.stringify(currentPath)}`, currentPath));
                }
            }
            for (const receiptPath of activeReceiptPaths) {
                if (candidate.matches(receiptPath)) {
                    diagnostics.push(diagnostic('historical-active-receipt-overlap', `historical assignment ${candidate.assignment.id} matches ` +
                        `active receipt ${JSON.stringify(receiptPath)}`, receiptPath));
                }
            }
        }
        const unmapped = [];
        for (const historicalPath of historicalPaths) {
            const matches = compiled.filter((candidate) => candidate.matches(historicalPath));
            if (matches.length !== 1) {
                unmapped.push(historicalPath);
                diagnostics.push(diagnostic(matches.length === 0
                    ? 'historical-unmapped-path'
                    : 'historical-assignment-ambiguity', matches.length === 0
                    ? `historical path has no assignment: ${JSON.stringify(historicalPath)}`
                    : `historical path matches multiple assignments: ` +
                        `${JSON.stringify(historicalPath)}`, historicalPath));
                continue;
            }
            matches[0].paths.push(historicalPath);
        }
        for (const candidate of compiled) {
            if (candidate.paths.length === 0) {
                diagnostics.push(diagnostic('historical-assignment-empty', `historical assignment ${candidate.assignment.id} matches no ` +
                    'historical path'));
            }
        }
        const assignments = compiled
            .map(({ assignment, paths }) => ({
            id: assignment.id,
            sourceKind: assignment.sourceKind,
            domain: assignment.domain,
            unit: assignment.unit,
            paths: [...paths].sort(compareText),
        }))
            .sort((left, right) => compareText(left.id, right.id));
        const sortedUnmapped = [...unmapped].sort(compareText);
        diagnostics.sort((left, right) => compareText(left.path ?? '', right.path ?? '') ||
            compareText(left.code, right.code) ||
            compareText(left.message, right.message));
        return {
            assignments,
            unmapped: sortedUnmapped,
            diagnostics,
            expansionDigest: historicalExpansionDigest(sourceKind, policy.historicalUnitAssignments, assignments, sortedUnmapped),
        };
    }
    catch (error) {
        return emptyHistoricalExpansion(error instanceof Error ? error.message : String(error));
    }
}
function snapshotTrackedInventory(inventory) {
    const diagnostics = [];
    const forcedConflicts = new Set();
    let snapshot;
    try {
        snapshot = snapshotPlainData(inventory, '/inventory', 0, {
            root: MAX_TRACKED_FILES,
            nested: MAX_POLICY_ROWS,
            nodes: MAX_TRACKED_FILES * 8 + 1,
            text: MAX_GIT_OUTPUT_BYTES,
        });
    }
    catch (error) {
        return {
            files: [],
            forcedConflicts,
            diagnostics: [diagnostic('invalid-inventory-input', error instanceof Error ? error.message : String(error))],
        };
    }
    if (!Array.isArray(snapshot)) {
        return {
            files: [],
            forcedConflicts,
            diagnostics: [diagnostic('invalid-inventory-input', 'inventory must be a plain array')],
        };
    }
    const files = [];
    const seen = new Map();
    const collisions = new Map();
    const exactFields = new Set([
        'path',
        'indexBlob',
        'currentBlob',
        'indexMode',
        'currentMode',
        'deleted',
    ]);
    for (let index = 0; index < snapshot.length; index += 1) {
        const candidate = snapshot[index];
        if (candidate === null ||
            typeof candidate !== 'object' ||
            Array.isArray(candidate)) {
            diagnostics.push(diagnostic('invalid-inventory-row', `inventory row ${index} must be a plain object`));
            continue;
        }
        const row = candidate;
        if (Object.keys(row).length !== exactFields.size ||
            Object.keys(row).some((key) => !exactFields.has(key))) {
            diagnostics.push(diagnostic('invalid-inventory-row', `inventory row ${index} must have exact tracked-file fields`));
            continue;
        }
        let repoPath;
        try {
            if (typeof row.path !== 'string')
                throw new Error('path must be text');
            repoPath = validateTrackedPath(row.path);
        }
        catch (error) {
            diagnostics.push(diagnostic('invalid-inventory-row', `inventory row ${index} has an invalid path: ${error instanceof Error ? error.message : String(error)}`));
            continue;
        }
        const blobLength = typeof row.indexBlob === 'string' ? row.indexBlob.length : 0;
        const validBlobLength = blobLength === 40 || blobLength === 64;
        if (!validBlobLength ||
            typeof row.indexBlob !== 'string' ||
            !/^[0-9a-f]+$/.test(row.indexBlob) ||
            (row.currentBlob !== null &&
                (typeof row.currentBlob !== 'string' ||
                    row.currentBlob.length !== blobLength ||
                    !/^[0-9a-f]+$/.test(row.currentBlob))) ||
            !REGULAR_GIT_MODES.has(String(row.indexMode)) ||
            (row.currentMode !== null &&
                !REGULAR_GIT_MODES.has(String(row.currentMode))) ||
            typeof row.deleted !== 'boolean') {
            diagnostics.push(diagnostic('invalid-inventory-row', `inventory row has invalid blob, mode, or deletion fields: ${JSON.stringify(repoPath)}`, repoPath));
            continue;
        }
        const file = {
            path: repoPath,
            indexBlob: row.indexBlob,
            currentBlob: row.currentBlob,
            indexMode: row.indexMode,
            currentMode: row.currentMode,
            deleted: row.deleted,
        };
        files.push(file);
        const indexes = seen.get(repoPath) ?? [];
        indexes.push(files.length - 1);
        seen.set(repoPath, indexes);
        const collisionKey = repoPath.normalize('NFC').toLowerCase();
        const collision = collisions.get(collisionKey);
        if (collision !== undefined && collision !== repoPath) {
            forcedConflicts.add(collision);
            forcedConflicts.add(repoPath);
            diagnostics.push(diagnostic('inventory-path-collision', `inventory paths collide by case or NFC: ` +
                `${JSON.stringify(collision)} and ${JSON.stringify(repoPath)}`, repoPath));
        }
        else {
            collisions.set(collisionKey, repoPath);
        }
        const coherent = (file.deleted &&
            file.currentBlob === null &&
            file.currentMode === null) ||
            (!file.deleted &&
                file.currentBlob !== null &&
                file.currentMode !== null);
        if (!coherent) {
            forcedConflicts.add(repoPath);
            diagnostics.push(diagnostic('incoherent-inventory-deletion', `inventory deletion/currentBlob/currentMode fields are incoherent for ${JSON.stringify(repoPath)}`, repoPath));
        }
        if (file.deleted) {
            forcedConflicts.add(repoPath);
            diagnostics.push(diagnostic('tracked-deletion', `tracked path is deleted from the worktree: ${JSON.stringify(repoPath)}`, repoPath));
        }
        if (file.currentMode !== null &&
            file.currentMode !== file.indexMode) {
            forcedConflicts.add(repoPath);
            diagnostics.push(diagnostic('inventory-mode-drift', `inventory executable mode drifted for ${JSON.stringify(repoPath)}`, repoPath));
        }
    }
    for (const [repoPath, indexes] of seen) {
        if (indexes.length <= 1)
            continue;
        forcedConflicts.add(repoPath);
        diagnostics.push(diagnostic('duplicate-inventory-path', `inventory contains duplicate path ${JSON.stringify(repoPath)}`, repoPath));
    }
    return { files, forcedConflicts, diagnostics };
}
export function classifyAuditInventory(inventory, policyInput) {
    const snapshot = snapshotTrackedInventory(inventory);
    const diagnostics = [...snapshot.diagnostics];
    if (policyInput === null) {
        return {
            files: snapshot.files.map((file) => ({
                ...file,
                ruleIds: [],
                classification: { kind: 'conflict' },
            })),
            diagnostics: [...diagnostics, diagnostic('missing-review-policy', 'tracked inventory cannot be classified without a valid review policy')],
        };
    }
    let policy;
    try {
        policy = snapshotPublicPolicy(policyInput).policy;
    }
    catch (error) {
        return {
            files: snapshot.files.map((file) => ({
                ...file,
                ruleIds: [],
                classification: { kind: 'conflict' },
            })),
            diagnostics: [...diagnostics, diagnostic('invalid-public-policy', `review policy input is invalid: ${error instanceof Error ? error.message : String(error)}`)],
        };
    }
    const ruleGlobCount = policy.rules.reduce((count, rule) => count + rule.include.length + rule.except.length, 0);
    const exclusionGlobCount = policy.rules.reduce((count, rule) => count + (isExclusionRule(rule)
        ? rule.include.length + rule.except.length
        : 0), 0);
    const unitGlobCount = policy.units.reduce((count, unit) => count + unit.include.length + unit.except.length, 0);
    const historicalGlobCount = policy.historicalUnitAssignments.reduce((count, assignment) => count + assignment.include.length, 0);
    const matchOperations = BigInt(snapshot.files.length) * BigInt(ruleGlobCount +
        exclusionGlobCount +
        unitGlobCount +
        historicalGlobCount);
    if (matchOperations > AUDIT_MATCH_OPERATION_LIMIT) {
        return {
            files: snapshot.files.map((file) => ({
                ...file,
                ruleIds: [],
                classification: { kind: 'conflict' },
            })),
            diagnostics: [...diagnostics, diagnostic('classification-resource-limit', `classification requires ${matchOperations.toString()} ` +
                    `worst-case match operations; limit is ` +
                    `${AUDIT_MATCH_OPERATION_LIMIT.toString()}`)],
        };
    }
    const compiledRules = policy.rules.map((rule) => ({
        rule,
        matches: matcher(rule.include, rule.except),
    }));
    const compiledUnits = policy.units.map((unit) => ({
        unit,
        owns: matcher(unit.include, unit.except),
    }));
    const historicalMatchers = policy.historicalUnitAssignments.map((assignment) => ({
        assignment,
        matches: matcher(assignment.include, []),
    }));
    const universalSwallow = new Set();
    if (snapshot.files.length > 0) {
        for (const compiled of compiledRules) {
            if (isExclusionRule(compiled.rule) &&
                compiled.rule.include.some(hasGlobMagic) &&
                snapshot.files.every((file) => compiled.matches(file.path))) {
                universalSwallow.add(compiled.rule.id);
                diagnostics.push(diagnostic('universal-exclusion', `excluded rule ${compiled.rule.id} swallows the entire tracked inventory`));
            }
        }
    }
    const ownedUnits = new Set();
    const files = snapshot.files.map((file) => {
        const matchedRules = compiledRules
            .filter((compiled) => compiled.matches(file.path))
            .map((compiled) => compiled.rule);
        const ruleIds = matchedRules.map((rule) => rule.id).sort(compareText);
        const exclusions = matchedRules.filter(isExclusionRule);
        const selectedDomains = new Set();
        for (const rule of matchedRules) {
            if (!isExclusionRule(rule)) {
                for (const domain of rule.domains)
                    selectedDomains.add(domain);
            }
        }
        let classification;
        const historical = historicalMatchers.filter((candidate) => candidate.matches(file.path));
        if (historical.length > 0) {
            classification = { kind: 'conflict' };
            diagnostics.push(diagnostic('historical-current-overlap', `historical assignment(s) ${historical.map((item) => item.assignment.id).join(', ')} match current tracked path ` +
                `${JSON.stringify(file.path)}`, file.path));
        }
        else if (snapshot.forcedConflicts.has(file.path)) {
            classification = { kind: 'conflict' };
        }
        else if (ruleIds.length === 0) {
            classification = { kind: 'unclassified' };
            diagnostics.push(diagnostic('unclassified-tracked-path', `tracked path is unclassified: ${JSON.stringify(file.path)}`, file.path));
        }
        else if (exclusions.length > 1 ||
            (exclusions.length > 0 && selectedDomains.size > 0)) {
            classification = { kind: 'conflict' };
            diagnostics.push(diagnostic('classification-rule-conflict', `tracked path ${JSON.stringify(file.path)} matches conflicting domain ` +
                `and/or exclusion rules: ${ruleIds.join(', ')}`, file.path));
        }
        else if (exclusions.length === 1) {
            const exclusion = exclusions[0];
            if (universalSwallow.has(exclusion.id) ||
                (hazardousExclusionPath(file) &&
                    !exclusionIsExactAndOwned(exclusion, file.path))) {
                classification = { kind: 'conflict' };
                diagnostics.push(diagnostic('unsafe-broad-exclusion', `executable or configuration path ${JSON.stringify(file.path)} ` +
                    `requires an exact exclusion with an owner`, file.path));
            }
            else {
                classification = {
                    kind: 'excluded',
                    ruleId: exclusion.id,
                    category: exclusion.excluded.category,
                    reason: exclusion.excluded.reason,
                    ...(exclusion.excluded.owner === undefined
                        ? {}
                        : { owner: exclusion.excluded.owner }),
                };
            }
        }
        else {
            const domains = {};
            let conflict = false;
            for (const domain of DOMAINS) {
                if (!selectedDomains.has(domain))
                    continue;
                const owners = compiledUnits
                    .filter((compiled) => compiled.unit.domain === domain &&
                    compiled.owns(file.path))
                    .map((compiled) => compiled.unit);
                if (owners.length !== 1) {
                    conflict = true;
                    diagnostics.push(diagnostic('unit-ownership-conflict', `tracked path ${JSON.stringify(file.path)} requires ${domain} ` +
                        `review but matches ${owners.length} owning units; context globs ` +
                        `do not own coverage`, file.path));
                    continue;
                }
                domains[domain] = { unit: owners[0].slug };
                ownedUnits.add(`${domain}/${owners[0].slug}`);
            }
            classification = conflict
                ? { kind: 'conflict' }
                : { kind: 'review', domains };
        }
        return { ...file, ruleIds, classification };
    });
    for (const unit of policy.units) {
        const unitId = `${unit.domain}/${unit.slug}`;
        if (!ownedUnits.has(unitId)) {
            diagnostics.push(diagnostic('empty-review-unit', `review unit ${unitId} owns no currently classified tracked paths`, undefined));
        }
    }
    diagnostics.sort((left, right) => compareText(left.path ?? '', right.path ?? '') ||
        compareText(left.code, right.code) ||
        compareText(left.message, right.message));
    return { files, diagnostics };
}
