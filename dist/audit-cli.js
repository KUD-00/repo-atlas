import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { loadConfig, scan } from './scan.js';
import { auditStatusEntries, importLegacyAudit, loadAuditExactEvidence, loadAuditPortfolios, stampAudits, } from './audits.js';
import { computeAuditCanonicalDigest, loadAuditObservationHistory, loadAuditObservations, } from './audit-v3.js';
import { canonicalJson, listBoundedAuditDirectory, normalizeAuditRepoPath, readBoundedAuditJson, } from './audit-core.js';
import { appendAuditDecision, buildAuditDecisionIndex, loadAuditDecisionLedgers, } from './audit-decisions.js';
import { classifyAuditInventory, loadAuditReviewPolicy, readAuditTrackedInventory, } from './audit-policy.js';
import { buildAuditCoverageReport, checkAuditCoverage, updateAuditCoverage, } from './audit-coverage-generator.js';
import { importCodexSecurityBundle } from './audit-import-codex.js';
import { AUDIT_PROVIDER_INVOCATION_COMMAND, AuditProviderError, loadAuditProviderPolicy, resolveAuditProviderPolicy, runAuditProviderInvocation, } from './audit-providers.js';
import { createGrokAuditProvider } from './audit-provider-grok.js';
import { publishAuditProviderRunObservations } from './audit-run-publish.js';
import { buildAuditLocalizationInput, canonicalAuditLocalizationJson, loadConfiguredAuditLocalizations, } from './audit-localizations.js';
import { loadReviewCoverage } from './review-coverage.js';
import { computeStatus } from './status.js';
const picomatch = createRequire(import.meta.url)('picomatch');
const AUDIT_USAGE = `repo-atlas audit — hierarchical audit command surface

usage: repo-atlas audit <verb> [args]

  audit check [--allow-incomplete]
                           validate V3/V2/V1 ledgers, history, decisions,
                           migration receipts, lifecycle policy, provenance, and
                           canonical coverage; exit 0 only for complete state or
                           honest incomplete state with --allow-incomplete
                           (never launches a provider)
  audit coverage check [--allow-incomplete]
                           regenerate review coverage in memory and byte-compare
  audit coverage update [--allow-incomplete]
                           rewrite .atlas/review-coverage.json (a write by name)
  audit status [--json]    report the V3 portfolio, decisions, migrations, and
                           coverage state (canonical JSON with --json)
  audit run security --provider grok [--unit <slug> | --all | --stale] [--resume <id>]
                     [--reuse-unchanged]
                           the ONLY command that launches a provider; default
                           selection is stale units from policy evidence.
                           --reuse-unchanged carries a published receipt forward
                           for any file whose blob and reviewing inputs are
                           unchanged, so a rescan costs what changed
  audit import codex-security <scan-dir> --slug <slug> [--apply]
                           import a sealed Codex Security 1.0 bundle as a V3
                           semantic observation (dry-run without --apply)
  audit import legacy-v1 <ledger.json>...
                           import legacy scans[] ledgers into atlas-audit-v1

  audit decision set <finding-or-occurrence> <action> --event <event.json>
                           append a finding-disposition event (a write by name)
  audit reconcile <before> <after> --event <event.json>
                           append a finding-reconciliation event
  audit retire <path> --event <event.json>
                           append a scope-retirement event for a tracked path
  audit retire --finalize-staged --event <event.json>
                           finalize an existing staged-deletion event
  audit stamp [names...]   (re)stamp audit ledgers with per-file git hashes
  audit localization input --locale <en|ja|zh|ko> [--json]
                           emit digest-bound canonical audit prose for translation
  audit localization check [--json]
                           require every configured audit content locale to be current

Dry-run is the default for import/migrate; pass --apply to write. decision set,
run, and coverage update are writes by name and apply immediately.`;
const USAGE_CHECK = 'usage: repo-atlas audit check [--allow-incomplete]';
const USAGE_COVERAGE = 'usage: repo-atlas audit coverage <check|update> [--allow-incomplete]';
const USAGE_STATUS = 'usage: repo-atlas audit status [--json]';
const USAGE_RUN = 'usage: repo-atlas audit run security --provider grok [--unit <slug> | --all | --stale] ' +
    '[--resume <id>] [--reuse-unchanged]';
const USAGE_IMPORT = 'usage: repo-atlas audit import <codex-security|legacy-v1> ...';
const USAGE_IMPORT_CODEX = 'usage: repo-atlas audit import codex-security <scan-dir> --slug <slug> [--apply]';
const USAGE_IMPORT_LEGACY = 'usage: repo-atlas audit import legacy-v1 <legacy-ledger.json>...';
const USAGE_DECISION_SET = 'usage: repo-atlas audit decision set <finding-or-occurrence> <action> --event <event.json>';
const USAGE_RECONCILE = 'usage: repo-atlas audit reconcile <before> <after> --event <event.json>';
const USAGE_RETIRE = 'usage: repo-atlas audit retire <path> --event <event.json>\n' +
    '       repo-atlas audit retire --finalize-staged --event <event.json>';
const USAGE_LOCALIZATION = 'usage: repo-atlas audit localization input --locale <en|ja|zh|ko> [--json]\n' +
    '       repo-atlas audit localization check [--json]';
const EVENT_FILE_BYTE_LIMIT = 4 * 1024 * 1024;
const MIGRATION_RECEIPT_BYTE_LIMIT = 64 * 1024 * 1024;
const MIGRATION_RECEIPT_COUNT_LIMIT = 1024;
const MIGRATION_ID_RE = /^amig_[0-9a-f]{24}$/u;
const SHA256_RE = /^sha256:[0-9a-f]{64}$/u;
const PRINT_DIAGNOSTIC_LIMIT = 20;
const PRINT_ROW_LIMIT = 15;
const AUDIT_FINDING_ACTIONS = new Set([
    'open',
    'remediated',
    'accepted-risk',
    'separate-design',
    'false-positive',
    'superseded',
    'reopened',
]);
function usage(usageText, message) {
    throw new Error(`${message}\n${usageText}`);
}
function errorMessage(error) {
    return error instanceof Error ? error.message : String(error);
}
function parseAuditArgs(args, spec, usageText) {
    const valueFlags = new Set(spec.values);
    const boolFlags = new Set(spec.flags);
    const positionals = [];
    const values = new Map();
    const flags = new Set();
    for (let index = 0; index < args.length; index++) {
        const arg = args[index];
        if (valueFlags.has(arg)) {
            const value = args[index + 1];
            if (value === undefined || value.startsWith('--')) {
                usage(usageText, `${arg} requires a value`);
            }
            if (values.has(arg))
                usage(usageText, `${arg} given twice`);
            values.set(arg, value);
            index++;
            continue;
        }
        if (boolFlags.has(arg)) {
            if (flags.has(arg))
                usage(usageText, `${arg} given twice`);
            flags.add(arg);
            continue;
        }
        if (arg.startsWith('--'))
            usage(usageText, `unknown flag ${arg}`);
        positionals.push(arg);
    }
    return { positionals, values, flags };
}
function rejectPositionals(parsed, usageText) {
    if (parsed.positionals.length > 0) {
        usage(usageText, `unexpected positional argument ${parsed.positionals[0]}`);
    }
}
function requiredValue(parsed, flag, usageText) {
    const value = parsed.values.get(flag);
    if (value === undefined)
        usage(usageText, `${flag} is required`);
    return value;
}
function requireConfig(root) {
    const config = loadConfig(root);
    if (!config) {
        throw new Error(`no .atlas/config.json in ${root} — run 'repo-atlas init' first`);
    }
    return config;
}
function printDiagnostics(diagnostics, indent = '  ') {
    for (const diagnostic of diagnostics.slice(0, PRINT_DIAGNOSTIC_LIMIT)) {
        console.log(`${indent}${diagnostic.code}${diagnostic.path ? ` ${diagnostic.path}` : ''}: ${diagnostic.message}`);
    }
    if (diagnostics.length > PRINT_DIAGNOSTIC_LIMIT) {
        console.log(`${indent}… and ${diagnostics.length - PRINT_DIAGNOSTIC_LIMIT} more`);
    }
}
function loadAuditMigrationReceipts(root) {
    const receipts = [];
    const diagnostics = [];
    let names;
    try {
        names = listBoundedAuditDirectory(root, '.atlas/migrations', MIGRATION_RECEIPT_COUNT_LIMIT);
    }
    catch (error) {
        return {
            receipts,
            diagnostics: [{
                    code: 'audit-migrations-directory-invalid',
                    path: '.atlas/migrations',
                    message: errorMessage(error),
                }],
        };
    }
    for (const name of names) {
        const repoPath = `.atlas/migrations/${name}`;
        if (!name.endsWith('.json')) {
            diagnostics.push({
                code: 'audit-migration-receipt-unexpected-entry',
                path: repoPath,
                message: 'migration receipts must be JSON files',
            });
            continue;
        }
        try {
            const raw = readBoundedAuditJson(root, repoPath, MIGRATION_RECEIPT_BYTE_LIMIT);
            if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
                throw new Error('migration receipt must be a plain JSON object');
            }
            const receipt = raw;
            if (receipt.formatVersion !== 1 || receipt.format !== 'atlas-audit-migration-v1') {
                throw new Error('migration receipt must declare format atlas-audit-migration-v1');
            }
            const migrationId = receipt.migrationId;
            if (typeof migrationId !== 'string' || !MIGRATION_ID_RE.test(migrationId)) {
                throw new Error('migration receipt has an invalid migrationId');
            }
            if (name !== `${migrationId}.json`) {
                throw new Error(`migration receipt id ${migrationId} does not match its file name`);
            }
            const digest = receipt.receiptDigest;
            if (typeof digest !== 'string' || !SHA256_RE.test(digest)) {
                throw new Error('migration receipt has an invalid receiptDigest');
            }
            const { receiptDigest: _sealed, ...receiptCore } = receipt;
            if (computeAuditCanonicalDigest(receiptCore) !== digest) {
                throw new Error('migration receipt digest does not cover its canonical bytes');
            }
            receipts.push({ migrationId, path: repoPath });
        }
        catch (error) {
            diagnostics.push({
                code: 'audit-migration-receipt-invalid',
                path: repoPath,
                message: errorMessage(error),
            });
        }
    }
    receipts.sort((left, right) => left.migrationId < right.migrationId ? -1 : left.migrationId > right.migrationId ? 1 : 0);
    return { receipts, diagnostics };
}
function legacyLedgerDiagnostics(root) {
    const config = loadConfig(root) ?? {};
    const statuses = auditStatusEntries(root, scan(root, config));
    const diagnostics = [];
    for (const entry of statuses) {
        if (entry.invalidReason === null)
            continue;
        diagnostics.push({
            code: 'audit-legacy-ledger-invalid',
            path: path.relative(root, entry.file),
            message: entry.invalidReason,
        });
    }
    return diagnostics;
}
function computeAuditCheck(root, allowIncomplete) {
    const area = (name, diagnostics) => ({
        area: name,
        ok: diagnostics.length === 0,
        diagnostics,
    });
    const areas = [];
    const policy = loadAuditReviewPolicy(root);
    areas.push(area('policy', [...policy.diagnostics]));
    const observations = loadAuditObservations(root);
    areas.push(area('observations', [...observations.diagnostics]));
    const decisions = loadAuditDecisionLedgers(root);
    areas.push(area('decisions', [...decisions.diagnostics]));
    areas.push(area('legacy-ledgers', legacyLedgerDiagnostics(root)));
    const migrations = loadAuditMigrationReceipts(root);
    areas.push(area('migrations', migrations.diagnostics));
    // Exact/semantic coverage, lifecycle assurance, and canonical coverage bytes.
    // The coverage result already separates structural invalidity from honest
    // missing/stale evidence allowed by --allow-incomplete; its diagnostics are
    // reported either way, but they fail the gate only when coverage.ok is false.
    const coverage = checkAuditCoverage(root, { allowIncomplete });
    areas.push({ area: 'coverage', ok: coverage.ok, diagnostics: [...coverage.diagnostics] });
    const ok = areas.every((entry) => entry.ok);
    return {
        ok,
        areas,
        coverageVerdict: coverage.report.verdict,
        coverageCurrent: coverage.current,
        historyAhead: observations.historyAhead,
    };
}
function auditCheck(root, args) {
    const parsed = parseAuditArgs(args, { values: [], flags: ['--allow-incomplete'] }, USAGE_CHECK);
    rejectPositionals(parsed, USAGE_CHECK);
    const allowIncomplete = parsed.flags.has('--allow-incomplete');
    const result = computeAuditCheck(root, allowIncomplete);
    if (result.ok) {
        console.log(`audit check: ok — ${result.areas.length} areas valid · ` +
            `coverage ${result.coverageVerdict}` +
            (allowIncomplete && result.coverageVerdict === 'incomplete'
                ? ' (honest incomplete allowed by --allow-incomplete)'
                : ''));
    }
    else {
        const failed = result.areas.filter((area) => !area.ok);
        console.log(`audit check: failed — ${failed.length}/${result.areas.length} areas invalid`);
    }
    for (const area of result.areas) {
        if (area.ok && area.diagnostics.length === 0) {
            console.log(`  ${area.area}: ok`);
        }
        else {
            console.log(`  ${area.area}: ${area.ok ? 'reported' : 'invalid'} — ${area.diagnostics.length} diagnostic(s)`);
            printDiagnostics(area.diagnostics, '    ');
        }
    }
    if (result.historyAhead.length > 0) {
        console.log(`  history-ahead: ${result.historyAhead.join(', ')}`);
    }
    if (!result.ok)
        process.exitCode = 1;
}
// ---------------------------------------------------------------------------
// audit coverage check / update
// ---------------------------------------------------------------------------
function auditCoverage(root, args) {
    const [verb, ...rest] = args;
    if (verb !== 'check' && verb !== 'update') {
        usage(USAGE_COVERAGE, verb === undefined
            ? 'audit coverage requires a verb (check or update)'
            : `unknown audit coverage verb: ${verb}`);
    }
    const parsed = parseAuditArgs(rest, { values: [], flags: ['--allow-incomplete'] }, USAGE_COVERAGE);
    rejectPositionals(parsed, USAGE_COVERAGE);
    const allowIncomplete = parsed.flags.has('--allow-incomplete');
    const result = verb === 'update'
        ? updateAuditCoverage(root, { allowIncomplete })
        : checkAuditCoverage(root, { allowIncomplete });
    const verdict = result.report.verdict;
    console.log(`audit coverage ${verb}: ${result.current ? 'current' : 'stale-bytes'} · verdict ${verdict}` +
        (result.wrote ? ' · wrote .atlas/review-coverage.json' : '') +
        (verdict === 'incomplete' && allowIncomplete
            ? ' · honest incomplete allowed by --allow-incomplete'
            : '') +
        (!result.ok && verdict === 'incomplete' && !allowIncomplete
            ? ' · pass --allow-incomplete to accept honest incomplete evidence'
            : ''));
    printDiagnostics(result.diagnostics);
    if (!result.ok)
        process.exitCode = 1;
}
// ---------------------------------------------------------------------------
// audit status
// ---------------------------------------------------------------------------
function auditStatus(root, args) {
    const parsed = parseAuditArgs(args, { values: [], flags: ['--json'] }, USAGE_STATUS);
    rejectPositionals(parsed, USAGE_STATUS);
    const observations = loadAuditObservations(root);
    const histories = loadAuditObservationHistory(root);
    const decisions = loadAuditDecisionLedgers(root);
    const migrations = loadAuditMigrationReceipts(root);
    const coverage = checkAuditCoverage(root, { allowIncomplete: true });
    const historyCounts = new Map(histories.histories.map((history) => [history.slug, history.entries.length]));
    const units = observations.observations.map((ledger) => ({
        slug: ledger.slug,
        reviewState: ledger.current.reviewState,
        findings: ledger.current.findings.length,
        files: ledger.current.scope.fileCount,
        historyEntries: historyCounts.get(ledger.slug) ?? 0,
    }));
    const payload = {
        observations: {
            slugs: observations.observations.map((ledger) => ledger.slug),
            historyAhead: observations.historyAhead,
            units,
            diagnostics: [...observations.diagnostics, ...histories.diagnostics],
        },
        decisions: {
            ledgers: decisions.ledgers.map((ledger) => ({
                slug: ledger.slug,
                entries: ledger.entries.length,
            })),
            diagnostics: [...decisions.diagnostics],
        },
        migrations: {
            receipts: migrations.receipts,
            diagnostics: migrations.diagnostics,
        },
        coverage: {
            current: coverage.current,
            verdict: coverage.report.verdict,
            summary: coverage.report.summary,
            diagnostics: [...coverage.diagnostics],
        },
    };
    if (parsed.flags.has('--json')) {
        process.stdout.write(`${canonicalJson(payload)}\n`);
        return;
    }
    const eventCount = decisions.ledgers.reduce((total, ledger) => total + ledger.entries.length, 0);
    console.log(`observations: ${units.length} current ledger(s) · ` +
        `${histories.histories.length} histor${histories.histories.length === 1 ? 'y' : 'ies'} · ` +
        `${observations.historyAhead.length} history-ahead`);
    for (const unit of units.slice(0, PRINT_ROW_LIMIT)) {
        console.log(`  ${unit.slug}: ${unit.reviewState} · ${unit.findings} finding(s) · ` +
            `${unit.files} file(s) · ${unit.historyEntries} history entr${unit.historyEntries === 1 ? 'y' : 'ies'}`);
    }
    if (units.length > PRINT_ROW_LIMIT) {
        console.log(`  … and ${units.length - PRINT_ROW_LIMIT} more (use --json for the full list)`);
    }
    console.log(`decisions: ${decisions.ledgers.length} ledger(s) · ${eventCount} event(s)`);
    console.log(`migrations: ${migrations.receipts.length} receipt(s)`);
    console.log(`coverage: ${coverage.current ? 'current' : 'stale-bytes'} · verdict ${coverage.report.verdict}`);
    const diagnostics = [
        ...payload.observations.diagnostics,
        ...payload.decisions.diagnostics,
        ...payload.migrations.diagnostics,
        ...payload.coverage.diagnostics,
    ];
    if (diagnostics.length > 0) {
        console.log(`diagnostics: ${diagnostics.length}`);
        printDiagnostics(diagnostics);
    }
}
function loadRunPolicy(root) {
    const policyLoad = loadAuditReviewPolicy(root);
    if (policyLoad.policy === null || policyLoad.policyHash === null) {
        throw new Error('audit run security requires a valid .atlas/review-policy.json: ' +
            policyLoad.diagnostics.map((diagnostic) => diagnostic.message).join('; '));
    }
    return { policy: policyLoad.policy, policyHash: policyLoad.policyHash };
}
function reviewablePaths(classification) {
    return new Map(classification.files.map((file) => [
        file.path,
        { deleted: file.deleted, currentBlob: file.currentBlob },
    ]));
}
function securityUnitOf(file) {
    return file.classification.kind === 'review'
        ? file.classification.domains.security?.unit
        : undefined;
}
function selectRunTargets(root, selection) {
    const { policy, policyHash } = loadRunPolicy(root);
    const inventory = readAuditTrackedInventory(root);
    if (inventory.diagnostics.length > 0) {
        throw new Error('audit run security requires a readable tracked inventory: ' +
            inventory.diagnostics.map((diagnostic) => diagnostic.message).join('; '));
    }
    const classification = classifyAuditInventory(inventory.files, policy);
    if (classification.diagnostics.length > 0) {
        throw new Error('audit run security requires an unambiguous policy classification: ' +
            classification.diagnostics.map((diagnostic) => diagnostic.message).join('; '));
    }
    const reviewable = reviewablePaths(classification);
    const isReviewable = (repoPath) => {
        const file = reviewable.get(repoPath);
        return file !== undefined && !file.deleted && file.currentBlob !== null;
    };
    // Publication rebuilds a unit ledger's `current` from the files a run actually
    // reviewed, and freshness reads `current` alone. A unit is therefore the
    // smallest thing that can be refreshed: reviewing a subset republishes a scope
    // covering only that subset and silently drops the standing receipts for the
    // rest of the unit. Selecting whole units is what makes that impossible.
    const targetsForUnits = (slugs) => {
        const wanted = new Set(slugs);
        const targets = [];
        for (const file of classification.files) {
            const slug = securityUnitOf(file);
            if (slug !== undefined && wanted.has(slug) && isReviewable(file.path)) {
                targets.push({ path: file.path, role: 'review' });
            }
        }
        const chosen = new Set(targets.map((target) => target.path));
        const contextGlobs = policy.units
            .filter((unit) => unit.domain === 'security' && wanted.has(unit.slug))
            .flatMap((unit) => unit.context);
        if (contextGlobs.length > 0) {
            const contextMatchers = contextGlobs.map((glob) => picomatch(glob, { dot: true }));
            for (const file of classification.files) {
                if (!isReviewable(file.path))
                    continue;
                if (chosen.has(file.path))
                    continue;
                if (contextMatchers.some((match) => match(file.path))) {
                    targets.push({ path: file.path, role: 'context' });
                    chosen.add(file.path);
                }
            }
        }
        return targets;
    };
    if (selection.kind === 'unit') {
        const unit = policy.units.find((candidate) => candidate.domain === 'security' && candidate.slug === selection.slug);
        if (unit === undefined) {
            const known = policy.units
                .filter((candidate) => candidate.domain === 'security')
                .map((candidate) => candidate.slug);
            throw new Error(`unknown security unit: ${selection.slug}` +
                (known.length > 0 ? ` (policy units: ${known.join(', ')})` : ''));
        }
        const targets = targetsForUnits([unit.slug]);
        if (!targets.some((target) => target.role === 'review')) {
            throw new Error(`security unit ${unit.slug} selects no tracked review files`);
        }
        return targets;
    }
    if (selection.kind === 'all') {
        const targets = classification.files
            .filter((file) => securityUnitOf(file) !== undefined && isReviewable(file.path))
            .map((file) => ({ path: file.path, role: 'review' }));
        if (targets.length === 0) {
            throw new Error('no tracked files are classified into a security review unit');
        }
        return targets;
    }
    // --stale (also the default): files whose exact security evidence is not fresh.
    const exactEvidence = loadAuditExactEvidence(root);
    if (exactEvidence.invalidLedgers.length > 0) {
        throw new Error('audit run security requires valid exact evidence ledgers: ' +
            exactEvidence.invalidLedgers.map((diagnostic) => diagnostic.message).join('; '));
    }
    const report = buildAuditCoverageReport({
        policy,
        policyHash,
        inventory,
        classification,
        exactEvidence,
    });
    if (report.verdict === 'invalid') {
        throw new Error('audit run security refuses to select stale targets from invalid coverage inputs: ' +
            report.reportErrors.map((diagnostic) => diagnostic.message).join('; '));
    }
    const staleUnits = new Set();
    for (const entry of report.entries) {
        if (entry.classification.kind !== 'review')
            continue;
        const slug = entry.classification.domains.security?.unit;
        if (slug === undefined)
            continue;
        if (entry.evidence.security?.status === 'fresh')
            continue;
        if (!isReviewable(entry.path))
            continue;
        staleUnits.add(slug);
    }
    if (staleUnits.size === 0) {
        throw new Error('no stale security evidence — every classified file has a fresh exact receipt ' +
            '(pass --unit <slug> or --all to run anyway)');
    }
    return targetsForUnits([...staleUnits].sort());
}
async function auditRun(root, args) {
    const [kind, ...rest] = args;
    if (kind !== 'security') {
        usage(USAGE_RUN, kind === undefined
            ? 'audit run requires a kind (security)'
            : `unknown audit run kind: ${kind}`);
    }
    const parsed = parseAuditArgs(rest, {
        values: ['--provider', '--unit', '--resume'],
        flags: ['--all', '--stale', '--reuse-unchanged'],
    }, USAGE_RUN);
    rejectPositionals(parsed, USAGE_RUN);
    const provider = parsed.values.get('--provider');
    if (provider !== 'grok') {
        usage(USAGE_RUN, provider === undefined
            ? '--provider grok is required'
            : `unknown provider: ${provider}`);
    }
    const selections = [
        parsed.values.has('--unit') ? '--unit' : null,
        parsed.flags.has('--all') ? '--all' : null,
        parsed.flags.has('--stale') ? '--stale' : null,
    ].filter((entry) => entry !== null);
    if (selections.length > 1) {
        usage(USAGE_RUN, 'target selection flags --unit, --all, and --stale are mutually exclusive');
    }
    const selection = parsed.values.has('--unit')
        ? { kind: 'unit', slug: parsed.values.get('--unit') }
        : parsed.flags.has('--all')
            ? { kind: 'all' }
            : { kind: 'stale' };
    const targets = selectRunTargets(root, selection);
    let policy;
    try {
        policy = resolveAuditProviderPolicy(loadAuditProviderPolicy(root) ?? {});
    }
    catch (error) {
        if (error instanceof AuditProviderError && error.code === 'policy-invalid') {
            throw new Error('audit run security requires an explicit provider policy at ' +
                `.atlas/audit-providers.json: ${error.message}`);
        }
        throw error;
    }
    const request = {
        command: AUDIT_PROVIDER_INVOCATION_COMMAND,
        provider: 'grok',
        repoRoot: root,
        policy,
        targets,
        ...(parsed.values.has('--resume')
            ? { resumeInvocationId: parsed.values.get('--resume') }
            : {}),
        // Reuse is opt-in, like --resume: a bare `audit run security` re-reviews
        // every file it selects, so asking for a review can never quietly return a
        // receipt somebody else's run earned.
        ...(parsed.flags.has('--reuse-unchanged') ? { reuseUnchangedReceipts: true } : {}),
    };
    const result = await runAuditProviderInvocation(request, createGrokAuditProvider());
    const publication = publishAuditProviderRunObservations(root, {
        result,
        targets,
    });
    const findings = result.files.filter((file) => file.outcome === 'findings').length;
    console.log(`audit run security: completed`);
    console.log(`  invocation: ${result.invocationId}`);
    if (result.resumedFromInvocationId !== undefined) {
        console.log(`  resumed from: ${result.resumedFromInvocationId}`);
    }
    console.log(`  files: ${result.files.length} reviewed (${result.files.length - findings} clean · ${findings} with findings)`);
    console.log(`  findings: ${result.findings.length}`);
    console.log(`  chunks: ${result.executedChunks.length} executed · ${result.reusedChunks.length} reused`);
    if (result.carriedReceipts.length > 0) {
        const sources = [...new Set(result.carriedReceipts.map((carried) => carried.observationId))];
        console.log(`  carried receipts: ${result.carriedReceipts.length} file(s) not re-reviewed ` +
            `(from ${sources.sort().join(', ')})`);
    }
    for (const unit of publication.units) {
        console.log(`  published ${unit.slug}: ${unit.status} (${unit.observationId}` +
            (unit.findings > 0 ? ` · ${unit.findings} finding(s)` : '') +
            ')');
    }
    console.log(`  coverage: ${publication.coverage.current ? 'current' : 'incomplete (reported)'} · ` +
        `report ${publication.coverage.wrote ? 'updated' : 'already current'}`);
}
// ---------------------------------------------------------------------------
// audit import
// ---------------------------------------------------------------------------
function auditImport(root, args) {
    const [kind, ...rest] = args;
    if (kind === 'codex-security')
        return auditImportCodexSecurity(root, rest);
    if (kind === 'legacy-v1')
        return auditImportLegacyCommand(root, rest);
    usage(USAGE_IMPORT, kind === undefined
        ? 'audit import requires a source kind'
        : `unknown audit import kind: ${kind}`);
}
function auditImportCodexSecurity(root, args) {
    const parsed = parseAuditArgs(args, { values: ['--slug'], flags: ['--apply'] }, USAGE_IMPORT_CODEX);
    if (parsed.positionals.length !== 1) {
        usage(USAGE_IMPORT_CODEX, 'expected exactly one <scan-dir> positional');
    }
    const slug = requiredValue(parsed, '--slug', USAGE_IMPORT_CODEX);
    const apply = parsed.flags.has('--apply');
    const result = importCodexSecurityBundle(root, {
        bundlePath: path.resolve(parsed.positionals[0]),
        unitSlug: slug,
        apply,
    });
    console.log(`audit import codex-security: ${result.observation.observationId} · ` +
        `${result.observation.reviewState} · ${result.observation.findings.length} finding(s)`);
    if (result.publication !== undefined) {
        console.log(`  wrote ${result.publication.currentPath}`);
        console.log(`  appended ${result.publication.historyPath} (${result.publication.appendedObservationId})`);
    }
    else {
        console.log('  dry run — pass --apply to publish this observation');
    }
}
/** Shared implementation behind `audit import legacy-v1` and legacy `audit-import`. */
export function auditImportLegacyCommand(root, args) {
    const sources = args.filter((arg) => !arg.startsWith('--'));
    if (!sources.length)
        usage(USAGE_IMPORT_LEGACY, 'expected at least one <legacy-ledger.json>');
    for (const source of sources) {
        const imported = importLegacyAudit(root, source);
        console.log(`imported: ${imported.name} · ${imported.fileCount} files · ` +
            `${imported.findingCount} finding(s) → ${imported.file}`);
    }
}
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// audit decision set / reconcile / retire
// ---------------------------------------------------------------------------
function readDecisionEventFile(parsed, usageText) {
    const file = parsed.values.get('--event');
    if (file === undefined)
        usage(usageText, '--event <event.json> is required');
    const resolved = path.resolve(file);
    let raw;
    try {
        const stat = fs.lstatSync(resolved);
        if (stat.isSymbolicLink() || !stat.isFile()) {
            throw new Error('event file is not a safe regular file');
        }
        if (stat.size > EVENT_FILE_BYTE_LIMIT) {
            throw new Error(`event file exceeds the ${EVENT_FILE_BYTE_LIMIT}-byte limit`);
        }
        raw = fs.readFileSync(resolved, 'utf8');
    }
    catch (error) {
        throw new Error(`cannot read decision event file ${file}: ${errorMessage(error)}`);
    }
    let value;
    try {
        value = JSON.parse(raw);
    }
    catch {
        throw new Error(`decision event file ${file} is not valid JSON`);
    }
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(`decision event file ${file} must contain a JSON object`);
    }
    return value;
}
function auditDecision(root, args) {
    const [verb, ...rest] = args;
    if (verb !== 'set') {
        usage(USAGE_DECISION_SET, verb === undefined
            ? 'audit decision requires a verb (set)'
            : `unknown audit decision verb: ${verb}`);
    }
    return auditDecisionSet(root, rest);
}
function decisionLedgerForFinding(root, event) {
    const observations = loadAuditObservations(root);
    const histories = loadAuditObservationHistory(root);
    const decisions = loadAuditDecisionLedgers(root);
    const diagnostics = [
        ...observations.diagnostics,
        ...histories.diagnostics,
        ...decisions.diagnostics,
    ];
    if (diagnostics.length > 0) {
        throw new Error('audit state is invalid; run `repo-atlas audit check` and resolve diagnostics first: ' +
            diagnostics.slice(0, 3).map((diagnostic) => diagnostic.message).join('; '));
    }
    const index = buildAuditDecisionIndex(observations.observations, histories.histories, decisions.ledgers);
    const findingId = event.findingId;
    const occurrenceId = event.occurrenceId;
    if (typeof findingId !== 'string' || typeof occurrenceId !== 'string') {
        throw new Error('the event must name its findingId and occurrenceId');
    }
    const finding = index.findings.get(findingId);
    if (finding === undefined)
        throw new Error(`unknown finding: ${findingId}`);
    const occurrence = index.occurrences.get(occurrenceId);
    if (occurrence === undefined)
        throw new Error(`unknown occurrence: ${occurrenceId}`);
    if (occurrence.findingId !== findingId) {
        throw new Error('the event occurrence does not belong to the event finding');
    }
    return finding.decisionLedger;
}
function auditDecisionSet(root, args) {
    const parsed = parseAuditArgs(args, { values: ['--event'], flags: [] }, USAGE_DECISION_SET);
    if (parsed.positionals.length !== 2) {
        usage(USAGE_DECISION_SET, 'expected <finding-or-occurrence> <action>');
    }
    const [target, action] = parsed.positionals;
    if (!AUDIT_FINDING_ACTIONS.has(action)) {
        usage(USAGE_DECISION_SET, `unknown action: ${action}`);
    }
    const raw = readDecisionEventFile(parsed, USAGE_DECISION_SET);
    if (raw.type !== 'finding-disposition') {
        throw new Error(`audit decision set accepts a finding-disposition event; got ${String(raw.type)}`);
    }
    const event = raw;
    if (event.action !== action) {
        throw new Error(`positional action ${action} does not match the event action ${event.action}`);
    }
    if (event.findingId !== target && event.occurrenceId !== target) {
        throw new Error(`positional target ${target} matches neither the event findingId nor occurrenceId`);
    }
    const slug = decisionLedgerForFinding(root, event);
    if ('decisionLedger' in event && event.decisionLedger !== slug) {
        throw new Error('the event decisionLedger does not match the finding home ledger');
    }
    const result = appendAuditDecision(root, slug, event);
    console.log(`audit decision set: ${result.status} ${result.eventId} → ${result.path}`);
}
function auditReconcile(root, args) {
    const parsed = parseAuditArgs(args, { values: ['--event'], flags: [] }, USAGE_RECONCILE);
    if (parsed.positionals.length !== 2) {
        usage(USAGE_RECONCILE, 'expected <before> <after>');
    }
    const [before, after] = parsed.positionals;
    const raw = readDecisionEventFile(parsed, USAGE_RECONCILE);
    if (raw.type !== 'finding-reconciliation') {
        throw new Error('audit reconcile appends a finding-reconciliation event ' +
            `(identity-alias reconciliations are produced by migrations); got ${String(raw.type)}`);
    }
    const event = raw;
    if (event.beforeOccurrenceIds.length !== 1 ||
        event.afterOccurrenceIds.length !== 1 ||
        event.beforeOccurrenceIds[0] !== before ||
        event.afterOccurrenceIds[0] !== after) {
        throw new Error('positional <before> <after> must equal the event before/after occurrence sets');
    }
    const result = appendAuditDecision(root, event.decisionLedger, event);
    console.log(`audit reconcile: ${result.status} ${result.eventId} → ${result.path}`);
}
function findStagedDeletion(root, slug, eventId) {
    const portfolio = loadAuditDecisionLedgers(root);
    if (portfolio.diagnostics.length > 0) {
        throw new Error('decision portfolio is invalid: ' +
            portfolio.diagnostics.slice(0, 3).map((diagnostic) => diagnostic.message).join('; '));
    }
    const entry = portfolio.ledgers
        .find((ledger) => ledger.slug === slug)
        ?.entries.find((candidate) => candidate.eventId === eventId);
    const event = entry?.event;
    if (event?.type === 'scope-retirement' && event.reason === 'staged-deletion') {
        return event;
    }
    return null;
}
function auditRetire(root, args) {
    const parsed = parseAuditArgs(args, { values: ['--event'], flags: ['--finalize-staged'] }, USAGE_RETIRE);
    const finalize = parsed.flags.has('--finalize-staged');
    if (finalize && parsed.positionals.length > 0) {
        usage(USAGE_RETIRE, '<path> and --finalize-staged are mutually exclusive');
    }
    if (!finalize && parsed.positionals.length !== 1) {
        usage(USAGE_RETIRE, 'expected <path> or --finalize-staged');
    }
    const raw = readDecisionEventFile(parsed, USAGE_RETIRE);
    if (raw.type !== 'scope-retirement') {
        throw new Error(`audit retire accepts a scope-retirement event; got ${String(raw.type)}`);
    }
    const event = raw;
    if (typeof event.decisionLedger !== 'string' || event.decisionLedger.length === 0) {
        throw new Error('the event must name its decisionLedger');
    }
    if (finalize) {
        if (event.reason === 'staged-deletion') {
            throw new Error('--finalize-staged requires a final reason (deleted, moved, or superseded), ' +
                'not another staged-deletion');
        }
        const supersedes = event.supersedesEventId;
        if (typeof supersedes !== 'string') {
            throw new Error('--finalize-staged requires the event to supersede a staged-deletion event');
        }
        const staged = findStagedDeletion(root, event.decisionLedger, supersedes);
        if (staged === null) {
            throw new Error(`no staged-deletion event ${supersedes} in ${event.decisionLedger} to finalize`);
        }
        if (staged.path !== event.path || staged.blob !== event.blob) {
            throw new Error('the finalized event must retire the same path/blob as its staged-deletion');
        }
    }
    else {
        const positional = normalizeAuditRepoPath(parsed.positionals[0]);
        if (event.path !== positional) {
            throw new Error(`positional path ${positional} does not match the event path ${event.path}`);
        }
    }
    const result = appendAuditDecision(root, event.decisionLedger, event);
    console.log(`audit retire: ${result.status} ${result.eventId} → ${result.path}`);
}
// ---------------------------------------------------------------------------
// audit stamp (shared with legacy `audit-stamp`)
// ---------------------------------------------------------------------------
/** Shared implementation behind `audit stamp` and legacy `audit-stamp`. */
export function auditStampCommand(root, args) {
    const names = args.filter((arg) => !arg.startsWith('--'));
    const { stamped, skipped, notFound } = stampAudits(root, scan(root, requireConfig(root)), names.length ? names : undefined);
    for (const name of stamped)
        console.log(`stamped: ${name}`);
    for (const refusal of skipped)
        console.error(`refused: ${refusal}`);
    for (const name of notFound)
        console.error(`refused: ${name}: audit ledger not found`);
    if (!stamped.length)
        console.log('no ledgers to stamp (check .atlas/audits/*.json)');
    if (skipped.length || notFound.length)
        process.exitCode = 1;
}
// ---------------------------------------------------------------------------
// audit localization (shared with the legacy flat aliases)
// ---------------------------------------------------------------------------
const AUDIT_LOCALES = new Set(['en', 'ja', 'zh', 'ko']);
function auditLocalizationContext(root, config) {
    const scanResult = scan(root, config);
    const status = computeStatus(root, scanResult, { readability: false });
    const portfolios = loadAuditPortfolios(root, status.audits);
    const reviewCoverage = loadReviewCoverage(root, portfolios);
    return { portfolios, reviewCoverage };
}
/** Shared implementation behind `audit localization input` and legacy `audit-localization-input`. */
export function auditLocalizationInputCommand(root, args) {
    const localeIndex = args.indexOf('--locale');
    const localeValue = localeIndex >= 0 ? args[localeIndex + 1] : undefined;
    const expectedLength = args.includes('--json') ? 3 : 2;
    if (localeIndex < 0 || localeIndex + 1 >= args.length || args.length !== expectedLength ||
        !localeValue || !AUDIT_LOCALES.has(localeValue)) {
        throw new Error('usage: repo-atlas audit-localization-input --locale <en|ja|zh|ko> [--json]');
    }
    const locale = localeValue;
    const config = requireConfig(root);
    const sourceLocale = config.auditSourceLocale ?? 'en';
    if (locale === sourceLocale) {
        throw new Error('audit localization target locale must differ from the canonical source locale');
    }
    const { portfolios, reviewCoverage } = auditLocalizationContext(root, config);
    const input = buildAuditLocalizationInput(sourceLocale, locale, reviewCoverage, portfolios);
    process.stdout.write(canonicalAuditLocalizationJson(input));
}
/** Shared implementation behind `audit localization check` and legacy `audit-localization-check`. */
export function auditLocalizationCheckCommand(root, args) {
    if (args.some((arg) => arg !== '--json') || args.filter((arg) => arg === '--json').length > 1) {
        throw new Error('usage: repo-atlas audit-localization-check [--json]');
    }
    const config = requireConfig(root);
    const { portfolios, reviewCoverage } = auditLocalizationContext(root, config);
    const loaded = loadConfiguredAuditLocalizations(root, config, reviewCoverage, portfolios);
    if (args.includes('--json')) {
        process.stdout.write(canonicalAuditLocalizationJson({
            sourceLocale: loaded.sourceLocale,
            locales: loaded.portfolios,
        }));
    }
    else if (Object.keys(loaded.portfolios).length === 0) {
        console.log('audit localizations: no required content locales configured');
    }
    else {
        for (const [locale, portfolio] of Object.entries(loaded.portfolios)) {
            console.log(`audit localization ${locale}: ${portfolio?.state ?? 'missing'}`);
            for (const error of portfolio?.errors ?? [])
                console.log(`  ${error.code}: ${error.message}`);
        }
    }
    if (Object.values(loaded.portfolios).some((portfolio) => portfolio?.state !== 'complete')) {
        process.exitCode = 1;
    }
}
function auditLocalization(root, args) {
    const [verb, ...rest] = args;
    if (verb === 'input')
        return auditLocalizationInputCommand(root, rest);
    if (verb === 'check')
        return auditLocalizationCheckCommand(root, rest);
    usage(USAGE_LOCALIZATION, verb === undefined
        ? 'audit localization requires a verb (input or check)'
        : `unknown audit localization verb: ${verb}`);
}
// ---------------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------------
/**
 * Hierarchical `repo-atlas audit ...` entry point. Only `audit run security`
 * may launch a provider process; every other verb is deterministic local I/O.
 */
export async function runAuditCommand(root, args) {
    const [verb, ...rest] = args;
    switch (verb) {
        case undefined:
        case 'help':
        case '--help':
        case '-h':
            console.log(AUDIT_USAGE);
            return;
        case 'check': return auditCheck(root, rest);
        case 'coverage': return auditCoverage(root, rest);
        case 'status': return auditStatus(root, rest);
        case 'run': return auditRun(root, rest);
        case 'import': return auditImport(root, rest);
        case 'decision': return auditDecision(root, rest);
        case 'reconcile': return auditReconcile(root, rest);
        case 'retire': return auditRetire(root, rest);
        case 'stamp': return auditStampCommand(root, rest);
        case 'localization': return auditLocalization(root, rest);
        default:
            usage(AUDIT_USAGE, `unknown audit verb: ${verb}`);
    }
}
