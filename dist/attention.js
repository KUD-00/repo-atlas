import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { git } from './scan.js';
const ATTENTION_FORMAT_VERSION = 1;
const ATTENTION_STATE_BYTES = 16 * 1024 * 1024;
const ATTENTION_CONCEPT_LIMIT = 100_000;
const ATTENTION_NOTE_LIMIT = 10_000;
const MAX_SLUG_LENGTH = 512;
const MAX_ID_LENGTH = 256;
const MAX_SNOOZE_MS = 365 * 24 * 60 * 60 * 1000;
export const ATTENTION_EVENT_LIMIT = 10_000;
const WORKFLOWS = new Set(['open', 'snoozed', 'done']);
const OUTCOMES = new Set(['acknowledged', 'understood', 'decided', 'not-relevant']);
const ACTIONS = new Set([...OUTCOMES, 'snooze', 'reopen']);
const EVENT_TYPES = new Set(['reviewed', 'snoozed', 'reopened', 'source-reopened']);
const SNAPSHOT_PATTERN = /^[a-f0-9]{64}$/;
function isRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function validTimestamp(value) {
    return typeof value === 'string' && value.length <= 64 && Number.isFinite(Date.parse(value));
}
function requireTimestamp(value, label) {
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed))
        throw new Error(`${label} must be a valid timestamp`);
    return parsed;
}
function cloneState(state) {
    const concepts = Object.create(null);
    for (const [slug, concept] of Object.entries(state.concepts))
        concepts[slug] = { ...concept };
    return {
        formatVersion: ATTENTION_FORMAT_VERSION,
        concepts,
        events: state.events.map((event) => ({ ...event })),
    };
}
function appendEvent(state, event) {
    if (state.events.length >= ATTENTION_EVENT_LIMIT) {
        throw new Error(`attention history capacity of ${ATTENTION_EVENT_LIMIT} events reached`);
    }
    state.events.push({ id: randomUUID(), ...event });
}
export function emptyAttentionState() {
    return {
        formatVersion: ATTENTION_FORMAT_VERSION,
        concepts: Object.create(null),
        events: [],
    };
}
/** Reconcile machine-observed source versions with human workflow. Freshness
 * can choose the initial state, but it never closes existing human work. */
export function reconcileAttention(input, concepts, now = new Date().toISOString()) {
    const nowMs = requireTimestamp(now, 'now');
    const state = cloneState(input);
    let changed = false;
    for (const concept of concepts) {
        const existing = Object.hasOwn(state.concepts, concept.slug)
            ? state.concepts[concept.slug]
            : undefined;
        if (!existing) {
            state.concepts[concept.slug] = {
                snapshot: concept.snapshot,
                workflow: concept.status === 'fresh' ? 'done' : 'open',
                firstSeenAt: now,
            };
            changed = true;
            continue;
        }
        if (existing.snapshot !== concept.snapshot) {
            state.concepts[concept.slug] = {
                snapshot: concept.snapshot,
                workflow: 'open',
                firstSeenAt: now,
            };
            appendEvent(state, {
                slug: concept.slug,
                snapshot: concept.snapshot,
                type: 'source-reopened',
                at: now,
            });
            changed = true;
            continue;
        }
        if (existing.workflow === 'snoozed' &&
            (!existing.snoozedUntil || requireTimestamp(existing.snoozedUntil, 'snoozedUntil') <= nowMs)) {
            state.concepts[concept.slug] = {
                ...existing,
                workflow: 'open',
                snoozedUntil: undefined,
            };
            appendEvent(state, {
                slug: concept.slug,
                snapshot: concept.snapshot,
                type: 'reopened',
                at: now,
            });
            changed = true;
        }
    }
    return { state, changed };
}
function normalizedNote(request) {
    if (request.note === undefined)
        return undefined;
    if (typeof request.note !== 'string')
        throw new Error('attention note must be a string');
    if (request.note.length > ATTENTION_NOTE_LIMIT) {
        throw new Error('attention note exceeds the 10,000 code-unit limit');
    }
    const note = request.note.trim();
    return note || undefined;
}
/** Apply one explicit reader action. The current concept snapshot is supplied
 * by the caller so stale tabs cannot close a newer version. */
export function applyAttentionAction(input, concepts, request, now = new Date().toISOString()) {
    const nowMs = requireTimestamp(now, 'now');
    if (!request || typeof request !== 'object')
        throw new Error('attention action must be an object');
    if (typeof request.slug !== 'string' || request.slug.length === 0 || request.slug.length > MAX_SLUG_LENGTH) {
        throw new Error('attention action has an invalid concept slug');
    }
    const concept = concepts.find((candidate) => candidate.slug === request.slug);
    if (!concept)
        throw new Error(`unknown concept: ${request.slug}`);
    if (typeof request.snapshot !== 'string' || request.snapshot !== concept.snapshot) {
        throw new Error('attention action snapshot does not match the current concept snapshot');
    }
    if (!ACTIONS.has(request.action))
        throw new Error(`unsupported attention action: ${String(request.action)}`);
    const current = input.concepts[concept.slug];
    if (!current || current.snapshot !== concept.snapshot) {
        throw new Error('attention state is not reconciled to the current concept snapshot');
    }
    if (input.events.length >= ATTENTION_EVENT_LIMIT) {
        throw new Error(`attention history capacity of ${ATTENTION_EVENT_LIMIT} events reached`);
    }
    const note = normalizedNote(request);
    if ((request.action === 'understood' || request.action === 'decided') && !note) {
        throw new Error(`${request.action} requires a note explaining the understanding or decision`);
    }
    const state = cloneState(input);
    if (request.action === 'snooze') {
        if (typeof request.until !== 'string')
            throw new Error('snooze requires a future until timestamp');
        const untilMs = requireTimestamp(request.until, 'snooze until');
        if (untilMs <= nowMs)
            throw new Error('snooze until must be in the future');
        if (untilMs - nowMs > MAX_SNOOZE_MS)
            throw new Error('snooze cannot exceed 365 days');
        const until = new Date(untilMs).toISOString();
        state.concepts[concept.slug] = { ...current, workflow: 'snoozed', snoozedUntil: until };
        appendEvent(state, {
            slug: concept.slug,
            snapshot: concept.snapshot,
            type: 'snoozed',
            at: now,
            ...(note ? { note } : {}),
            until,
        });
        return state;
    }
    if (request.action === 'reopen') {
        state.concepts[concept.slug] = { ...current, workflow: 'open', snoozedUntil: undefined };
        appendEvent(state, {
            slug: concept.slug,
            snapshot: concept.snapshot,
            type: 'reopened',
            at: now,
            ...(note ? { note } : {}),
        });
        return state;
    }
    state.concepts[concept.slug] = {
        ...current,
        workflow: 'done',
        snoozedUntil: undefined,
        lastReviewedAt: now,
        lastOutcome: request.action,
    };
    appendEvent(state, {
        slug: concept.slug,
        snapshot: concept.snapshot,
        type: 'reviewed',
        at: now,
        outcome: request.action,
        ...(note ? { note } : {}),
    });
    return state;
}
export function attentionStatePath(root) {
    const raw = git(root, ['rev-parse', '--git-common-dir']).trim();
    const commonDirectory = path.isAbsolute(raw) ? path.normalize(raw) : path.resolve(root, raw);
    return path.join(commonDirectory, 'repo-atlas', 'attention-v1.json');
}
/** Best-effort mechanical evidence for a concept change. No prose is inferred:
 * the result is only paths Git can prove changed since the stamped anchor,
 * plus currently broken declared sources. */
export function conceptChangedPaths(root, concept) {
    const changed = new Set(concept.brokenSources);
    if (concept.sources.length === 0)
        return [...changed].sort();
    if (concept.anchor && /^[a-f0-9]{7,64}$/i.test(concept.anchor)) {
        try {
            const raw = git(root, [
                'diff', '--name-only', '--no-renames', '-z', concept.anchor, '--', ...concept.sources,
            ]);
            for (const entry of raw.split('\0'))
                if (entry)
                    changed.add(entry);
        }
        catch {
            // An expired/unavailable anchor leaves declared sources as the fallback evidence.
        }
    }
    try {
        const raw = git(root, ['ls-files', '--others', '--exclude-standard', '-z', '--', ...concept.sources]);
        for (const entry of raw.split('\0'))
            if (entry)
                changed.add(entry);
    }
    catch {
        // Static/uninitialized repositories may not have an index yet.
    }
    return [...changed].sort();
}
function parseConceptState(value) {
    if (!isRecord(value))
        return false;
    if (typeof value.snapshot !== 'string' || !SNAPSHOT_PATTERN.test(value.snapshot))
        return false;
    if (typeof value.workflow !== 'string' || !WORKFLOWS.has(value.workflow))
        return false;
    if (!validTimestamp(value.firstSeenAt))
        return false;
    if (value.snoozedUntil !== undefined && !validTimestamp(value.snoozedUntil))
        return false;
    if (value.lastReviewedAt !== undefined && !validTimestamp(value.lastReviewedAt))
        return false;
    if (value.lastOutcome !== undefined && (typeof value.lastOutcome !== 'string' || !OUTCOMES.has(value.lastOutcome)))
        return false;
    return true;
}
function parseEvent(value) {
    if (!isRecord(value))
        return false;
    if (typeof value.id !== 'string' || value.id.length === 0 || value.id.length > MAX_ID_LENGTH)
        return false;
    if (typeof value.slug !== 'string' || value.slug.length === 0 || value.slug.length > MAX_SLUG_LENGTH)
        return false;
    if (typeof value.snapshot !== 'string' || !SNAPSHOT_PATTERN.test(value.snapshot))
        return false;
    if (typeof value.type !== 'string' || !EVENT_TYPES.has(value.type))
        return false;
    if (!validTimestamp(value.at))
        return false;
    if (value.outcome !== undefined && (typeof value.outcome !== 'string' || !OUTCOMES.has(value.outcome)))
        return false;
    if (value.note !== undefined && (typeof value.note !== 'string' || value.note.length > ATTENTION_NOTE_LIMIT))
        return false;
    if (value.until !== undefined && !validTimestamp(value.until))
        return false;
    return true;
}
function parseState(value) {
    if (!isRecord(value) || value.formatVersion !== ATTENTION_FORMAT_VERSION)
        return null;
    if (!isRecord(value.concepts) || !Array.isArray(value.events))
        return null;
    const conceptEntries = Object.entries(value.concepts);
    if (conceptEntries.length > ATTENTION_CONCEPT_LIMIT || value.events.length > ATTENTION_EVENT_LIMIT)
        return null;
    for (const [slug, concept] of conceptEntries) {
        if (slug.length === 0 || slug.length > MAX_SLUG_LENGTH || !parseConceptState(concept))
            return null;
    }
    if (!value.events.every(parseEvent))
        return null;
    return value;
}
function diagnostic(code, message) {
    return { state: null, diagnostics: [{ code, message }] };
}
function safeStateDirectory(file, create) {
    const directory = path.dirname(file);
    const stat = fs.lstatSync(directory, { throwIfNoEntry: false });
    if (stat) {
        if (stat.isSymbolicLink() || !stat.isDirectory()) {
            throw new Error(`attention state directory is not a safe directory: ${directory}`);
        }
        return;
    }
    if (create)
        fs.mkdirSync(directory, { recursive: false, mode: 0o700 });
}
export function loadAttentionState(root) {
    const file = attentionStatePath(root);
    try {
        safeStateDirectory(file, false);
    }
    catch (error) {
        return diagnostic('unsafe-state-directory', error instanceof Error ? error.message : String(error));
    }
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (!stat)
        return { state: emptyAttentionState(), diagnostics: [] };
    if (stat.isSymbolicLink() || !stat.isFile()) {
        return diagnostic('unsafe-state-file', 'attention state must be a regular non-symlink file');
    }
    if (stat.size > ATTENTION_STATE_BYTES) {
        return diagnostic('state-too-large', `attention state exceeds ${ATTENTION_STATE_BYTES} bytes`);
    }
    let raw;
    try {
        const noFollow = fs.constants.O_NOFOLLOW ?? 0;
        const fd = fs.openSync(file, fs.constants.O_RDONLY | noFollow);
        try {
            const opened = fs.fstatSync(fd);
            if (!opened.isFile() || opened.size > ATTENTION_STATE_BYTES) {
                return diagnostic('unsafe-state-file', 'attention state changed while it was being opened');
            }
            const bounded = Buffer.alloc(Math.min(opened.size + 1, ATTENTION_STATE_BYTES + 1));
            let offset = 0;
            while (offset < bounded.length) {
                const read = fs.readSync(fd, bounded, offset, bounded.length - offset, null);
                if (read === 0)
                    break;
                offset += read;
            }
            if (offset > ATTENTION_STATE_BYTES) {
                return diagnostic('state-too-large', `attention state exceeds ${ATTENTION_STATE_BYTES} bytes`);
            }
            raw = bounded.subarray(0, offset).toString('utf8');
        }
        finally {
            fs.closeSync(fd);
        }
    }
    catch (error) {
        return diagnostic('unreadable-state', error instanceof Error ? error.message : String(error));
    }
    let decoded;
    try {
        decoded = JSON.parse(raw);
    }
    catch {
        return diagnostic('invalid-json', 'attention state is not valid JSON');
    }
    const state = parseState(decoded);
    if (!state)
        return diagnostic('invalid-state', 'attention state does not match formatVersion 1');
    return { state: cloneState(state), diagnostics: [] };
}
export function saveAttentionState(root, state) {
    if (!parseState(state))
        throw new Error('refusing to persist invalid attention state');
    const file = attentionStatePath(root);
    safeStateDirectory(file, true);
    const existing = fs.lstatSync(file, { throwIfNoEntry: false });
    if (existing) {
        if (existing.isSymbolicLink() || !existing.isFile()) {
            throw new Error('refusing to replace an unsafe attention state file');
        }
        const loaded = loadAttentionState(root);
        if (!loaded.state)
            throw new Error('refusing to overwrite an invalid attention state file');
    }
    const contents = `${JSON.stringify(state, null, 2)}\n`;
    if (Buffer.byteLength(contents) > ATTENTION_STATE_BYTES) {
        throw new Error(`attention state exceeds ${ATTENTION_STATE_BYTES} bytes`);
    }
    const temporary = path.join(path.dirname(file), `.attention-v1.json.tmp-${process.pid}-${randomUUID()}`);
    let fd = null;
    try {
        fd = fs.openSync(temporary, 'wx', 0o600);
        fs.writeFileSync(fd, contents, 'utf8');
        fs.fsyncSync(fd);
        fs.closeSync(fd);
        fd = null;
        fs.renameSync(temporary, file);
        try {
            const directoryFd = fs.openSync(path.dirname(file), fs.constants.O_RDONLY);
            try {
                fs.fsyncSync(directoryFd);
            }
            finally {
                fs.closeSync(directoryFd);
            }
        }
        catch {
            // Directory fsync is unavailable on some platforms. The file itself was
            // already fsynced before the atomic rename.
        }
    }
    catch (error) {
        if (fd !== null)
            fs.closeSync(fd);
        try {
            fs.unlinkSync(temporary);
        }
        catch {
            // The temporary may already have been renamed or never created.
        }
        throw error;
    }
}
/** Build the viewer projection without conflating source health with human
 * workflow. A static build gets a useful read-only initial projection; a live
 * build supplies the reconciled clone-local state. */
export function buildAttentionPayload(status, options = {}) {
    const now = options.now ?? new Date().toISOString();
    requireTimestamp(now, 'now');
    const mode = options.mode ?? 'static';
    const invalid = options.state === null;
    const sourceState = options.state ?? emptyAttentionState();
    const reconciled = reconcileAttention(sourceState, status.concepts, now).state;
    const changedPaths = options.changedPaths ?? {};
    const items = status.concepts.map((concept) => {
        const subject = reconciled.concepts[concept.slug];
        return {
            id: `concept:${concept.slug}:${concept.snapshot}`,
            slug: concept.slug,
            title: concept.title,
            audience: concept.audience,
            chapter: concept.chapter,
            conceptStatus: concept.status,
            workflow: subject.workflow,
            snapshot: concept.snapshot,
            sources: [...concept.sources],
            brokenSources: [...concept.brokenSources],
            changedPaths: [...(changedPaths[concept.slug] ?? [])],
            stamped: concept.stamped,
            anchor: concept.anchor,
            firstSeenAt: subject.firstSeenAt,
            ...(subject.snoozedUntil ? { snoozedUntil: subject.snoozedUntil } : {}),
            ...(subject.lastReviewedAt ? { lastReviewedAt: subject.lastReviewedAt } : {}),
            ...(subject.lastOutcome ? { lastOutcome: subject.lastOutcome } : {}),
        };
    });
    const rank = { open: 0, snoozed: 1, done: 2 };
    items.sort((left, right) => rank[left.workflow] - rank[right.workflow]);
    const documentEntries = status.entries.filter((entry) => entry.path !== '');
    const documents = {
        outdated: documentEntries.filter((entry) => entry.status === 'outdated').length,
        missing: documentEntries.filter((entry) => entry.status === 'missing').length,
        ignored: documentEntries.filter((entry) => entry.status === 'ignored').length,
        total: documentEntries.length,
    };
    const health = {
        documents,
        concepts: {
            fresh: status.concepts.filter((concept) => concept.status === 'fresh').length,
            outdated: status.concepts.filter((concept) => concept.status === 'outdated').length,
            brokenSource: status.concepts.filter((concept) => concept.status === 'broken-source').length,
            total: status.concepts.length,
        },
        brokenReferences: status.brokenRefs.length,
        orphans: status.orphans.length,
    };
    return {
        mode,
        state: invalid ? 'invalid' : 'ready',
        generatedAt: now,
        items,
        events: invalid ? [] : reconciled.events.map((event) => ({ ...event })),
        summary: {
            open: items.filter((item) => item.workflow === 'open').length,
            snoozed: items.filter((item) => item.workflow === 'snoozed').length,
            done: items.filter((item) => item.workflow === 'done').length,
            history: invalid ? 0 : reconciled.events.length,
        },
        health,
        diagnostics: (options.diagnostics ?? []).map((entry) => ({ ...entry })),
    };
}
