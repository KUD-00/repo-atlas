#!/usr/bin/env node
// Fake `grok` CLI used by test/audit-provider-grok.test.mjs.
//
// Contract double for the Repo Atlas Grok adapter (repo-atlas/grok-v1):
// - records every invocation (argv/env/cwd/stdin/prompt) into invocations/ next
//   to this script;
// - answers `--version`, `--help`, and `inspect --json` probes;
// - validates analysis-run argv against the real grok 0.2.82 (clap) option
//   contract: value-taking flags require a value, unknown flags are rejected,
//   and violations exit 2 with the real error shapes before any side effect;
// - for analysis runs, writes the session transcript at the real 0.2.82
//   location $HOME/.grok/sessions/<encodeURIComponent(--cwd)>/<session-id>/
//   chat_history.jsonl (XDG_DATA_HOME is ignored) in the real vocabulary
//   (system/user/reasoning ambient events, assistant messages with
//   JSON-string tool_call arguments, tool_result messages linked by
//   tool_call_id, one final assistant message), and emits bounded
//   streaming-json on stdout in the real grok 0.2.82 vocabulary
//   (thought chunks, ordered text chunks, one terminal end event; tool calls
//   never appear on stdout) whose concatenated text response is
//   byte-identical to the concatenated transcript assistant content.
//
// Behavior is steered by control.json written beside this script by the test.
// The script never touches the network.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const control = JSON.parse(fs.readFileSync(path.join(here, 'control.json'), 'utf8'))
// `flaky-review-once` reproduces the shape that made a large corpus
// unfinishable: one review unit emits output this run cannot validate, then the
// same unit succeeds when asked again. Only the first analysis run misbehaves,
// which is what distinguishes a retried transient from a deterministic fault.
let mode = control.mode ?? 'ok'
const FLAKY_ONCE = {
  'flaky-review-once': 'bad-transcript-coverage',
  'flaky-receipt-once': 'extra-receipt',
}
if (FLAKY_ONCE[mode] !== undefined) {
  const marker = path.join(here, 'flaky-fired')
  if (fs.existsSync(marker)) mode = 'ok'
  else {
    fs.writeFileSync(marker, '1')
    mode = FLAKY_ONCE[mode]
  }
}

const argv = process.argv.slice(2)
const invocationsDir = path.join(here, 'invocations')
fs.mkdirSync(invocationsDir, { recursive: true })
const sequence = fs.readdirSync(invocationsDir).filter((name) => name.endsWith('.json')).length
const record = {
  seq: sequence,
  argv,
  cwd: process.cwd(),
  env: { ...process.env },
  stdin: '',
}

function argValue(flag) {
  const index = argv.indexOf(flag)
  return index >= 0 ? argv[index + 1] : undefined
}

function finishRecord(extra) {
  // Concurrent bounded sub-reviews may observe the same sequence number; the
  // pid suffix keeps every process's record.
  fs.writeFileSync(
    path.join(invocationsDir, `${String(sequence).padStart(4, '0')}-${process.pid}.json`),
    JSON.stringify({ ...record, ...extra }),
  )
}

function timeline(mark, id) {
  fs.appendFileSync(path.join(here, 'timeline.log'), `${mark} ${id} ${Date.now()}\n`)
}

const HELP_FLAGS = [
  '--single',
  '--no-plan',
  '--permission-mode',
  '--tools',
  '--no-memory',
  '--no-subagents',
  '--disable-web-search',
  '--output-format',
  '--session-id',
  '--cwd',
  '--prompt-file',
  '--model',
]

// The pinned version the adapter accepts. A test overrides it to prove the
// preflight rejects any other build instead of parsing its output hopefully.
const CLI_VERSION = control.version ?? '0.2.111'

if (argv[0] === '--version') {
  finishRecord({ kind: 'version' })
  process.stdout.write(`grok ${CLI_VERSION}\n`)
  process.exit(0)
}

if (argv[0] === '--help') {
  finishRecord({ kind: 'help' })
  process.stdout.write(`grok CLI\n${HELP_FLAGS.join('\n')}\n`)
  process.exit(0)
}

if (argv[0] === 'inspect') {
  record.homeMode = (fs.statSync(process.env.HOME).mode & 0o777).toString(8)
  record.homeEntries = listHome(process.env.HOME)
  finishRecord({ kind: 'inspect' })
  const inspect = {
    version: CLI_VERSION,
    hooks: [],
    plugins: [],
    mcpServers: [],
    projectInstructions: [],
    permissionSources: ['default'],
    effectiveConfig: {},
    ...(control.inspect ?? {}),
  }
  process.stdout.write(`${JSON.stringify(inspect)}\n`)
  process.exit(0)
}

// ---------------------------------------------------------------------------
// Real-CLI argv contract (grok 0.2.82, clap). The fake emulates only the
// headless single-turn surface the adapter uses; anything outside it is a
// usage error: exit 2 with the real clap error shapes, recorded as a
// 'run-rejected' invocation, before any prompt read, transcript, or stdout
// event. `-p, --single <PROMPT>` notably REQUIRES a value — a bare `--single`
// is how the real binary rejected the original adapter argv.
// ---------------------------------------------------------------------------

// Long name -> value placeholder, mirroring `grok --help`. Short aliases map
// to their long name because clap reports the long name in its errors.
const VALUE_FLAGS = new Map([
  ['--single', '<PROMPT>'],
  ['--permission-mode', '<MODE>'],
  ['--tools', '<TOOLS>'],
  ['--output-format', '<OUTPUT_FORMAT>'],
  ['--model', '<MODEL>'],
  ['--session-id', '<SESSION_ID>'],
  ['--cwd', '<CWD>'],
  ['--prompt-file', '<PATH>'],
])
const SHORT_ALIASES = new Map([
  ['-p', '--single'],
  ['-m', '--model'],
  ['-s', '--session-id'],
])
const BOOLEAN_FLAGS = new Set([
  '--no-plan',
  '--no-memory',
  '--no-subagents',
  '--disable-web-search',
])

function usageError(message, tip) {
  finishRecord({ kind: 'run-rejected', error: message })
  let text = `error: ${message}\n`
  if (tip !== undefined) text += `\n  tip: ${tip}\n\nUsage: grok [OPTIONS] [PROMPT] [COMMAND]\n`
  text += `\nFor more information, try '--help'.\n`
  process.stderr.write(text)
  process.exit(2)
}

for (let index = 0; index < argv.length; index += 1) {
  let token = argv[index]
  if (!token.startsWith('-')) {
    // The double emulates headless single-turn runs only; it has no TUI and
    // therefore no positional-PROMPT entry point.
    usageError(
      `unexpected argument '${token}' found`,
      `to pass '${token}' as a value, use '-- ${token}'`,
    )
  }
  let inlineValue
  const equals = token.indexOf('=')
  if (token.startsWith('--') && equals >= 0) {
    inlineValue = token.slice(equals + 1)
    token = token.slice(0, equals)
  }
  const long = SHORT_ALIASES.get(token) ?? token
  if (BOOLEAN_FLAGS.has(long)) {
    if (inlineValue !== undefined) {
      usageError(`unexpected value '${inlineValue}' for '${long}' found`)
    }
    continue
  }
  const placeholder = VALUE_FLAGS.get(long)
  if (placeholder === undefined) {
    usageError(
      `unexpected argument '${token}' found`,
      `to pass '${token}' as a value, use '-- ${token}'`,
    )
  }
  if (inlineValue !== undefined) continue
  const next = argv[index + 1]
  if (next === undefined || next.startsWith('-')) {
    // Verbatim clap 0.2.82 shape, e.g.:
    // error: a value is required for '--single <PROMPT>' but none was supplied
    usageError(`a value is required for '${long} ${placeholder}' but none was supplied`)
  }
  index += 1
}

const sessionId = argValue('--session-id')
const snapshotCwd = argValue('--cwd')
const promptFile = argValue('--prompt-file')
const prompt = fs.readFileSync(promptFile, 'utf8')
record.kind = 'run'
record.prompt = prompt
record.homeMode = (fs.statSync(process.env.HOME).mode & 0o777).toString(8)
record.homeEntries = listHome(process.env.HOME)
timeline('S', sessionId)

function listHome(home) {
  const entries = []
  const walk = (dir, rel) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name
      const childPath = path.join(dir, entry.name)
      const stat = fs.statSync(childPath)
      if (entry.isDirectory()) {
        entries.push({ path: `${childRel}/`, mode: (stat.mode & 0o777).toString(8) })
        walk(childPath, childRel)
      } else {
        entries.push({
          path: childRel,
          mode: (stat.mode & 0o777).toString(8),
          size: stat.size,
        })
      }
    }
  }
  walk(home, '')
  return entries
}

function parseUnit() {
  const marker = prompt.lastIndexOf('ATLAS-UNIT')
  if (marker < 0) throw new Error('prompt is missing the ATLAS-UNIT block')
  return JSON.parse(prompt.slice(marker + 'ATLAS-UNIT'.length).trim())
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

const unit = parseUnit()
record.unit = { kind: unit.kind, unit: unit.unit }
record.snapshotFiles = unit.files.map((file) => {
  const stat = fs.statSync(path.join(snapshotCwd, ...file.path.split('/')))
  return { path: file.path, mode: (stat.mode & 0o777).toString(8) }
})

async function main() {
  if (mode === 'signal') {
    finishRecord({ phase: unit.kind })
    process.kill(process.pid, 'SIGKILL')
    await new Promise(() => {})
  }
  if (mode === 'exit-nonzero') {
    finishRecord({ phase: unit.kind })
    process.stderr.write('fake grok exploded\n')
    process.exit(3)
  }
  if (control.sleepMs) await sleep(control.sleepMs)

  if (mode === 'corrupt-snapshot') {
    const victim = path.join(snapshotCwd, ...unit.files[0].path.split('/'))
    fs.chmodSync(victim, 0o644)
    fs.appendFileSync(victim, '/* tampered by fake grok */\n')
  }

  // Real 0.2.82 transcript vocabulary: ambient system/user/reasoning events,
  // assistant messages whose tool_calls carry a JSON-string arguments
  // payload, tool_result messages linked by tool_call_id, and one final
  // assistant message (content, no tool calls) as the last event. The
  // concatenation of every assistant content is byte-identical to the stdout
  // text stream.
  const events = []
  events.push({ type: 'system', content: 'fake grok system prompt' })
  events.push({ type: 'user', content: [{ type: 'text', text: prompt }] })
  events.push({
    type: 'reasoning',
    id: 'rs_fake_1',
    summary: [{ type: 'summary_text', text: 'planning the bounded review' }],
    status: 'completed',
  })
  let callSequence = 0
  let firstRead = true
  const NARRATION = 'Reading the listed files.'
  const assistantTurn = (content, toolCalls) => {
    const event = {
      type: 'assistant',
      content,
      model_id: 'grok-4.5-build',
      model_fingerprint: 'fp_fake',
    }
    if (toolCalls.length > 0) event.tool_calls = toolCalls
    events.push(event)
  }
  // A read_file result prefixes the first returned line with `<start>→` and
  // every absolute decade line (10, 20, …) with its line number. The content
  // ends with the file's trailing newline when the range reaches EOF. ANY read
  // that reaches EOF additionally appends a phantom `<lines+1>→` anchor when
  // that number is a multiple of ten (verified live: a 129-line file ends with
  // "130→").
  //
  // This fixture used to gate the phantom on no-argument full reads, matching
  // the same false belief the consumer's interval proof held. Real grok emitted
  // it from a RANGED read of a 1719-line file (offset 1001, limit 800), and
  // because fake and proof agreed on the wrong rule, no test could catch it —
  // the failure surfaced only as a rejected live audit run.
  const readContent = (startLine, endLine, fileLines, emitEofPhantom) => {
    const lines = []
    for (let line = startLine; line <= endLine; line += 1) {
      const text = `fake source line ${line}`
      lines.push(line === startLine || line % 10 === 0 ? `${line}→${text}` : text)
    }
    if (fileLines === 0) return ''
    let content = lines.join('\n')
    if (endLine === fileLines) content += '\n'
    if (emitEofPhantom && endLine === fileLines && (fileLines + 1) % 10 === 0) {
      content += `${fileLines + 1}→`
    }
    return content
  }
  const nextCallId = () => {
    callSequence += 1
    return `call-00000000-0000-4000-8000-${String(callSequence).padStart(12, '0')}`
  }
  const readCall = (rel, startLine, endLine, fileLines) => {
    const id = nextCallId()
    // Whole-file single reads go without offset/limit, like the real model's
    // full reads of small files; ranged chunks carry explicit arguments.
    const wholeFileNoArgs = startLine === 1 && endLine === fileLines
    const args = { target_file: rel }
    if (!wholeFileNoArgs) {
      args.offset = startLine
      args.limit = endLine - startLine + 1
    }
    // The first read turn carries narration, like real mid-turn assistant
    // text; every assistant content joins the byte-equality check.
    assistantTurn(firstRead ? NARRATION : '', [
      { id, name: 'read_file', arguments: JSON.stringify(args) },
    ])
    firstRead = false
    let content = readContent(startLine, endLine, fileLines, mode !== 'bad-phantom')
    if (mode === 'bad-phantom' && wholeFileNoArgs) {
      // A fabricated phantom that is not the verified EOF decade shape must
      // stay unproven.
      content += `${fileLines + 2}→`
    }
    events.push({
      type: 'tool_result',
      tool_call_id: id,
      content,
    })
  }
  // Real grok refuses a whole-file read whose content exceeds its token cap and
  // tells the model to retry with offset and limit. The refusal carries no line
  // anchors, so it must not read as a fabricated result.
  const refusedReadCall = (rel, tokens) => {
    const id = nextCallId()
    assistantTurn(firstRead ? NARRATION : '', [
      { id, name: 'read_file', arguments: JSON.stringify({ target_file: rel }) },
    ])
    firstRead = false
    events.push({
      type: 'tool_result',
      tool_call_id: id,
      content:
        `File content (${tokens} tokens) exceeds maximum allowed tokens (25000 tokens).\n` +
        'Please use offset and limit parameters to read the file in chunks.',
    })
  }
  const readFully = (rel, lines) => {
    // A zero-line file still gets read once, and the result is empty — verified
    // against real grok on a `.gitkeep`. The loop below cannot express that, and
    // the fixture used to emit no read at all for such a file, so the interval
    // proof's inability to accept an empty result went untested until a real
    // repository with one empty tracked file could not be audited at all.
    if (lines === 0) {
      readCall(rel, 1, 0, 0)
      return
    }
    if (mode === 'token-cap-refusal' || mode === 'token-cap-only') {
      refusedReadCall(rel, 31136)
      // 'token-cap-only' stops here: the refusal is the whole proof attempt, so
      // the range must stay unproven and the run must fail.
      if (mode === 'token-cap-only') return
    }
    const chunk = 400
    for (let start = 1; start <= lines; start += chunk) {
      readCall(rel, start, Math.min(lines, start + chunk - 1), lines)
    }
  }

  if (mode !== 'zero-read') {
    for (const file of unit.files) {
      if (mode === 'bad-transcript-coverage') {
        readCall(file.path, 1, Math.max(1, Math.floor(file.lines / 2)), file.lines)
      } else {
        readFully(file.path, file.lines)
      }
    }
  }
  if (mode === 'bad-transcript-tool') {
    const id = nextCallId()
    assistantTurn('', [{ id, name: 'bash', arguments: JSON.stringify({ command: 'id' }) }])
    events.push({ type: 'tool_result', tool_call_id: id, content: 'uid=0(fake)' })
  }
  if (mode === 'bad-transcript-path') {
    const id = nextCallId()
    assistantTurn('', [
      { id, name: 'read_file', arguments: JSON.stringify({ target_file: '../../outside.txt', offset: 1, limit: 1 }) },
    ])
    events.push({ type: 'tool_result', tool_call_id: id, content: readContent(1, 1, 1, false) })
  }
  if (mode === 'tool-error') {
    const id = nextCallId()
    assistantTurn('', [{ id, name: 'grep', arguments: JSON.stringify({ pattern: 'x' }) }])
    events.push({
      type: 'tool_result',
      tool_call_id: id,
      content: 'Error: simulated tool error',
    })
  }
  if (mode === 'unsupported-event') {
    events.push({ type: 'teleport', target: 'elsewhere' })
  }

  const findingsByPath = control.reviewFindings ?? {}
  let payload
  if (unit.kind === 'review') {
    let files = unit.files
    if (mode === 'missing-receipt') files = files.slice(0, -1)
    const receipts = files.map((file) => {
      const findings = (findingsByPath[file.path] ?? []).map((finding) => ({ ...finding }))
      return {
        path: file.path,
        status: 'reviewed',
        // cleanWithFindings emulates the real model's evaluated-and-rejected
        // candidate list under a clean outcome.
        outcome:
          control.cleanWithFindings === true
            ? 'clean'
            : findings.length > 0
              ? 'findings'
              : 'clean',
        summary: findings.length > 0 ? 'findings recorded' : `checked ${file.path}`,
        findings,
      }
    })
    if (mode === 'extra-receipt') {
      receipts.push({
        path: 'src/unknown.ts',
        status: 'reviewed',
        outcome: 'clean',
        summary: 'phantom',
        findings: [],
      })
    }
    payload = { receipts }
  } else {
    payload = {
      dispositions: unit.candidates.map((candidate) => ({
        fingerprint: candidate.fingerprint,
        disposition: control.disposition ?? 'reportable',
        rationale: 'independent evidence trace reconstructed',
      })),
    }
  }

  let response = JSON.stringify(payload)
  if (mode === 'invalid-json') response = 'this is not json at all'

  let transcriptResponse = response
  if (mode === 'transcript-mismatch') {
    const altered = JSON.parse(response)
    altered.note = 'transcript disagrees with stdout'
    transcriptResponse = JSON.stringify(altered)
  }

  assistantTurn(transcriptResponse, [])
  if (mode === 'duplicate-result') {
    assistantTurn(transcriptResponse, [])
  }

  // The real CLI keeps sessions under $HOME/.grok (XDG_DATA_HOME is
  // ignored), grouped by the encodeURIComponent form of --cwd.
  const sessionDir = path.join(
    process.env.HOME,
    '.grok',
    'sessions',
    encodeURIComponent(snapshotCwd),
    sessionId,
  )
  record.transcriptPath = sessionDir
  if (mode !== 'no-transcript') {
    fs.mkdirSync(sessionDir, { recursive: true })
    fs.writeFileSync(
      path.join(sessionDir, 'chat_history.jsonl'),
      events.map((event) => JSON.stringify(event)).join('\n') + '\n',
    )
  }

  // Real 0.2.82 stdout vocabulary: reasoning streams as thought chunks, the
  // assistant text streams as ordered text chunks (narration first, then the
  // final response split in two so the adapter's concatenation is
  // exercised), and one terminal end event closes the turn. The concatenated
  // text is byte-identical to the concatenated transcript assistant content.
  // Tool calls never appear on stdout.
  const stdoutEvents = []
  stdoutEvents.push({ type: 'thought', data: 'planning the bounded review' })
  if (control.progressMarker) {
    stdoutEvents.push({ type: 'thought', data: control.progressMarker })
  }
  if (mode === 'stdout-error') {
    // The real CLI reports failures as an in-band error event (usually with a
    // nonzero exit); here the process exits 0 so the adapter's own fail-closed
    // error-event handling is what rejects the stream.
    stdoutEvents.push({
      type: 'error',
      message: "Couldn't set model 'grok-4.5': Invalid params: \"unknown model id\".",
    })
  } else {
    if (mode !== 'empty-response') {
      if (mode !== 'zero-read') stdoutEvents.push({ type: 'text', data: NARRATION })
      const midpoint = Math.ceil(response.length / 2)
      stdoutEvents.push({ type: 'text', data: response.slice(0, midpoint) })
      stdoutEvents.push({ type: 'text', data: response.slice(midpoint) })
    }
    if (mode !== 'no-terminal-end') {
      stdoutEvents.push({
        type: 'end',
        stopReason: mode === 'bad-stop-reason' ? 'MaxTokens' : 'EndTurn',
        sessionId: mode === 'bad-session-id' ? 'ffffffff-ffff-4fff-8fff-ffffffffffff' : sessionId,
        requestId: '00000000-1111-4222-8333-444444444444',
      })
    }
    if (mode === 'events-after-end') {
      stdoutEvents.push({ type: 'text', data: '{"late":true}' })
    }
  }
  for (const event of stdoutEvents) process.stdout.write(`${JSON.stringify(event)}\n`)
  finishRecord({ phase: unit.kind })
  timeline('E', sessionId)
}

await main()
