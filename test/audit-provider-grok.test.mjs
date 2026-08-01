import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url))
const PACKAGE_ROOT = path.dirname(TEST_DIR)
const FAKE_GROK_SOURCE = path.join(TEST_DIR, 'fixtures', 'fake-grok', 'grok.mjs')

const providers = await import('../dist/audit-providers.js').catch((error) => {
  assert.fail(
    `Task 7 provider orchestration API is missing: ${
      error instanceof Error ? error.message : String(error)
    }`,
  )
})
const grok = await import('../dist/audit-provider-grok.js').catch((error) => {
  assert.fail(
    `Task 7 Grok adapter API is missing: ${
      error instanceof Error ? error.message : String(error)
    }`,
  )
})
const core = await import('../dist/audit-core.js')

const {
  AuditProviderError,
  loadAuditProviderPolicy,
  resolveAuditProviderPolicy,
  runAuditProviderInvocation,
} = providers
const { createGrokAuditProvider } = grok
const { canonicalJson } = core

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function sha256Tagged(value) {
  return `sha256:${sha256(value)}`
}

function makeSource(lines, label) {
  const body = []
  for (let index = 1; index <= lines; index += 1) {
    body.push(`export const ${label}_${index} = ${index}`)
  }
  return body.join('\n') + '\n'
}

function write(root, rel, contents) {
  const target = path.join(root, ...rel.split('/'))
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, contents)
}

function makeRepo(t, files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-provider-repo-'))
  for (const [rel, contents] of Object.entries(files)) write(root, rel, contents)
  t.after(() => fs.rmSync(root, { recursive: true, force: true }))
  return root
}

function makeFakeGrok(t, control) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-fake-grok-'))
  const binPath = path.join(dir, 'grok.mjs')
  fs.copyFileSync(FAKE_GROK_SOURCE, binPath)
  fs.chmodSync(binPath, 0o755)
  fs.writeFileSync(path.join(dir, 'control.json'), JSON.stringify(control))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const invocationsDir = path.join(dir, 'invocations')
  return {
    binPath,
    dir,
    invocations() {
      if (!fs.existsSync(invocationsDir)) return []
      return fs
        .readdirSync(invocationsDir)
        .filter((name) => name.endsWith('.json'))
        .sort()
        .map((name) => JSON.parse(fs.readFileSync(path.join(invocationsDir, name), 'utf8')))
    },
    timeline() {
      const file = path.join(dir, 'timeline.log')
      if (!fs.existsSync(file)) return []
      return fs
        .readFileSync(file, 'utf8')
        .trim()
        .split('\n')
        .map((line) => {
          const [mark, id, at] = line.split(' ')
          return { mark, id, at: Number(at) }
        })
    },
  }
}

function makePolicy(fake, overrides = {}) {
  return resolveAuditProviderPolicy({
    command: fake.binPath,
    model: 'grok-4.5',
    concurrency: 2,
    maxBatchFiles: 1,
    timeoutMs: 10_000,
    ...overrides,
  })
}

function makeRequest(root, policy, targets, overrides = {}) {
  return {
    command: 'audit run security',
    provider: 'grok',
    repoRoot: root,
    policy,
    targets: targets.map((target) => ({ path: target })),
    ...overrides,
  }
}

function journalDir(root, invocationId) {
  return path.join(root, '.atlas', '.runtime', 'audit-runs', invocationId)
}

function listFiles(root) {
  const entries = []
  const walk = (dir, rel) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const childRel = rel ? `${rel}/${entry.name}` : entry.name
      if (entry.isDirectory()) walk(path.join(dir, entry.name), childRel)
      else entries.push(childRel)
    }
  }
  if (fs.existsSync(root)) walk(root, '')
  return entries
}

function chunkDigests(receipt) {
  return receipt.chunks.map((chunk) => {
    const { digest, ...rest } = chunk
    const recomputed = sha256Tagged(canonicalJson(rest))
    assert.equal(digest, recomputed, `chunk ${chunk.chunkId} digest must cover its canonical bytes`)
    return { chunkId: chunk.chunkId, digest }
  })
}

function assertReceiptChain(receipt) {
  const covered = chunkDigests(receipt)
  assert.equal(
    receipt.transcriptDigest,
    sha256Tagged(canonicalJson(covered)),
    'final receipt transcript digest must cover every phase chunk digest',
  )
  const { receiptDigest, ...rest } = receipt
  assert.equal(
    receiptDigest,
    sha256Tagged(canonicalJson(rest)),
    'receipt digest must cover the canonical receipt excluding only receiptDigest',
  )
}

const AMBIENT_ENV_KEYS = ['HOME', 'LANG', 'LC_ALL', 'LC_CTYPE', 'TZ']

async function withControlledEnv(overrides, fn) {
  const saved = new Map()
  for (const key of [...AMBIENT_ENV_KEYS, 'GROK_API_KEY', 'ATLAS_TEST_AMBIENT_LEAK']) {
    saved.set(key, process.env[key])
  }
  try {
    delete process.env.LC_ALL
    delete process.env.LC_CTYPE
    delete process.env.TZ
    delete process.env.GROK_API_KEY
    delete process.env.ATLAS_TEST_AMBIENT_LEAK
    process.env.LANG = 'C.UTF-8'
    for (const [key, value] of Object.entries(overrides)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
    return await fn()
  } finally {
    for (const [key, value] of saved.entries()) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

test('the library entry rejects anything that is not an explicit audit run security request', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const policy = makePolicy(fake)
  const provider = createGrokAuditProvider()

  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        { ...makeRequest(root, policy, ['src/a.ts']), command: 'audit check' },
        provider,
      ),
    (error) => {
      assert.ok(error instanceof AuditProviderError)
      assert.equal(error.code, 'invalid-request')
      return true
    },
  )
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        { ...makeRequest(root, policy, ['src/a.ts']), command: 'audit status' },
        provider,
      ),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        { ...makeRequest(root, policy, ['src/a.ts']), provider: 'codex' },
        provider,
      ),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )

  let adapterCalled = false
  await assert.rejects(
    () =>
      runAuditProviderInvocation(makeRequest(root, policy, ['src/a.ts']), {
        name: 'other-provider',
        run: () => {
          adapterCalled = true
          return Promise.resolve({})
        },
      }),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )
  assert.equal(adapterCalled, false, 'a mismatched provider must never be started')

  await assert.rejects(
    () => runAuditProviderInvocation(makeRequest(root, policy, []), provider),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )
  await assert.rejects(
    () => runAuditProviderInvocation(makeRequest(root, policy, ['../escape.ts']), provider),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, policy, ['src/a.ts', 'src/a.ts']),
        provider,
      ),
    (error) => error instanceof AuditProviderError && error.code === 'invalid-request',
  )
  assert.throws(
    () => resolveAuditProviderPolicy({ command: fake.binPath, concurrency: 0 }),
    (error) => error instanceof AuditProviderError && error.code === 'policy-invalid',
  )
  assert.throws(
    () => resolveAuditProviderPolicy({ command: fake.binPath, model: 'grok-4.5', timeoutMs: 1 }),
    (error) => error instanceof AuditProviderError && error.code === 'policy-invalid',
  )
  assert.equal(fake.invocations().length, 0, 'rejected requests must never spawn grok')
})

test('repo-atlas init, status, build, and check never invoke grok', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const cliPath = path.join(PACKAGE_ROOT, 'dist', 'cli.js')
  const env = {
    ...process.env,
    PATH: `${fake.dir}${path.delimiter}${process.env.PATH}`,
  }
  for (const command of ['init', 'status', 'build', 'check']) {
    try {
      execFileSync(process.execPath, [cliPath, command], {
        cwd: root,
        env,
        stdio: ['ignore', 'pipe', 'pipe'],
        timeout: 60_000,
      })
    } catch {
      // A command may legitimately exit nonzero on a bare repository; it must
      // still never have executed the provider binary.
    }
  }
  assert.deepEqual(
    fake.invocations(),
    [],
    'check/status/build/init must run without any ambient provider call',
  )
})

test('an explicit run completes in an isolated environment with exact argv and a full receipt chain', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(9, 'b'),
    'src/c.ts': makeSource(12, 'c'),
  }
  const root = makeRepo(t, files)
  const policy = makePolicy(fake)
  const provider = createGrokAuditProvider()

  const result = await withControlledEnv(
    { ATLAS_TEST_AMBIENT_LEAK: 'must-not-leak' },
    () =>
      runAuditProviderInvocation(
        makeRequest(root, policy, Object.keys(files), {
          extraPrompt: 'Repository specific threat context.',
        }),
        provider,
      ),
  )

  assert.equal(result.status, 'completed')
  assert.match(result.invocationId, /^arun_[0-9a-f]{24}$/)
  assert.equal(result.files.length, 3)
  for (const file of result.files) {
    assert.equal(file.status, 'reviewed')
    assert.equal(file.outcome, 'clean')
    assert.match(file.blob, /^git-sha1:[0-9a-f]{40}$/)
  }
  assert.deepEqual(result.findings, [])

  const invocations = fake.invocations()
  assert.deepEqual(
    invocations.map((invocation) => invocation.kind),
    ['version', 'help', 'inspect', 'run', 'run', 'run'],
    'probes precede one bounded process per review batch',
  )

  const ambientHome = os.homedir()
  const [version, help, inspect, ...runs] = invocations
  assert.equal(version.env.HOME, ambientHome, 'binary version is recorded before the environment changes')
  assert.equal(help.env.HOME, ambientHome)
  const isolatedHome = inspect.env.HOME
  assert.ok(isolatedHome, 'inspect runs with an isolated HOME')
  assert.notEqual(isolatedHome, ambientHome)
  assert.ok(
    isolatedHome.startsWith(os.tmpdir()),
    'the isolated home is a temporary directory outside the repository',
  )
  assert.ok(!isolatedHome.startsWith(root))
  assert.equal(inspect.homeMode, '700', 'temporary home is mode 0700')

  const allowedIsolatedKeys = [
    'HOME',
    'LANG',
    'PATH',
    'TMPDIR',
    'XDG_CACHE_HOME',
    'XDG_CONFIG_HOME',
    'XDG_DATA_HOME',
    'XDG_STATE_HOME',
  ]
  for (const run of runs) {
    assert.equal(run.env.HOME, isolatedHome, 'every phase shares the isolated home')
    assert.equal(run.env.XDG_CONFIG_HOME, path.join(isolatedHome, 'config'))
    assert.equal(run.env.XDG_DATA_HOME, path.join(isolatedHome, 'data'))
    assert.equal(run.env.XDG_STATE_HOME, path.join(isolatedHome, 'state'))
    assert.equal(run.env.XDG_CACHE_HOME, path.join(isolatedHome, 'cache'))
    assert.deepEqual(
      Object.keys(run.env).sort(),
      allowedIsolatedKeys,
      'the child environment is an exact allowlist',
    )
    assert.equal(run.env.ATLAS_TEST_AMBIENT_LEAK, undefined)
    assert.equal(run.env.GROK_API_KEY, undefined)

    const sessionId = run.argv[run.argv.indexOf('--session-id') + 1]
    assert.match(sessionId, /^[0-9a-f-]{36}$/)
    const snapshotRoot = run.argv[run.argv.indexOf('--cwd') + 1]
    const promptFile = run.argv[run.argv.indexOf('--prompt-file') + 1]
    assert.deepEqual(
      run.argv,
      [
        '--no-plan',
        '--permission-mode',
        'dontAsk',
        '--tools',
        'Read,Grep,Glob',
        '--no-memory',
        '--no-subagents',
        '--disable-web-search',
        '--output-format',
        'streaming-json',
        '--model',
        'grok-4.5',
        '--session-id',
        sessionId,
        '--cwd',
        snapshotRoot,
        '--prompt-file',
        promptFile,
      ],
      'exact adapter argv with no dangerous flags',
    )
    assert.equal(run.cwd, snapshotRoot, 'grok runs against the snapshot, not the repository')
    assert.ok(!snapshotRoot.startsWith(root))
    for (const snapshotFile of run.snapshotFiles) {
      assert.equal(snapshotFile.mode, '444', 'snapshot files are read-only')
    }
    assert.match(run.prompt, /one receipt per (listed )?file/i)
    assert.match(run.prompt, /ATLAS-UNIT/)
    assert.match(run.prompt, /Repository specific threat context\./)
  }

  const receipt = result.receipt
  assert.equal(receipt.format, 'atlas-audit-provider-run/v1')
  assert.equal(receipt.provider, 'grok')
  assert.equal(receipt.adapter, 'repo-atlas/grok-v1')
  assert.equal(receipt.invocationId, result.invocationId)
  assert.equal(receipt.ruleset.id, 'atlas-security-v3')
  assert.equal(receipt.model, 'grok-4.5')
  assert.equal(receipt.prompt.builtinVersion, 'atlas-security-prompt-v1')
  assert.equal(receipt.prompt.extraPath, '.atlas/pipeline/security.extra.md')
  assert.match(receipt.prompt.extraDigest, /^sha256:[0-9a-f]{64}$/)
  assert.deepEqual(
    receipt.chunks.map((chunk) => chunk.phase),
    ['inventory', 'review', 'review', 'review', 'verification', 'synthesis'],
    'phase order is inventory, parallel bounded review, verification, synthesis',
  )
  assert.equal(receipt.chunks[0].processCount, 3, 'inventory chunk records the three probes')
  assert.equal(receipt.chunks.at(-2).processCount, 0, 'no candidates means no verification processes')
  assert.equal(receipt.chunks.at(-1).processCount, 0, 'synthesis is deterministic')
  assertReceiptChain(receipt)

  const journal = JSON.parse(
    fs.readFileSync(path.join(journalDir(root, result.invocationId), 'journal.json'), 'utf8'),
  )
  assert.equal(journal.status, 'completed')
  assert.ok(
    fs.existsSync(path.join(journalDir(root, result.invocationId), 'receipt.json')),
    'the final receipt is clone-local run state',
  )
  const atlasWrites = listFiles(path.join(root, '.atlas'))
  assert.ok(
    atlasWrites.every((entry) => entry.startsWith('.runtime/')),
    'nothing outside .atlas/.runtime is written',
  )
  for (const run of runs) {
    assert.ok(
      !fs.existsSync(run.argv[run.argv.indexOf('--cwd') + 1]),
      'the temporary snapshot is deleted after transcript validation',
    )
  }
})

test('the adapter never passes a bare --single, and the fake CLI enforces the real 0.2.82 option contract', async (t) => {
  // The adapter argv carries no `--single`/`-p`: in grok 0.2.82 that flag
  // requires an inline prompt value, and `--prompt-file` alone already
  // selects the single-turn headless mode.
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const result = await runAuditProviderInvocation(
    makeRequest(root, makePolicy(fake), ['src/a.ts']),
    createGrokAuditProvider(),
  )
  assert.equal(result.status, 'completed', 'the enforcing double accepts the corrected argv')
  const runs = fake.invocations().filter((invocation) => invocation.kind === 'run')
  assert.ok(runs.length > 0)
  for (const run of runs) {
    assert.ok(!run.argv.includes('--single'), 'argv must not contain --single')
    assert.ok(!run.argv.includes('-p'), 'argv must not contain -p')
    assert.ok(run.argv.includes('--prompt-file'), 'the prompt rides --prompt-file alone')
  }

  // Hand-crafted invocations that violate the real 0.2.82 contract fail
  // closed: exit 2 with the real clap error shape, no streaming stdout, no
  // session transcript, nothing published.
  const xdgData = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-fake-grok-xdg-'))
  t.after(() => fs.rmSync(xdgData, { recursive: true, force: true }))
  const promptPath = path.join(xdgData, 'prompt.md')
  fs.writeFileSync(promptPath, 'prompt')
  const runEnv = { PATH: process.env.PATH, HOME: xdgData, XDG_DATA_HOME: xdgData }
  const validTail = [
    '--no-plan',
    '--permission-mode',
    'dontAsk',
    '--tools',
    'Read,Grep,Glob',
    '--no-memory',
    '--no-subagents',
    '--disable-web-search',
    '--output-format',
    'streaming-json',
    '--model',
    'grok-4.5',
    '--session-id',
    '11111111-2222-3333-4444-555555555555',
    '--cwd',
    root,
    '--prompt-file',
    promptPath,
  ]

  const baselineRecords = fake.invocations().length
  const bareSingle = spawnSync(process.execPath, [fake.binPath, '--single', ...validTail], {
    env: runEnv,
    encoding: 'utf8',
  })
  assert.equal(bareSingle.status, 2)
  assert.match(
    bareSingle.stderr,
    /error: a value is required for '--single <PROMPT>' but none was supplied/,
    'the original adapter argv shape is rejected like the real binary rejects it',
  )
  assert.equal(bareSingle.stdout, '')

  const bareShort = spawnSync(process.execPath, [fake.binPath, '-p'], {
    env: runEnv,
    encoding: 'utf8',
  })
  assert.equal(bareShort.status, 2)
  assert.match(
    bareShort.stderr,
    /error: a value is required for '--single <PROMPT>' but none was supplied/,
  )

  const unknown = spawnSync(process.execPath, [fake.binPath, '--zzz-qqq', ...validTail], {
    env: runEnv,
    encoding: 'utf8',
  })
  assert.equal(unknown.status, 2)
  assert.match(unknown.stderr, /error: unexpected argument '--zzz-qqq' found/)
  assert.equal(unknown.stdout, '')

  // A real-but-dangerous flag the double does not emulate fails closed too.
  const dangerous = spawnSync(process.execPath, [fake.binPath, '--always-approve', ...validTail], {
    env: runEnv,
    encoding: 'utf8',
  })
  assert.equal(dangerous.status, 2)
  assert.match(dangerous.stderr, /error: unexpected argument '--always-approve' found/)

  // Rejected invocations leave no session tree and no output beyond their
  // rejection records.
  assert.ok(
    !fs.existsSync(path.join(xdgData, 'grok')),
    'a rejected invocation writes no transcript or session state',
  )
  const rejected = fake.invocations().slice(baselineRecords)
  assert.equal(rejected.length, 4)
  assert.ok(rejected.every((invocation) => invocation.kind === 'run-rejected'))
})

test('ambient hooks, plugins, MCP, and config stay out of the isolated home; only the auth record is copied', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'atlas-ambient-home-'))
  t.after(() => fs.rmSync(home, { recursive: true, force: true }))
  write(home, '.grok/auth.json', 'secret-auth-marker')
  fs.chmodSync(path.join(home, '.grok', 'auth.json'), 0o600)
  write(home, '.grok/config.json', '{"hooks":{"evil":"sh"}}')
  write(home, '.grok/hooks/evil.sh', 'echo pwned')
  write(home, '.grok/plugins/evil.js', 'module.exports = 1')
  write(home, '.grok/mcp.json', '{"servers":{"evil":{}}}')

  const policy = makePolicy(fake)
  const result = await withControlledEnv({ HOME: home }, () =>
    runAuditProviderInvocation(
      makeRequest(root, policy, ['src/a.ts']),
      createGrokAuditProvider(),
    ),
  )
  assert.equal(result.status, 'completed')

  const run = fake.invocations().find((invocation) => invocation.kind === 'run')
  const homeEntries = run.homeEntries.map((entry) => entry.path)
  assert.ok(homeEntries.includes('.grok/auth.json'), 'only the auth record is copied')
  for (const forbidden of ['.grok/config.json', '.grok/hooks/evil.sh', '.grok/plugins/evil.js', '.grok/mcp.json']) {
    assert.ok(!homeEntries.includes(forbidden), `${forbidden} must never be copied`)
  }
  const authEntry = run.homeEntries.find((entry) => entry.path === '.grok/auth.json')
  assert.equal(authEntry.mode, '600', 'the copied auth record is mode 0600')
  assert.equal(
    authEntry.size,
    'secret-auth-marker'.length,
    'the auth record bytes are copied exactly (recorded by size, never by content)',
  )

  const journalBytes = fs.readFileSync(
    path.join(journalDir(root, result.invocationId), 'journal.json'),
    'utf8',
  )
  const receiptBytes = fs.readFileSync(
    path.join(journalDir(root, result.invocationId), 'receipt.json'),
    'utf8',
  )
  for (const marker of ['secret-auth-marker', home]) {
    assert.ok(!journalBytes.includes(marker), 'journal must not contain credentials or home paths')
    assert.ok(!receiptBytes.includes(marker), 'receipt must not contain credentials or home paths')
  }
})

test('preflight rejects ambient hooks, plugins, MCP, project instructions, and unapproved effective config', async (t) => {
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const rejections = [
    { hooks: [{ command: 'evil' }] },
    { plugins: [{ path: '/evil' }] },
    { mcpServers: [{ name: 'evil' }] },
    { projectInstructions: ['do evil'] },
    { permissionSources: ['project-config'] },
    { effectiveConfig: { model: 'grok-9' } },
  ]
  for (const inspect of rejections) {
    const fake = makeFakeGrok(t, { mode: 'ok', inspect })
    await assert.rejects(
      () =>
        runAuditProviderInvocation(
          makeRequest(root, makePolicy(fake), ['src/a.ts']),
          createGrokAuditProvider(),
        ),
      (error) =>
        error instanceof AuditProviderError && error.code === 'preflight-rejected',
      `inspect drift ${JSON.stringify(inspect)} must be rejected`,
    )
  }

  const drifted = { effectiveConfig: { model: 'grok-9' } }
  const approved = makeFakeGrok(t, { mode: 'ok', inspect: drifted })
  const approvedDigest = sha256Tagged(canonicalJson(drifted.effectiveConfig))
  const result = await runAuditProviderInvocation(
    makeRequest(
      root,
      makePolicy(approved, { approvedConfigDigests: [approvedDigest] }),
      ['src/a.ts'],
    ),
    createGrokAuditProvider(),
  )
  assert.equal(result.status, 'completed')
  assert.equal(result.receipt.effectiveConfigDigest, approvedDigest)
})

test('review dispatches bounded parallel sub-reviews within the configured concurrency', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok', sleepMs: 250 })
  const files = Object.fromEntries(
    ['a', 'b', 'c', 'd', 'e', 'f'].map((name) => [`src/${name}.ts`, makeSource(5, name)]),
  )
  const root = makeRepo(t, files)
  const policy = makePolicy(fake, { concurrency: 2, maxBatchFiles: 1 })
  const result = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files)),
    createGrokAuditProvider(),
  )
  assert.equal(result.status, 'completed')
  assert.equal(result.receipt.chunks.filter((chunk) => chunk.phase === 'review').length, 6)

  const events = fake.timeline()
  const ends = new Map()
  let running = 0
  let maxRunning = 0
  for (const event of events) {
    if (event.mark === 'S') {
      running += 1
      maxRunning = Math.max(maxRunning, running)
    } else {
      running -= 1
      ends.set(event.id, true)
    }
  }
  assert.equal(maxRunning, 2, 'two workers run in parallel but never exceed the policy bound')
  assert.equal(events.filter((event) => event.mark === 'S').length, 6)
})

test('a per-process timeout kills grok and fails closed', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok', sleepMs: 30_000 })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const before = fs.readFileSync(path.join(root, 'src', 'a.ts'), 'utf8')
  let invocationId
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake, { timeoutMs: 250 }), ['src/a.ts']),
        createGrokAuditProvider(),
      ),
    (error) => {
      assert.ok(error instanceof AuditProviderError)
      assert.equal(error.code, 'timeout')
      return true
    },
  )
  const runsRoot = path.join(root, '.atlas', '.runtime', 'audit-runs')
  const entries = fs.existsSync(runsRoot) ? fs.readdirSync(runsRoot) : []
  assert.equal(entries.length, 1)
  invocationId = entries[0]
  const journal = JSON.parse(
    fs.readFileSync(path.join(journalDir(root, invocationId), 'journal.json'), 'utf8'),
  )
  assert.equal(journal.status, 'failed')
  assert.ok(
    !fs.existsSync(path.join(journalDir(root, invocationId), 'receipt.json')),
    'a timed-out run never publishes a receipt',
  )
  assert.equal(fs.readFileSync(path.join(root, 'src', 'a.ts'), 'utf8'), before)
})

test('invalid final JSON prevents publication', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'invalid-json' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake), ['src/a.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'output-invalid',
  )
})

test('a missing per-file receipt prevents publication', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'missing-receipt' })
  const root = makeRepo(t, {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(6, 'b'),
  })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake, { maxBatchFiles: 2 }), ['src/a.ts', 'src/b.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'missing-file-receipt',
  )
  const phantom = makeFakeGrok(t, { mode: 'extra-receipt' })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(phantom, { maxBatchFiles: 2 }), ['src/a.ts', 'src/b.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'missing-file-receipt',
  )
})

test('changed snapshot bytes prevent publication', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'corrupt-snapshot' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake), ['src/a.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'snapshot-mismatch',
  )
})

test('a signal-killed process prevents publication', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'signal' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake), ['src/a.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'signal',
  )
})

test('a stdout/transcript mismatch prevents publication', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'transcript-mismatch' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await assert.rejects(
    () =>
      runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake), ['src/a.ts']),
        createGrokAuditProvider(),
      ),
    (error) => error instanceof AuditProviderError && error.code === 'transcript-mismatch',
  )
})

test('transcript violations prevent publication', async (t) => {
  const cases = [
    ['no-transcript', 'a missing transcript'],
    ['zero-read', 'a zero-read response'],
    ['bad-transcript-coverage', 'partial line-range coverage'],
    ['bad-transcript-tool', 'a forbidden tool'],
    ['bad-transcript-path', 'a tool path outside the snapshot'],
    ['tool-error', 'a hidden tool error'],
    ['unsupported-event', 'an unsupported event'],
    ['duplicate-result', 'more than one terminal result'],
  ]
  for (const [mode, label] of cases) {
    const fake = makeFakeGrok(t, { mode })
    const root = makeRepo(t, { 'src/a.ts': makeSource(8, 'a') })
    await assert.rejects(
      () =>
        runAuditProviderInvocation(
          makeRequest(root, makePolicy(fake), ['src/a.ts']),
          createGrokAuditProvider(),
        ),
      (error) => error instanceof AuditProviderError && error.code === 'transcript-invalid',
      `${label} must remain a clone-local failed attempt`,
    )
    const atlasWrites = listFiles(path.join(root, '.atlas'))
    assert.ok(atlasWrites.every((entry) => entry.startsWith('.runtime/')))
  }
})

test('a nonzero exit prevents publication without leaking environment values', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'exit-nonzero' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await withControlledEnv({ GROK_API_KEY: 'sk-secret-marker' }, async () => {
    await assert.rejects(
      () =>
        runAuditProviderInvocation(
          makeRequest(root, makePolicy(fake, { apiKeyEnv: 'GROK_API_KEY' }), ['src/a.ts']),
          createGrokAuditProvider(),
        ),
      (error) => {
        assert.ok(error instanceof AuditProviderError)
        assert.equal(error.code, 'exit-code')
        assert.ok(!error.message.includes('sk-secret-marker'))
        return true
      },
    )
  })
})

test('an explicitly named API key passes through; other environment never does', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  await withControlledEnv(
    { GROK_API_KEY: 'sk-secret-marker', ATLAS_TEST_AMBIENT_LEAK: 'leak-marker' },
    async () => {
      const result = await runAuditProviderInvocation(
        makeRequest(root, makePolicy(fake, { apiKeyEnv: 'GROK_API_KEY' }), ['src/a.ts']),
        createGrokAuditProvider(),
      )
      assert.equal(result.status, 'completed')
    },
  )
  const run = fake.invocations().find((invocation) => invocation.kind === 'run')
  assert.equal(run.env.GROK_API_KEY, 'sk-secret-marker', 'the explicit key reaches grok')
  assert.equal(run.env.ATLAS_TEST_AMBIENT_LEAK, undefined)
  const runsRoot = path.join(root, '.atlas', '.runtime', 'audit-runs')
  const receiptBytes = fs.readFileSync(
    path.join(runsRoot, fs.readdirSync(runsRoot)[0], 'receipt.json'),
    'utf8',
  )
  assert.ok(!receiptBytes.includes('sk-secret-marker'))
})

test('findings flow through an independent verification phase with no discovery reasoning', async (t) => {
  const finding = {
    ruleId: 'injection-sql-cmd-path-ssrf/command-exec',
    title: 'unsanitized exec',
    severity: 'high',
    summary: 'user input reaches exec',
    startLine: 2,
    endLine: 3,
    detail: 'abuse path detail',
    fix: 'spawn with an argv array',
  }
  const fake = makeFakeGrok(t, {
    mode: 'ok',
    reviewFindings: { 'src/a.ts': [finding] },
    progressMarker: 'HIDDEN-REASONING-MARKER',
  })
  const root = makeRepo(t, {
    'src/a.ts': makeSource(8, 'a'),
    'src/b.ts': makeSource(8, 'b'),
  })
  const result = await runAuditProviderInvocation(
    makeRequest(root, makePolicy(fake), ['src/a.ts', 'src/b.ts']),
    createGrokAuditProvider(),
  )
  assert.equal(result.status, 'completed')
  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].disposition, 'reportable')
  assert.equal(result.findings[0].title, 'unsanitized exec')
  const fileA = result.files.find((file) => file.path === 'src/a.ts')
  assert.equal(fileA.outcome, 'findings')

  const reviewRuns = fake.invocations().filter((invocation) => invocation.phase === 'review')
  const verificationRuns = fake
    .invocations()
    .filter((invocation) => invocation.phase === 'verification')
  assert.equal(verificationRuns.length, 1, 'one bounded verification process for the candidate')
  assert.match(reviewRuns[0].prompt, /ATLAS-UNIT/)
  const verificationPrompt = verificationRuns[0].prompt
  assert.ok(
    !verificationPrompt.includes('HIDDEN-REASONING-MARKER'),
    'the fact checker never sees discovery reasoning',
  )
  assert.ok(!verificationPrompt.includes('abuse path detail'))
  assert.ok(verificationPrompt.includes(result.findings[0].fingerprint))
  assert.ok(verificationPrompt.includes(finding.ruleId))

  const verificationChunk = result.receipt.chunks.find((chunk) => chunk.phase === 'verification')
  assert.equal(verificationChunk.processCount, 1)
  assertReceiptChain(result.receipt)
})

test('resume reuses only verified outputs and reruns changed, corrupt, or missing work', async (t) => {
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(6, 'b'),
    'src/c.ts': makeSource(6, 'c'),
    'src/d.ts': makeSource(6, 'd'),
  }
  const root = makeRepo(t, files)
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const policy = makePolicy(fake, { maxBatchFiles: 1 })
  const provider = createGrokAuditProvider()

  const first = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files)),
    provider,
  )
  assert.equal(first.status, 'completed')
  const firstReviewChunks = first.receipt.chunks.filter((chunk) => chunk.phase === 'review')
  assert.equal(firstReviewChunks.length, 4)
  const baselineInvocations = fake.invocations().length
  assert.equal(baselineInvocations, 3 + 4, 'three probes plus four review processes')

  // A changed source invalidates only the batch that contains it.
  write(root, 'src/b.ts', makeSource(7, 'b2'))
  const second = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files), {
      resumeInvocationId: first.invocationId,
    }),
    provider,
  )
  assert.equal(second.status, 'completed')
  assert.notEqual(second.invocationId, first.invocationId)
  const secondInvocations = fake.invocations().length - baselineInvocations
  assert.equal(secondInvocations, 3 + 1, 'fresh probes plus one rerun review batch')
  assert.equal(
    second.receipt.chunks.filter((chunk) => chunk.phase === 'review').length,
    4,
    'the receipt still covers every review unit',
  )
  assert.equal(second.reusedChunks.length, 3)
  assertReceiptChain(second.receipt)

  // Corrupt journal work reruns instead of resuming.
  const thirdBaseline = fake.invocations().length
  const chunksDir = path.join(journalDir(root, second.invocationId), 'chunks')
  const chunkFiles = fs.readdirSync(chunksDir).filter((name) => name.endsWith('.json'))
  const reviewChunkFile = chunkFiles.find((name) => name.includes('review-0'))
  const corrupted = JSON.parse(fs.readFileSync(path.join(chunksDir, reviewChunkFile), 'utf8'))
  corrupted.output.receipts[0].summary = 'tampered journal output'
  fs.writeFileSync(path.join(chunksDir, reviewChunkFile), JSON.stringify(corrupted))
  const missingFile = chunkFiles.find((name) => name.includes('review-1'))
  fs.rmSync(path.join(chunksDir, missingFile))

  const third = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files), {
      resumeInvocationId: second.invocationId,
    }),
    provider,
  )
  assert.equal(third.status, 'completed')
  assert.equal(third.invocationId, second.invocationId, 'unchanged inputs derive the same run id')
  assert.equal(
    fake.invocations().length - thirdBaseline,
    3 + 2,
    'corrupt and missing chunks rerun; verified chunks are reused',
  )
  assert.equal(third.reusedChunks.length, 2)
  assertReceiptChain(third.receipt)

  // A changed prompt invalidates every content-addressed chunk.
  const fourthBaseline = fake.invocations().length
  const fourth = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files), {
      extraPrompt: 'Different repository context.',
      resumeInvocationId: third.invocationId,
    }),
    provider,
  )
  assert.equal(fourth.status, 'completed')
  assert.notEqual(fourth.invocationId, third.invocationId)
  assert.equal(
    fake.invocations().length - fourthBaseline,
    3 + 4,
    'a changed prompt digest invalidates all resumed work',
  )
  assert.equal(fourth.reusedChunks.length, 0)

  // No resume requested means no reuse even when inputs are identical.
  const fifthBaseline = fake.invocations().length
  const fifth = await runAuditProviderInvocation(
    makeRequest(root, policy, Object.keys(files), {
      extraPrompt: 'Different repository context.',
    }),
    provider,
  )
  assert.equal(fifth.status, 'completed')
  assert.equal(fifth.invocationId, fourth.invocationId)
  assert.equal(fake.invocations().length - fifthBaseline, 3 + 4)
  assert.equal(fifth.reusedChunks.length, 0)
})

test('original repository files are never modified, even when a run fails', async (t) => {
  const files = {
    'src/a.ts': makeSource(6, 'a'),
    'src/b.ts': makeSource(6, 'b'),
  }
  const root = makeRepo(t, files)
  const before = Object.fromEntries(
    Object.keys(files).map((rel) => [rel, sha256(fs.readFileSync(path.join(root, ...rel.split('/'))))]),
  )
  const ok = makeFakeGrok(t, { mode: 'ok' })
  await runAuditProviderInvocation(
    makeRequest(root, makePolicy(ok), Object.keys(files)),
    createGrokAuditProvider(),
  )
  const corrupt = makeFakeGrok(t, { mode: 'corrupt-snapshot' })
  await assert.rejects(() =>
    runAuditProviderInvocation(
      makeRequest(root, makePolicy(corrupt), Object.keys(files)),
      createGrokAuditProvider(),
    ),
  )
  for (const [rel, digest] of Object.entries(before)) {
    assert.equal(
      sha256(fs.readFileSync(path.join(root, ...rel.split('/')))),
      digest,
      `${rel} must be byte-identical after success and failure`,
    )
  }
})

test('clone-local run state lives only under .atlas/.runtime/audit-runs and is gitignored', async (t) => {
  const fake = makeFakeGrok(t, { mode: 'ok' })
  const root = makeRepo(t, { 'src/a.ts': makeSource(6, 'a') })
  const result = await runAuditProviderInvocation(
    makeRequest(root, makePolicy(fake), ['src/a.ts']),
    createGrokAuditProvider(),
  )
  const atlasFiles = listFiles(path.join(root, '.atlas'))
  assert.deepEqual(
    [...new Set(atlasFiles.map((entry) => entry.split('/')[0]))],
    ['.runtime'],
    'provider runs write no committed Atlas evidence',
  )
  assert.ok(
    atlasFiles.some((entry) =>
      entry.startsWith(`.runtime/audit-runs/${result.invocationId}/`),
    ),
  )
  const gitignore = fs.readFileSync(path.join(PACKAGE_ROOT, '.gitignore'), 'utf8')
  assert.match(
    gitignore,
    /^\.atlas\/\.runtime\/?$/m,
    '.atlas/.runtime must be ignored so run state never enters Git',
  )
})

test('loadAuditProviderPolicy parses .atlas/audit-providers.json strictly and tolerates its absence', async (t) => {
  const root = makeRepo(t, {})
  assert.equal(loadAuditProviderPolicy(root), null)
  write(
    root,
    '.atlas/audit-providers.json',
    JSON.stringify({
      formatVersion: 1,
      format: 'atlas-audit-providers/v1',
      provider: 'grok',
      model: 'grok-4.5',
      concurrency: 3,
      timeoutMs: 60_000,
      approvedConfigDigests: [sha256Tagged('x')],
    }),
  )
  const loaded = loadAuditProviderPolicy(root)
  assert.equal(loaded.model, 'grok-4.5')
  assert.equal(loaded.concurrency, 3)
  assert.equal(loaded.timeoutMs, 60_000)
  assert.deepEqual(loaded.approvedConfigDigests, [sha256Tagged('x')])

  write(root, '.atlas/audit-providers.json', '{"format":"other"}')
  assert.throws(
    () => loadAuditProviderPolicy(root),
    (error) => error instanceof AuditProviderError && error.code === 'policy-invalid',
  )
})
