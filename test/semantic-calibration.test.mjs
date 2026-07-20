import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { createSemanticManifest } from '../qa/readability/calibrate/semantic-manifest.mjs'

const ROOT = new URL('..', import.meta.url).pathname
const SCORE = path.join(ROOT, 'qa/readability/calibrate/semantic-score.mjs')
const RUN = path.join(ROOT, 'qa/readability/calibrate/semantic-run.sh')
const BUILD = path.join(ROOT, 'qa/readability/calibrate/semantic-build.mjs')
const SEMANTIC = path.join(ROOT, 'qa/readability/semantic.ts')
const RESULT = path.join(ROOT, 'qa/readability/calibrate/semantic-result.mjs')
const MANIFEST = path.join(ROOT, 'qa/readability/calibrate/semantic-manifest.mjs')
const WORKSPACE = path.join(ROOT, 'qa/readability/calibrate/semantic-workspace.mjs')

function prepareScoreFixture(out, files) {
  const repo = path.join(out, 'fixture')
  for (const [index, file] of files.entries()) {
    const target = path.join(repo, file)
    fs.mkdirSync(path.dirname(target), { recursive: true })
    fs.writeFileSync(target, `export const value${index} = ${index}\n`)
  }
  const manifest = createSemanticManifest(repo, files)
  fs.writeFileSync(path.join(out, 'files.json'), JSON.stringify(files))
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest))
  return manifest
}

function semanticResult(manifest, repoPath, values = {}) {
  return {
    formatVersion: 1,
    sampleHash: manifest.sampleHash,
    rows: [{
      path: repoPath,
      sourceHash: manifest.fileHashes[repoPath],
      naming: 5,
      commentCoherence: 5,
      antipatterns: [],
      barrel: false,
      reason: '',
      ...values,
    }],
  }
}

function prepareSemanticRun(root, calibrate, out) {
  fs.mkdirSync(path.join(root, 'src'), { recursive: true })
  fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const answer = 1\n')
  fs.copyFileSync(RESULT, path.join(calibrate, 'semantic-result.mjs'))
  fs.copyFileSync(MANIFEST, path.join(calibrate, 'semantic-manifest.mjs'))
  const files = ['src/a.ts']
  fs.writeFileSync(path.join(out, 'files.json'), JSON.stringify(files))
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(createSemanticManifest(root, files)))
}

test('semantic score calls zero-variance rank correlation undefined and reports exact agreement', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-score-'))
  try {
    const files = ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'e.ts']
    const manifest = prepareScoreFixture(out, files)
    for (const pass of ['pass1', 'pass2']) {
      fs.mkdirSync(path.join(out, pass))
      for (let i = 0; i < 5; i++) {
        const repoPath = files[i]
        fs.writeFileSync(path.join(out, pass, `${i}.json`), JSON.stringify(semanticResult(manifest, repoPath)))
      }
    }
    const run = spawnSync(process.execPath, [SCORE, '--out-dir', out], { encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    assert.match(run.stdout, /exact agreement.*100\.0%/)
    assert.match(run.stdout, /rho=n\/a.*zero variance/i)
  } finally {
    fs.rmSync(out, { recursive: true, force: true })
  }
})

test('semantic batch exits non-zero when the underlying evaluator fails', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-run-'))
  try {
    const calibrate = path.join(root, 'qa', 'readability', 'calibrate')
    const out = path.join(calibrate, '.work', 'semantic')
    const bin = path.join(root, 'bin')
    fs.mkdirSync(out, { recursive: true })
    fs.mkdirSync(bin)
    fs.copyFileSync(RUN, path.join(calibrate, 'semantic-run.sh'))
    prepareSemanticRun(root, calibrate, out)
    fs.writeFileSync(path.join(bin, 'bun'), '#!/bin/sh\necho evaluator exploded >&2\nexit 7\n', { mode: 0o755 })

    const run = spawnSync('bash', [path.join(calibrate, 'semantic-run.sh'), '1'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ATLAS_SEMANTIC_OUT: out },
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /evaluator exploded|semantic evaluation failed/i)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic batch rejects a nonempty evaluator error result', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-invalid-'))
  try {
    const calibrate = path.join(root, 'qa', 'readability', 'calibrate')
    const out = path.join(calibrate, '.work', 'semantic')
    const bin = path.join(root, 'bin')
    fs.mkdirSync(out, { recursive: true })
    fs.mkdirSync(bin)
    fs.copyFileSync(RUN, path.join(calibrate, 'semantic-run.sh'))
    prepareSemanticRun(root, calibrate, out)
    fs.writeFileSync(path.join(bin, 'bun'), `#!/bin/sh
while [ "$1" != "--out" ]; do shift; done
printf '%s\n' '{"rows":[{"path":"src/a.ts","naming":null,"commentCoherence":null,"antipatterns":[],"barrel":null,"reason":"","error":"parse failed"}]}' > "$2"
exit 0
`, { mode: 0o755 })

    const run = spawnSync('bash', [path.join(calibrate, 'semantic-run.sh'), '1'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ATLAS_SEMANTIC_OUT: out },
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /invalid semantic evaluation|parse failed/i)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic batch refuses checkpoints after sampled file bytes change', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-stale-'))
  try {
    const calibrate = path.join(root, 'qa', 'readability', 'calibrate')
    const out = path.join(calibrate, '.work', 'semantic')
    const bin = path.join(root, 'bin')
    fs.mkdirSync(out, { recursive: true })
    fs.mkdirSync(bin)
    fs.copyFileSync(RUN, path.join(calibrate, 'semantic-run.sh'))
    prepareSemanticRun(root, calibrate, out)
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const answer = 2\n')
    fs.writeFileSync(path.join(bin, 'bun'), '#!/bin/sh\nexit 0\n', { mode: 0o755 })

    const run = spawnSync('bash', [path.join(calibrate, 'semantic-run.sh'), '1'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, ATLAS_SEMANTIC_OUT: out },
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /sample paths or file bytes changed|manifest/i)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic calibration sampling never duplicates or exceeds the eligible population', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-build-'))
  try {
    const calibrate = path.join(root, 'calibrate')
    const repo = path.join(root, 'fixture')
    fs.mkdirSync(calibrate)
    fs.mkdirSync(path.join(repo, '.atlas'), { recursive: true })
    fs.copyFileSync(BUILD, path.join(calibrate, 'semantic-build.mjs'))
    fs.copyFileSync(MANIFEST, path.join(calibrate, 'semantic-manifest.mjs'))
    fs.copyFileSync(WORKSPACE, path.join(calibrate, 'semantic-workspace.mjs'))
    const files = Object.fromEntries(Array.from({ length: 5 }, (_, index) => [`src/file-${index}.ts`, {
      lang: 'ts',
      nonBlankLines: 40,
      commentRatio: index / 10,
      halsteadPerLine: 2 + index,
      lineLen: { mean: 30 + index },
      tokenEntropy: 3 + index / 10,
    }]))
    for (const repoPath of Object.keys(files)) {
      fs.mkdirSync(path.dirname(path.join(repo, repoPath)), { recursive: true })
      fs.writeFileSync(path.join(repo, repoPath), `export const value${repoPath.match(/\d+/)[0]} = 1\n`)
    }
    fs.writeFileSync(path.join(repo, '.atlas/readability.json'), JSON.stringify({
      format: 'repo-atlas-readability-v1',
      formatVersion: 1,
      files,
      norms: {
        commentRatio: { mean: 0.2, sd: 0.1 },
        halsteadPerLine: { mean: 4, sd: 1 },
        lineLenMean: { mean: 32, sd: 1 },
        tokenEntropy: { mean: 3.2, sd: 0.1 },
      },
    }))

    const run = spawnSync(process.execPath, [path.join(calibrate, 'semantic-build.mjs'), '--n', '18'], {
      cwd: repo,
      encoding: 'utf8',
    })
    assert.equal(run.status, 0, run.stderr)
    const repoWork = fs.readdirSync(path.join(calibrate, '.work', 'semantic'), { withFileTypes: true })
      .find((entry) => entry.isDirectory())
    assert.ok(repoWork)
    const pointer = JSON.parse(fs.readFileSync(path.join(calibrate, '.work', 'semantic', repoWork.name, 'current.json'), 'utf8'))
    const picks = JSON.parse(fs.readFileSync(path.join(calibrate, '.work', 'semantic', repoWork.name, pointer.sampleHash, 'files.json'), 'utf8'))
    assert.equal(picks.length, 5)
    assert.equal(new Set(picks).size, picks.length)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic evaluator rejects paths that resolve outside the target repository', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-path-'))
  try {
    const repo = path.join(parent, 'fixture')
    const bin = path.join(parent, 'bin')
    fs.mkdirSync(path.join(repo, '.atlas'), { recursive: true })
    fs.mkdirSync(bin)
    fs.writeFileSync(path.join(parent, 'secret.ts'), 'export const secret = "do not send"\n')
    const agent = path.join(bin, 'fake-agent')
    fs.writeFileSync(agent, `#!/bin/sh
printf '%s\n' '{"text":"{\\"naming\\":5,\\"commentCoherence\\":null,\\"antipatterns\\":[],\\"barrel\\":false,\\"reason\\":\\"ok\\"}"}'
`, { mode: 0o755 })

    const run = spawnSync('bun', [SEMANTIC, '../secret.ts'], {
      cwd: repo,
      encoding: 'utf8',
      env: { ...process.env, ATLAS_QA_AGENT: agent },
      timeout: 10_000,
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /outside|repository|仓库|路径/i)
  } finally {
    fs.rmSync(parent, { recursive: true, force: true })
  }
})

test('semantic evaluator rejects syntactically valid output from a nonzero agent exit', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-agent-exit-'))
  try {
    const bin = path.join(root, 'bin')
    fs.mkdirSync(path.join(root, '.atlas'), { recursive: true })
    fs.mkdirSync(path.join(root, 'src'))
    fs.mkdirSync(bin)
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const answer = 1\n')
    const agent = path.join(bin, 'fake-agent')
    fs.writeFileSync(agent, `#!/bin/sh
printf '%s\n' '{"text":"{\\"naming\\":5,\\"commentCoherence\\":null,\\"antipatterns\\":[],\\"barrel\\":false,\\"reason\\":\\"looks valid\\"}"}'
exit 7
`, { mode: 0o755 })

    const run = spawnSync('bun', [SEMANTIC, 'src/a.ts', '--out', '.atlas/result.json'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, ATLAS_QA_AGENT: agent },
      timeout: 10_000,
    })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /exit|agent|7/i)
    assert.equal(fs.existsSync(path.join(root, '.atlas/result.json')), false)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic evaluator accepts sampled paths beginning with option-like dashes after --', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-dash-path-'))
  try {
    const bin = path.join(root, 'bin')
    fs.mkdirSync(path.join(root, '.atlas'), { recursive: true })
    fs.mkdirSync(bin)
    fs.writeFileSync(path.join(root, '--evil.ts'), 'export const answer = 1\n')
    const agent = path.join(bin, 'fake-agent')
    fs.writeFileSync(agent, `#!/bin/sh
printf '%s\n' '{"text":"{\\"naming\\":5,\\"commentCoherence\\":null,\\"antipatterns\\":[],\\"barrel\\":false,\\"reason\\":\\"ok\\"}"}'
`, { mode: 0o755 })

    const run = spawnSync('bun', [SEMANTIC, '--out', '.atlas/result.json', '--', '--evil.ts'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, ATLAS_QA_AGENT: agent },
      timeout: 10_000,
    })
    assert.equal(run.status, 0, run.stderr)
    const result = JSON.parse(fs.readFileSync(path.join(root, '.atlas/result.json'), 'utf8'))
    assert.equal(result.rows[0].path, '--evil.ts')
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic score deduplicates samples, compares every pass pair, and scores human coherence', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-score-full-'))
  try {
    const files = ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'e.ts']
    const manifest = prepareScoreFixture(out, files)
    for (let pass = 1; pass <= 3; pass++) {
      const dir = path.join(out, `pass${pass}`)
      fs.mkdirSync(dir)
      files.forEach((file, index) => fs.writeFileSync(path.join(dir, `${index}.json`), JSON.stringify({
        ...semanticResult(manifest, file, {
          naming: Math.min(5, index + 1),
          commentCoherence: Math.min(5, index + 1),
        }),
      })))
    }
    fs.writeFileSync(path.join(out, 'semantic-labels.json'), JSON.stringify({
      formatVersion: 1,
      sampleHash: manifest.sampleHash,
      rows: files.map((file, index) => ({
        path: file,
        naming: Math.min(5, index + 1),
        commentCoherence: Math.min(5, index + 1),
      })),
    }))

    const run = spawnSync(process.execPath, [SCORE, '--out-dir', out], { encoding: 'utf8' })
    assert.equal(run.status, 0, run.stderr)
    assert.match(run.stdout, /pass1: 5\/5 ratings/)
    assert.match(run.stdout, /pass2.*pass3|pass2.*↔.*pass3/)
    assert.match(run.stdout, /grok vs 人工标注 \(coherence, n=5\).*exact agreement=100\.0%/)
  } finally {
    fs.rmSync(out, { recursive: true, force: true })
  }
})

test('semantic score rejects an incomplete pass instead of scoring a biased subset', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-score-incomplete-'))
  try {
    const files = ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'e.ts']
    const manifest = prepareScoreFixture(out, files)
    fs.mkdirSync(path.join(out, 'pass1'))
    fs.mkdirSync(path.join(out, 'pass2'))
    files.forEach((file, index) => {
      fs.writeFileSync(path.join(out, 'pass1', `${index}.json`), JSON.stringify(semanticResult(manifest, file)))
      if (index < files.length - 1) {
        fs.writeFileSync(path.join(out, 'pass2', `${index}.json`), JSON.stringify(semanticResult(manifest, file)))
      }
    })

    const run = spawnSync(process.execPath, [SCORE, '--out-dir', out], { encoding: 'utf8' })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /incomplete|4\/5|missing/i)
  } finally {
    fs.rmSync(out, { recursive: true, force: true })
  }
})

test('semantic result validation binds checkpoints to the sample and source bytes', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-result-bind-'))
  try {
    const manifest = prepareScoreFixture(out, ['a.ts'])
    const result = semanticResult(manifest, 'a.ts', { sourceHash: '0'.repeat(64) })
    const resultFile = path.join(out, 'result.json')
    fs.writeFileSync(resultFile, JSON.stringify(result))

    const run = spawnSync(process.execPath, [RESULT, resultFile, 'a.ts', path.join(out, 'manifest.json')], { encoding: 'utf8' })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /sourceHash|source bytes|hash/i)
  } finally {
    fs.rmSync(out, { recursive: true, force: true })
  }
})

test('semantic manifests reject alias paths that sample the same file twice', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-alias-'))
  try {
    fs.mkdirSync(path.join(root, 'src'))
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const answer = 1\n')
    assert.throws(
      () => createSemanticManifest(root, ['src/a.ts', 'src/../src/a.ts']),
      /normalized|duplicate|relative/i,
    )
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic evaluator does not fill in required fields missing from agent output', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-schema-'))
  try {
    const bin = path.join(root, 'bin')
    fs.mkdirSync(path.join(root, '.atlas'), { recursive: true })
    fs.mkdirSync(path.join(root, 'src'))
    fs.mkdirSync(bin)
    fs.writeFileSync(path.join(root, 'src/a.ts'), 'export const answer = 1\n')
    const agent = path.join(bin, 'fake-agent')
    fs.writeFileSync(agent, `#!/bin/sh
printf '%s\n' '{"text":"{\\"naming\\":5,\\"barrel\\":false}"}'
`, { mode: 0o755 })

    const run = spawnSync('bun', [SEMANTIC, 'src/a.ts', '--out', '.atlas/result.json'], {
      cwd: root,
      encoding: 'utf8',
      env: { ...process.env, ATLAS_QA_AGENT: agent },
      timeout: 10_000,
    })
    assert.notEqual(run.status, 0)
    const result = JSON.parse(fs.readFileSync(path.join(root, '.atlas/result.json'), 'utf8'))
    assert.match(result.rows[0].error, /commentCoherence|antipatterns|reason|required/i)
  } finally {
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('semantic score rejects human labels after sampled source bytes change', () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'repo-atlas-sem-label-drift-'))
  try {
    const files = ['a.ts', 'b.ts', 'c.ts', 'd.ts', 'e.ts']
    const manifest = prepareScoreFixture(out, files)
    for (const pass of ['pass1', 'pass2']) {
      fs.mkdirSync(path.join(out, pass))
      files.forEach((file, index) => {
        fs.writeFileSync(path.join(out, pass, `${index}.json`), JSON.stringify(semanticResult(manifest, file)))
      })
    }
    fs.writeFileSync(path.join(out, 'semantic-labels.json'), JSON.stringify({
      formatVersion: 1,
      sampleHash: manifest.sampleHash,
      rows: files.map((file) => ({ path: file, naming: 5, commentCoherence: 5 })),
    }))
    fs.writeFileSync(path.join(manifest.repoRoot, 'a.ts'), 'export const changedAfterSampling = true\n')

    const run = spawnSync(process.execPath, [SCORE, '--out-dir', out], { encoding: 'utf8' })
    assert.notEqual(run.status, 0)
    assert.match(run.stderr, /sample paths or file bytes changed|manifest|source bytes/i)
  } finally {
    fs.rmSync(out, { recursive: true, force: true })
  }
})
