import assert from 'node:assert/strict'
import test from 'node:test'

import { relevantGlossary } from '../qa/glossary.mjs'

const glossary = `# Glossary

## L1
aliases: Layer One, 一级
The first layer.

## auth
Authentication shorthand.
`

test('QA glossary context matches aliases and Latin word boundaries like the viewer', () => {
  const aliasMatch = relevantGlossary(glossary, 'The request enters Layer One before dispatch.')
  assert.match(aliasMatch, /^## L1/m)

  const falsePositives = relevantGlossary(glossary, 'L114 reauthenticates a request.')
  assert.equal(falsePositives, '')

  const cjkAlias = relevantGlossary(glossary, '请求进入一级调度。')
  assert.match(cjkAlias, /^## L1/m)
})
