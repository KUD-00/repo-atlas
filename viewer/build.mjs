import * as esbuild from 'esbuild'
import * as fs from 'node:fs/promises'
import path from 'node:path'
import { transformAsync } from '@babel/core'
import reactCompiler from 'babel-plugin-react-compiler'
import linguiMacroPlugin from '@lingui/babel-plugin-lingui-macro'
import { babelRe, getBabelParserOptions } from '@lingui/cli/api/extractors/babel'
import { getConfig } from '@lingui/conf'
import postcss from 'postcss'
import tailwindcss from '@tailwindcss/postcss'

const watch = process.argv.includes('--watch')
const linguiConfig = getConfig({ skipValidation: true })
const MACRO_RE = /from ["']@lingui(\/.+)?\/macro["']/

const tailwindPlugin = {
  name: 'tailwind-css',
  setup(build) {
    build.onLoad({ filter: /styles\.css$/ }, async (args) => {
      const source = await fs.readFile(args.path, 'utf8')
      const result = await postcss([tailwindcss()]).process(source, { from: args.path })
      return { contents: result.css, loader: 'css' }
    })
  },
}

/** Babel pass: React Compiler first, then Lingui macros when present. */
const babelViewerPlugin = {
  name: 'babel-viewer',
  setup(build) {
    build.onLoad({ filter: babelRe, namespace: '' }, async (args) => {
      if (args.path.includes(`${path.sep}node_modules${path.sep}`)) return
      const filename = path.relative(process.cwd(), args.path)
      const contents = await fs.readFile(args.path, 'utf8')
      const hasMacro = MACRO_RE.test(contents)
      // Always run compiler on app sources so memoization is automatic.
      const plugins = [
        reactCompiler, // must run first
      ]
      if (hasMacro) {
        plugins.push([
          linguiMacroPlugin,
          { linguiConfig },
        ])
      }
      const result = await transformAsync(contents, {
        babelrc: false,
        configFile: false,
        filename,
        sourceMaps: 'inline',
        parserOpts: {
          plugins: getBabelParserOptions(
            filename,
            linguiConfig.extractorParserOptions,
          ),
        },
        plugins,
      })
      return { contents: result?.code ?? contents, loader: 'tsx' }
    })
  },
}

const opts = {
  entryPoints: ['viewer/main.tsx'],
  bundle: true,
  jsx: 'automatic',
  outfile: 'src/vendor/viewer.js',
  minify: !watch,
  plugins: [babelViewerPlugin, tailwindPlugin],
}

if (watch) {
  const ctx = await esbuild.context(opts)
  await ctx.watch()
  console.log('watching viewer…')
} else {
  await esbuild.build(opts)
}
