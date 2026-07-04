import * as esbuild from 'esbuild'
import * as fs from 'node:fs/promises'
import postcss from 'postcss'
import tailwindcss from '@tailwindcss/postcss'
import { pluginLinguiMacro } from 'esbuild-plugin-lingui-macro'

const watch = process.argv.includes('--watch')

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

const opts = {
  entryPoints: ['viewer/main.tsx'],
  bundle: true,
  jsx: 'automatic',
  outfile: 'src/vendor/viewer.js',
  minify: !watch,
  plugins: [pluginLinguiMacro(), tailwindPlugin],
}

if (watch) {
  const ctx = await esbuild.context(opts)
  await ctx.watch()
  console.log('watching viewer…')
} else {
  await esbuild.build(opts)
}