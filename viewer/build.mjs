import * as esbuild from 'esbuild'
import { pluginLinguiMacro } from 'esbuild-plugin-lingui-macro'

const watch = process.argv.includes('--watch')

const opts = {
  entryPoints: ['viewer/main.tsx'],
  bundle: true,
  jsx: 'automatic',
  outfile: 'src/vendor/viewer.js',
  minify: !watch,
  plugins: [pluginLinguiMacro()],
}

if (watch) {
  const ctx = await esbuild.context(opts)
  await ctx.watch()
  console.log('watching viewer…')
} else {
  await esbuild.build(opts)
}