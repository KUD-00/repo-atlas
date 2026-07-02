// Vendor bundle source: pnpm dlx esbuild src/vendor/hljs-entry.mjs --bundle --minify --format=iife --outfile=src/vendor/hljs.js
import hljs from 'highlight.js/lib/common'
import nix from 'highlight.js/lib/languages/nix'
import dockerfile from 'highlight.js/lib/languages/dockerfile'
hljs.registerLanguage('nix', nix)
hljs.registerLanguage('dockerfile', dockerfile)
window.hljs = hljs
