import type { AtlasPayload } from '../src/types'

interface MermaidAPI {
  initialize: (config: Record<string, unknown>) => void
  render: (id: string, src: string) => Promise<{ svg: string }>
}

interface HLJSAPI {
  getLanguage: (lang: string) => unknown
  highlight: (text: string, opts: { language: string; ignoreIllegals: boolean }) => { value: string }
}

declare global {
  interface Window {
    __ATLAS__: AtlasPayload
    mermaid?: MermaidAPI
    hljs?: HLJSAPI
  }
}

export {}