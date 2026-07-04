import type { LinguiConfig } from '@lingui/conf'

const config: LinguiConfig = {
  sourceLocale: 'en',
  locales: ['en', 'ja', 'zh', 'ko'],
  catalogs: [
    {
      path: 'viewer/locales/{locale}/messages',
      include: ['viewer'],
    },
  ],
  format: 'po',
}

export default config