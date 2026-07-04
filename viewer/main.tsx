import { createRoot } from 'react-dom/client'
import { I18nProvider } from '@lingui/react'
import { App } from './App'
import { getStoredLocale, i18n, initI18n } from './i18n'
import './styles.css'

initI18n(getStoredLocale())

createRoot(document.getElementById('root')!).render(
  <I18nProvider i18n={i18n}>
    <App data={window.__ATLAS__} />
  </I18nProvider>,
)