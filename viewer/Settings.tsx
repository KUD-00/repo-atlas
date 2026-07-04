import { useEffect } from 'react'
import { t } from '@lingui/core/macro'
import { useLingui } from '@lingui/react/macro'
import {
  type AppLocale, LOCALE_LABELS, LOCALES, setStoredLocale,
} from './i18n'

const GEAR_ICON = (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden>
    <circle cx="12" cy="12" r="3" />
    <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
  </svg>
)

export function SettingsButton({ onClick }: { onClick: () => void }) {
  return (
    <button
      type="button"
      className="settings-btn"
      onClick={onClick}
      title={t`Settings`}
      aria-label={t`Settings`}
    >
      {GEAR_ICON}
    </button>
  )
}

export function SettingsDialog({
  locale, onLocale, onClose,
}: {
  locale: AppLocale
  onLocale: (l: AppLocale) => void
  onClose: () => void
}) {
  const { i18n } = useLingui()

  useEffect(() => {
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onClose()
      }
    }
    window.addEventListener('keydown', onKey, true)
    return () => window.removeEventListener('keydown', onKey, true)
  }, [onClose])

  return (
    <div className="toc-overlay" onClick={onClose}>
      <div className="toc-panel settings-panel" onClick={(e) => e.stopPropagation()}>
        <div className="toc-head settings-head">
          <b>{t(i18n)`Settings`}</b>
          <button type="button" className="toc-open" onClick={onClose} aria-label={t(i18n)`Close`}>×</button>
        </div>
        <div className="settings-body">
          <div className="settings-label">{t(i18n)`Language`}</div>
          <div className="settings-langs">
            {LOCALES.map((l) => (
              <button
                key={l}
                type="button"
                className={'settings-lang' + (locale === l ? ' on' : '')}
                onClick={() => {
                  setStoredLocale(l)
                  onLocale(l)
                }}
              >
                {LOCALE_LABELS[l]}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}