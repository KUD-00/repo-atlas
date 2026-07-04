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
  const { i18n } = useLingui()
  return (
    <button
      type="button"
      className="settings-btn shrink-0 flex items-center justify-center w-7 h-7 border border-border rounded-lg bg-bg text-muted cursor-pointer p-0 hover:text-accent hover:border-[#3d6b5440] hover:bg-[#3d6b540a]"
      onClick={onClick}
      title={t(i18n)`Settings`}
      aria-label={t(i18n)`Settings`}
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
    <div
      className="fixed inset-0 z-30 bg-[#00000033] flex items-center justify-center"
      onClick={onClose}
    >
      <div
        className="w-[min(360px,90vw)] flex flex-col bg-panel border border-border rounded-xl shadow-[0_10px_40px_#00000030] overflow-hidden animate-[chat-in_0.16s_ease] origin-center"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center flex-wrap gap-0.5 py-2.5 px-3.5 border-b border-border text-[0.8rem] w-full">
          <b>{t(i18n)`Settings`}</b>
          <button
            type="button"
            className="ml-auto font-inherit border-none bg-transparent cursor-pointer text-muted py-0 px-1 hover:text-accent"
            onClick={onClose}
            aria-label={t(i18n)`Close`}
          >
            ×
          </button>
        </div>
        <div className="px-4 py-3.5 pb-[18px] flex flex-col gap-2.5">
          <div className="text-[0.75rem] text-muted">{t(i18n)`Language`}</div>
          <div className="flex flex-col gap-1.5">
            {LOCALES.map((l) => (
              <button
                key={l}
                type="button"
                className={
                  'font-inherit text-[0.85rem] text-left py-2 px-3 border border-border rounded-lg bg-bg text-text cursor-pointer ' +
                  (locale === l
                    ? 'on border-accent text-accent bg-[#3d6b540f]'
                    : 'hover:border-[#3d6b5440]')
                }
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