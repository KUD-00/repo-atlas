import { i18n } from '@lingui/core'
import { messages as en } from './locales/en/messages'
import { messages as ja } from './locales/ja/messages'
import { messages as ko } from './locales/ko/messages'
import { messages as zh } from './locales/zh/messages'
import { resolveInitialLocale } from '../src/audit-localization-presentation'

export const LOCALE_KEY = 'atlas-locale'

export const LOCALES = ['en', 'ja', 'zh', 'ko'] as const
export type AppLocale = (typeof LOCALES)[number]

export const LOCALE_LABELS: Record<AppLocale, string> = {
  en: 'English',
  ja: '日本語',
  zh: '中文',
  ko: '한국어',
}

const CATALOGS: Record<AppLocale, typeof en> = { en, ja, zh, ko }

export function getStoredLocale(defaultLocale?: AppLocale): AppLocale {
  let stored: string | null = null
  try {
    stored = localStorage.getItem(LOCALE_KEY)
  } catch {
    /* private mode */
  }
  return resolveInitialLocale(defaultLocale, stored)
}

export function setStoredLocale(locale: AppLocale): void {
  try {
    localStorage.setItem(LOCALE_KEY, locale)
  } catch {
    /* private mode */
  }
}

export function initI18n(locale: AppLocale): void {
  i18n.load(CATALOGS)
  i18n.activate(locale)
}

export function activateLocale(locale: AppLocale): void {
  i18n.activate(locale)
}

export { i18n }
