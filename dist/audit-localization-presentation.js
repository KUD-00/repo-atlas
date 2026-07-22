import { missingReviewCoverage } from './review-coverage-portfolio.js';
const LOCALES = new Set(['en', 'ja', 'zh', 'ko']);
export function resolveInitialLocale(defaultLocale, storedValue) {
    if (storedValue && LOCALES.has(storedValue))
        return storedValue;
    if (defaultLocale && LOCALES.has(defaultLocale))
        return defaultLocale;
    return 'en';
}
function unitKey(domain, slug) {
    return `${domain}\0${slug}`;
}
function validText(value) {
    return typeof value === 'string' && value.length > 0;
}
function validSecurityTranslation(translation, unit) {
    return translation.domain === 'security' &&
        translation.slug === unit.slug &&
        validText(translation.title) &&
        translation.findings.length === unit.findings.length &&
        translation.findings.every((finding) => validText(finding.sourceDigest) &&
            validText(finding.title) &&
            'dataflow' in finding && validText(finding.dataflow) &&
            validText(finding.fix));
}
function validTestTranslation(translation, unit) {
    return translation.domain === 'test' &&
        translation.slug === unit.slug &&
        validText(translation.title) &&
        translation.findings.length === unit.findings.length &&
        translation.findings.every((finding) => validText(finding.sourceDigest) &&
            validText(finding.title) &&
            'invariant' in finding && validText(finding.invariant) &&
            validText(finding.evidence) &&
            validText(finding.fix));
}
export function localizeAuditPresentation({ locale, sourceLocale = 'en', localizations = {}, audits, testAudits, reviewCoverage, }) {
    const coverage = reviewCoverage ?? missingReviewCoverage();
    if (locale === sourceLocale) {
        return {
            state: 'source',
            audits: audits.map((unit) => ({ ...unit, findings: unit.findings.map((finding) => ({ ...finding })) })),
            testAudits: testAudits.map((unit) => ({ ...unit, findings: unit.findings.map((finding) => ({ ...finding })) })),
            reviewCoverage: coverage.report
                ? { ...coverage, report: { ...coverage.report, units: coverage.report.units.map((unit) => ({ ...unit })) } }
                : { ...coverage },
        };
    }
    const portfolio = localizations[locale];
    const canUseTranslations = portfolio?.state === 'complete' || portfolio?.state === 'incomplete';
    const translations = new Map();
    if (canUseTranslations) {
        for (const unit of portfolio.units)
            translations.set(unitKey(unit.domain, unit.slug), unit);
    }
    let fellBack = !portfolio || portfolio.state !== 'complete';
    const localizedAudits = audits.map((unit) => {
        const translation = translations.get(unitKey('security', unit.slug));
        if (!translation || !validSecurityTranslation(translation, unit)) {
            fellBack = true;
            return { ...unit, findings: unit.findings.map((finding) => ({ ...finding })) };
        }
        return {
            ...unit,
            title: translation.title,
            findings: unit.findings.map((finding, index) => ({
                ...finding,
                title: translation.findings[index].title,
                dataflow: translation.findings[index].dataflow,
                fix: translation.findings[index].fix,
            })),
        };
    });
    const localizedTests = testAudits.map((unit) => {
        const translation = translations.get(unitKey('test', unit.slug));
        if (!translation || !validTestTranslation(translation, unit)) {
            fellBack = true;
            return { ...unit, findings: unit.findings.map((finding) => ({ ...finding })) };
        }
        return {
            ...unit,
            title: translation.title,
            findings: unit.findings.map((finding, index) => ({
                ...finding,
                title: translation.findings[index].title,
                invariant: translation.findings[index].invariant,
                evidence: translation.findings[index].evidence,
                fix: translation.findings[index].fix,
            })),
        };
    });
    const localizedCoverage = coverage.report
        ? {
            ...coverage,
            report: {
                ...coverage.report,
                units: coverage.report.units.map((unit) => {
                    const translation = translations.get(unitKey(unit.domain, unit.slug));
                    if (!translation || !validText(translation.title)) {
                        fellBack = true;
                        return { ...unit };
                    }
                    return { ...unit, title: translation.title };
                }),
            },
        }
        : { ...coverage };
    return {
        state: fellBack ? 'fallback' : 'translated',
        audits: localizedAudits,
        testAudits: localizedTests,
        reviewCoverage: localizedCoverage,
    };
}
