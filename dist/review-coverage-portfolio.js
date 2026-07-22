/** Canonical fail-closed portfolio shared by Node loaders and the browser. */
export function missingReviewCoverage() {
    return {
        state: 'missing',
        report: null,
        errors: [],
        drift: { added: [], removed: [], changed: [] },
    };
}
