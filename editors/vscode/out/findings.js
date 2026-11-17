"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.reportableFindings = reportableFindings;
/**
 * Review states the project's policy uses to dismiss a finding. They match
 * the CLI's build gate: a dismissed finding never fails `--fail-on`, so the
 * editor does not show it either.
 */
const DISMISSED_STATES = new Set(['falsePositive', 'acceptedRisk', 'suppressed']);
/** Findings worth a diagnostic: everything except policy dismissals. */
function reportableFindings(findings) {
    return findings.filter((finding) => !DISMISSED_STATES.has(finding.review?.state ?? ''));
}
//# sourceMappingURL=findings.js.map