/** Findings, scoring and text rendering shared by every tool. */

export type Severity = "info" | "low" | "medium" | "high";

export interface Finding {
  /** Stable machine-readable ID, e.g. `tls.expired`. */
  id: string;
  severity: Severity;
  message: string;
  remediation?: string;
  /** True for positive results ("HSTS is set"). They never lower the score. */
  ok?: boolean;
}

const PENALTY: Record<Severity, number> = { info: 0, low: 3, medium: 10, high: 25 };
const RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3 };

export const issue = (id: string, severity: Severity, message: string, remediation?: string): Finding => ({
  id,
  severity,
  message,
  ...(remediation ? { remediation } : {}),
});

export const good = (id: string, message: string): Finding => ({ id, severity: "info", message, ok: true });

export function score(findings: Finding[]): { score: number; grade: "A" | "B" | "C" | "D" | "F" } {
  const penalty = findings.filter((f) => !f.ok).reduce((sum, f) => sum + PENALTY[f.severity], 0);
  const value = Math.max(0, 100 - penalty);
  const grade = value >= 90 ? "A" : value >= 75 ? "B" : value >= 60 ? "C" : value >= 40 ? "D" : "F";
  return { score: value, grade };
}

export function worstSeverity(findings: Finding[]): Severity | undefined {
  let worst: Severity | undefined;
  for (const finding of findings) {
    if (finding.ok) continue;
    if (worst === undefined || RANK[finding.severity] > RANK[worst]) worst = finding.severity;
  }
  return worst;
}

/** Problems first (worst to least), then the things that are fine. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    if (!!a.ok !== !!b.ok) return a.ok ? 1 : -1;
    return RANK[b.severity] - RANK[a.severity];
  });
}

export function renderFindings(findings: Finding[]): string {
  const lines: string[] = [];
  for (const finding of sortFindings(findings)) {
    const tag = finding.ok ? "OK" : finding.severity.toUpperCase();
    lines.push(`- [${tag}] ${finding.id}: ${finding.message}`);
    if (finding.remediation && !finding.ok) lines.push(`  Fix: ${finding.remediation}`);
  }
  return lines.join("\n");
}
