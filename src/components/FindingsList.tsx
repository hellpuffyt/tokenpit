import type { Finding } from "../lib/rules";
import { SeverityBadge } from "./SeverityBadge";

export function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="empty-note" role="status">
        No findings for this token.
      </p>
    );
  }

  const criticalOrHigh = findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

  return (
    <div>
      <p className="findings-summary" role="status" aria-live="polite">
        {criticalOrHigh > 0
          ? `${criticalOrHigh} critical/high-severity ${criticalOrHigh === 1 ? "issue" : "issues"} found, ${findings.length} total.`
          : `${findings.length} finding${findings.length === 1 ? "" : "s"}, none critical or high.`}
      </p>
      <ul className="findings-list">
        {findings.map((f) => (
          <li key={f.id} className={`finding finding-${f.severity}`} data-testid={`finding-${f.id}`}>
            <div className="finding-head">
              <SeverityBadge severity={f.severity} />
              <h3>{f.title}</h3>
            </div>
            <p className="finding-detail">{f.detail}</p>
            <p className="finding-recommendation">
              <strong>Fix:</strong> {f.recommendation}
            </p>
          </li>
        ))}
      </ul>
    </div>
  );
}
