import type { Severity } from "../lib/rules";

const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge-${severity}`} data-testid="severity-badge">
      {LABEL[severity]}
    </span>
  );
}
