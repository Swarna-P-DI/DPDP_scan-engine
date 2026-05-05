import { normalizeRisk, riskTone, severityTone } from "../utils/governanceModel";

export default function RiskBadge({ value, mode = "risk" }) {
  const label = mode === "severity" ? String(value || "low").toLowerCase() : normalizeRisk(value);
  const tone = mode === "severity" ? severityTone(value) : riskTone(value);

  return <span className={`risk-badge risk-${tone}`}>{label}</span>;
}
