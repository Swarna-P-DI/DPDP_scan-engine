export default function ActionButtons({ compact = false }) {
  return (
    <div className={compact ? "action-row compact" : "action-row"}>
      <span className="action-required-badge">Action Required</span>
    </div>
  );
}
