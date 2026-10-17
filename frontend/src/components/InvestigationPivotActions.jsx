function InvestigationPivotActions({ pivots = [], onNavigate }) {
  if (!pivots.length) return null
  return (
    <div className="investigation-pivot-actions" aria-label="Related record navigation">
      {pivots.map((item) => (
        <button key={`${item.kind}:${item.id}:${item.label}`} className="security-detail-close" type="button"
          onClick={() => onNavigate?.(item.kind, item.id, item.item)}>
          {item.label}
        </button>
      ))}
    </div>
  )
}

export default InvestigationPivotActions
