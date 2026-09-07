function ThreatRationale({ investigationData }) {
  if (!investigationData) return null;

  const { why_threat_occurred, how_to_resolve, investigation_summary } = investigationData;

  return (
    <div className="section-card rationale-card">
      <h3 className="card-heading">🕵️ Security Investigation & Threat Rationale</h3>
      <div className="summary-banner">{investigation_summary}</div>

      <div className="rationale-grid">
        {/* Why Threat Occurred Block */}
        <div className="rationale-block block-why">
          <h4 className="rationale-block-title">
            ❓ Why Threat Occurred (Threat Analysis)
          </h4>
          <ul className="rationale-list">
            {why_threat_occurred && why_threat_occurred.map((item, i) => (
              <li key={i} className="rationale-item item-why">
                <span className="bullet-icon">🔍</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>

        {/* How to Resolve Block */}
        <div className="rationale-block block-how">
          <h4 className="rationale-block-title">
            🛠️ How to Resolve (Actionable Playbook)
          </h4>
          <ul className="rationale-list">
            {how_to_resolve && how_to_resolve.map((item, i) => (
              <li key={i} className="rationale-item item-how">
                <span className="bullet-icon">🛡️</span>
                <span>{item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

window.ThreatRationale = ThreatRationale;
