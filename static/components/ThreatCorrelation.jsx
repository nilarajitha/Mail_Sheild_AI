function ThreatCorrelation({ correlationData }) {
  if (!correlationData) return null;

  const matches = correlationData.relationship_graph_nodes || [];
  const totalMatches = correlationData.total_correlated_matches || 0;

  return (
    <div className="section-card correlation-card">
      <div className="card-title-row">
        <h3 className="card-heading">
          🔗 Email Relationship & Threat History Correlation
        </h3>
        <span className="card-badge">
          {totalMatches > 0 ? `${totalMatches} Correlated History Emails` : 'No Prior History Matches'}
        </span>
      </div>

      <div className="correlation-overview">
        <div className="campaign-box">
          <span className="campaign-label">Detected Campaign Cluster:</span>
          <span className="campaign-name">{correlationData.campaign_name}</span>
        </div>

        <div className="correlation-stats-grid">
          <div className="correlation-stat-item">
            <span className="stat-value">{correlationData.shared_domain_nodes}</span>
            <span className="stat-label">Matching Domain Nodes</span>
          </div>
          <div className="correlation-stat-item">
            <span className="stat-value">{correlationData.shared_ip_subnets}</span>
            <span className="stat-label">Shared IP Subnets</span>
          </div>
          <div className="correlation-stat-item">
            <span className="stat-value">{totalMatches}</span>
            <span className="stat-label">Threat Cluster Matches</span>
          </div>
        </div>
      </div>

      {matches.length > 0 ? (
        <div className="matched-history-list">
          <h4 className="sub-heading">Matched Historical Email Records:</h4>
          {matches.map((item, idx) => (
            <div key={idx} className="matched-item-row">
              <div className="matched-item-header">
                <div className="matched-subject">{item.subject}</div>
                <div className="similarity-pill">
                  {item.similarity_score}% Relationship Similarity
                </div>
              </div>

              <div className="matched-meta">
                <span>Sender: <code>{item.sender}</code></span>
                <span>Date: {item.timestamp}</span>
                <span className={`severity-tag-${item.severity?.toLowerCase()}`}>{item.threat_score}% ({item.severity})</span>
              </div>

              <div className="match-reasons-list">
                {item.match_reasons?.map((reason, rIdx) => (
                  <span key={rIdx} className="reason-badge">
                    • {reason}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="empty-correlation-box">
          <p>✅ This is the first recorded instance of this email pattern in your database history. No previous campaign correlations found.</p>
        </div>
      )}
    </div>
  );
}

window.ThreatCorrelation = ThreatCorrelation;
