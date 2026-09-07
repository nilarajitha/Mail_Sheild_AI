function AuthGrid({ authData }) {
  if (!authData) return null;

  const { spf, dkim, dmarc } = authData;

  const getStatusBadge = (status) => {
    const s = (status || '').toUpperCase();
    if (s === 'PASS') return <span className="auth-badge status-pass">✓ PASS</span>;
    if (s === 'FAIL') return <span className="auth-badge status-fail">✗ FAIL</span>;
    if (s === 'SOFTFAIL') return <span className="auth-badge status-softfail">⚠️ SOFTFAIL</span>;
    return <span className="auth-badge status-neutral">❓ {s || 'NONE'}</span>;
  };

  return (
    <div className="section-card auth-card">
      <div className="card-title-row">
        <h3 className="card-heading">🔒 Email Protocol Authentication (SPF / DKIM / DMARC)</h3>
        <span className={`auth-overall-badge ${authData.overall_pass ? 'pass' : 'fail'}`}>
          {authData.overall_pass ? 'AUTHENTICATION VERIFIED' : 'AUTHENTICATION FAILED'}
        </span>
      </div>

      <div className="auth-protocol-grid">
        {/* SPF Protocol Card */}
        <div className="protocol-card">
          <div className="protocol-header">
            <span className="protocol-title">SPF (Sender Policy Framework)</span>
            {getStatusBadge(spf?.status)}
          </div>
          <div className="protocol-desc">{spf?.details}</div>
          <div className="protocol-meta">
            <span>Domain: <code>{spf?.domain}</code></span>
            <span>IP: <code>{spf?.ip}</code></span>
          </div>
        </div>

        {/* DKIM Protocol Card */}
        <div className="protocol-card">
          <div className="protocol-header">
            <span className="protocol-title">DKIM (DomainKeys Identified Mail)</span>
            {getStatusBadge(dkim?.status)}
          </div>
          <div className="protocol-desc">{dkim?.details}</div>
          <div className="protocol-meta">
            <span>Selector: <code>{dkim?.selector}</code></span>
            <span>Algorithm: <code>{dkim?.algorithm}</code></span>
          </div>
        </div>

        {/* DMARC Protocol Card */}
        <div className="protocol-card">
          <div className="protocol-header">
            <span className="protocol-title">DMARC Policy Alignment</span>
            {getStatusBadge(dmarc?.status)}
          </div>
          <div className="protocol-desc">{dmarc?.details}</div>
          <div className="protocol-meta">
            <span>Policy Action: <code>{dmarc?.policy}</code></span>
            <span>Disposition: <code>{dmarc?.disposition}</code></span>
          </div>
        </div>
      </div>
    </div>
  );
}

window.AuthGrid = AuthGrid;
