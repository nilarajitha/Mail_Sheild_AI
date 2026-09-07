const { useState, useEffect } = React;

function App() {
  const [theme, setTheme] = useState('dark');
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [inspectData, setInspectData] = useState(null);
  const [historyItems, setHistoryItems] = useState([]);
  const [notification, setNotification] = useState(null);
  const [modelStatus, setModelStatus] = useState(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    fetchHistory();
    fetchModelStatus();
  }, [theme]);

  const showNotify = (msg, type = 'info') => {
    setNotification({ msg, type });
    setTimeout(() => setNotification(null), 4000);
  };

  const fetchHistory = () => {
    fetch('/api/history')
      .then(res => res.json())
      .then(data => setHistoryItems(data))
      .catch(err => console.error("Failed to load history:", err));
  };

  const fetchModelStatus = () => {
    fetch('/api/model/status')
      .then(res => res.json())
      .then(data => setModelStatus(data))
      .catch(err => console.error("Failed to load model status:", err));
  };

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
  };

  const handleAnalyzeText = (textPayload) => {
    setIsLoading(true);
    fetch('/api/analyze/text', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(textPayload)
    })
      .then(res => {
        if (!res.ok) throw new Error("Analysis failed.");
        return res.json();
      })
      .then(data => {
        setAnalysisResult(data);
        showNotify(`Analysis Complete! Threat Score: ${data.threat_score}% (${data.severity})`, data.threat_score >= 60 ? 'warning' : 'success');
        fetchHistory();
      })
      .catch(err => {
        showNotify("Error performing email analysis. Please try again.", "error");
      })
      .finally(() => setIsLoading(false));
  };

  const handleAnalyzeFile = (file) => {
    setIsLoading(true);
    const formData = new FormData();
    formData.append('file', file);

    fetch('/api/analyze/file', {
      method: 'POST',
      body: formData
    })
      .then(res => {
        if (!res.ok) throw new Error("File analysis failed.");
        return res.json();
      })
      .then(data => {
        setAnalysisResult(data);
        showNotify(`File Analysis Complete! Threat Score: ${data.threat_score}% (${data.severity})`, 'success');
        fetchHistory();
      })
      .catch(err => {
        showNotify("Failed to analyze uploaded file.", "error");
      })
      .finally(() => setIsLoading(false));
  };

  // History Inspect Handler: Populates text area & switches view
  const handleSelectHistoryItem = (scanId) => {
    fetch(`/api/history/${scanId}`)
      .then(res => res.json())
      .then(data => {
        setAnalysisResult(data);
        setInspectData(data);
        
        // Smooth scroll to analyzer input text area
        const analyzerEl = document.getElementById('analyzer');
        if (analyzerEl) {
          analyzerEl.scrollIntoView({ behavior: 'smooth' });
        }
        showNotify(`Loaded historical scan report #${scanId} into analyzer`, 'info');
      })
      .catch(err => showNotify("Failed to load historical scan detail.", "error"));
  };

  const handleDeleteHistoryItem = (scanId) => {
    fetch(`/api/history/${scanId}`, { method: 'DELETE' })
      .then(res => res.json())
      .then(() => {
        showNotify(`Deleted scan ${scanId}`, 'info');
        fetchHistory();
      });
  };

  const handleClearAllHistory = () => {
    if (confirm("Are you sure you want to clear all persistent scan history?")) {
      fetch('/api/history', { method: 'DELETE' })
        .then(res => res.json())
        .then(() => {
          showNotify("All history records cleared.", "info");
          fetchHistory();
        });
    }
  };

  const handleTrainingLabel = (scanId, label) => {
    fetch(`/api/history/${scanId}/label`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label })
    })
      .then(res => {
        if (!res.ok) throw new Error('Labeling failed.');
        return res.json();
      })
      .then(data => {
        setModelStatus(data);
        setAnalysisResult(previous => previous ? { ...previous, training_label: label } : previous);
        fetchHistory();
        showNotify(data.trained ? `Marked as ${label}. Model retrained from ${data.training_count} emails.` : `Marked as ${label}. Add the other label to train the model.`, 'success');
      })
      .catch(() => showNotify('Could not save the training label.', 'error'));
  };

  return (
    <div className="app-layout">
      {/* Toast Notification */}
      {notification && (
        <div className={`toast-notification toast-${notification.type}`}>
          {notification.msg}
        </div>
      )}

      {/* Main Header */}
      <header className="app-header">
        <window.MailShieldLogo theme={theme} />

        <nav className="header-nav-links">
          <a href="#analyzer" className="hdr-link">Analyzer</a>
          <a href="#results" className="hdr-link">Threat Intel</a>
          <a href="#history" className="hdr-link">Audit History</a>
          
          <button 
            className="theme-switcher-btn"
            onClick={toggleTheme}
          >
            {theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode'}
          </button>
        </nav>
      </header>

      {/* Hero Security Radar Banner */}
      <section className="dashboard-hero">
        <window.RadarDashboard activeThreatCount={historyItems.length} />
        <div className="model-status-banner">
          Model: {modelStatus?.trained ? `trained on ${modelStatus.training_count} labeled emails` : 'rules-only; label one spam and one ham email to train'}
        </div>
      </section>

      {/* Main Workspace */}
      <main className="main-workspace">
        {/* Input Hub */}
        <section id="analyzer" className="analyzer-section">
          <window.AnalyzerInput 
            onAnalyzeText={handleAnalyzeText}
            onAnalyzeFile={handleAnalyzeFile}
            isLoading={isLoading}
            inspectData={inspectData}
          />
        </section>

        {/* Detailed Results Section */}
        {analysisResult && (
          <section id="results" className="results-section">
            <div className="results-grid-top">
              <window.ThreatGauge 
                threatScore={analysisResult.threat_score}
                severity={analysisResult.severity}
                category={analysisResult.category}
                confidence={analysisResult.confidence}
              />
              <div className="training-label-panel">
                <strong>Correct this result for training</strong>
                <span>Saved email: {analysisResult.training_label || 'not labeled'}</span>
                <div>
                  <button className="btn-tbl-del" onClick={() => handleTrainingLabel(analysisResult.scan_id, 'spam')}>Mark Spam</button>
                  <button className="btn-tbl-view" onClick={() => handleTrainingLabel(analysisResult.scan_id, 'ham')}>Mark Ham</button>
                </div>
              </div>
            </div>

            {/* Email Relationship & Threat Correlation Component */}
            <window.ThreatCorrelation 
              correlationData={analysisResult.threat_correlation}
            />

            {/* Domain & IP Intelligence + Geolocation Map */}
            <window.DomainIpIntel 
              domainIntel={analysisResult.domain_intelligence}
              ipIntel={analysisResult.ip_intelligence}
              geoIntel={analysisResult.geo_location}
            />

            {/* SPF / DKIM / DMARC Grid */}
            <window.AuthGrid 
              authData={analysisResult.auth_verifier}
            />

            {/* Attack Hop Path Visualizer */}
            <window.AttackTrace 
              attackTraceNodes={analysisResult.attack_trace}
            />

            {/* Investigation Threat Rationale & Remediation Playbook */}
            <window.ThreatRationale 
              investigationData={analysisResult.investigation}
            />

            {/* Blockchain Proof Verification Certificate */}
            <window.BlockchainProof 
              proofData={analysisResult.blockchain_proof}
              scanId={analysisResult.scan_id}
            />
          </section>
        )}

        {/* Persistent History Drawer Table */}
        <section id="history" className="history-section">
          <window.HistoryDrawer 
            historyItems={historyItems}
            onSelectHistoryItem={handleSelectHistoryItem}
            onDeleteHistoryItem={handleDeleteHistoryItem}
            onClearAllHistory={handleClearAllHistory}
          />
        </section>
      </main>

      {/* Footer */}
      <footer className="app-footer">
        <div className="footer-flex">
          <div>
            <strong>MailShield AI Security Engine v1.0.0</strong> • AI powered email threat detection geo location and forensic intelligence
          </div>
          <div className="footer-status">
            <span className="status-dot"></span> System Operational • Fast API & ReactJS Core
          </div>
        </div>
      </footer>
    </div>
  );
}

// Mount React App
const rootElement = document.getElementById('root');
if (rootElement) {
  const root = ReactDOM.createRoot(rootElement);
  root.render(<App />);
}
