const { useState, useEffect } = React;

function AnalyzerInput({ onAnalyzeText, onAnalyzeFile, isLoading, inspectData }) {
  const [activeTab, setActiveTab] = useState('text');
  const [emailText, setEmailText] = useState('');
  const [subject, setSubject] = useState('');
  const [sender, setSender] = useState('');
  const [samples, setSamples] = useState([]);
  const [isDragOver, setIsDragOver] = useState(false);

  useEffect(() => {
    fetch('/api/samples')
      .then(res => res.json())
      .then(data => setSamples(data))
      .catch(err => console.error("Failed to load sample emails:", err));
  }, []);

  // When inspectData is updated from history click, populate input fields & switch tab
  useEffect(() => {
    if (inspectData) {
      if (inspectData.email_text || inspectData.ml_analysis) {
        setEmailText(inspectData.email_text || inspectData.subject || '');
        setSubject(inspectData.subject || '');
        setSender(inspectData.sender || '');
        setActiveTab('text');
      }
    }
  }, [inspectData]);

  const handleTextSubmit = (e) => {
    e.preventDefault();
    if (!emailText.trim()) return;
    onAnalyzeText({ email_text: emailText, subject, sender });
  };

  const handleSampleClick = (sample) => {
    setEmailText(sample.text);
    setSubject(sample.subject);
    setSender(sample.sender);
    setActiveTab('text');
    onAnalyzeText({ email_text: sample.text, subject: sample.subject, sender: sample.sender });
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      onAnalyzeFile(file);
    }
  };

  const handleFileSelect = (e) => {
    if (e.target.files && e.target.files[0]) {
      onAnalyzeFile(e.target.files[0]);
    }
  };

  return (
    <div className="analyzer-input-card">
      {/* Tab Header Navigation */}
      <div className="input-tab-bar">
        <button 
          className={`input-tab-btn ${activeTab === 'text' ? 'active' : ''}`}
          onClick={() => setActiveTab('text')}
        >
          📝 Text & Header Analyzer
        </button>
        <button 
          className={`input-tab-btn ${activeTab === 'file' ? 'active' : ''}`}
          onClick={() => setActiveTab('file')}
        >
          📁 Drag & Drop File Upload
        </button>
        <button 
          className={`input-tab-btn ${activeTab === 'samples' ? 'active' : ''}`}
          onClick={() => setActiveTab('samples')}
        >
          🧪 Sample Threat Library
        </button>
      </div>

      <div className="input-tab-content">
        {/* Tab 1: Text & Header Raw Input */}
        {activeTab === 'text' && (
          <form onSubmit={handleTextSubmit} className="text-analyzer-form">
            <div className="form-row-2">
              <div className="form-group">
                <label className="input-label">Email Subject (Optional)</label>
                <input 
                  type="text" 
                  className="theme-input"
                  placeholder="e.g. URGENT: Account Suspended Verification Needed"
                  value={subject}
                  onChange={(e) => setSubject(e.target.value)}
                />
              </div>
              <div className="form-group">
                <label className="input-label">Sender Email Address (Optional)</label>
                <input 
                  type="text" 
                  className="theme-input"
                  placeholder="e.g. security-alert@micros0ft-login.xyz"
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                />
              </div>
            </div>

            <div className="form-group">
              <label className="input-label">Paste Raw Email Body or Headers *</label>
              <textarea
                className="theme-textarea"
                rows="7"
                placeholder="Paste full raw email content, headers, or body text here..."
                value={emailText}
                onChange={(e) => setEmailText(e.target.value)}
                required
              />
            </div>

            <div className="submit-action-row">
              <button 
                type="submit" 
                className="btn-analyze-primary"
                disabled={isLoading || !emailText.trim()}
              >
                {isLoading ? (
                  <>
                    <span className="spinner-icon">🔄</span> Analyzing Threat Vectors...
                  </>
                ) : (
                  <>
                    <span className="btn-icon">⚡</span> Analyze Threat Score & Intelligence
                  </>
                )}
              </button>
            </div>
          </form>
        )}

        {/* Tab 2: Drag & Drop File Upload Zone */}
        {activeTab === 'file' && (
          <div 
            className={`file-drop-zone ${isDragOver ? 'drag-over' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleFileDrop}
          >
            <div className="drop-zone-icon">📥</div>
            <h3 className="drop-zone-title">Drag & Drop Email File Here</h3>
            <p className="drop-zone-sub">Supports .eml, .msg, .txt, .json email export formats</p>
            
            <label htmlFor="file-input-element" className="btn-browse-file">
              Select File from Device
            </label>
            <input 
              id="file-input-element"
              type="file" 
              accept=".eml,.txt,.msg,.json" 
              onChange={handleFileSelect}
              style={{ display: 'none' }}
            />
          </div>
        )}

        {/* Tab 3: Sample Threat Library */}
        {activeTab === 'samples' && (
          <div className="samples-grid">
            {samples.map(sample => (
              <div 
                key={sample.id} 
                className="sample-card"
                onClick={() => handleSampleClick(sample)}
              >
                <div className="sample-card-title">{sample.title}</div>
                <div className="sample-card-sub">{sample.subject}</div>
                <div className="sample-sender-tag">From: {sample.sender}</div>
                <button className="btn-load-sample">⚡ Load & Analyze</button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

window.AnalyzerInput = AnalyzerInput;
