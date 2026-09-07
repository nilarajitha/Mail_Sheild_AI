import React, { useState, useEffect } from 'react';

/**
 * HelloAntigravity Component
 * Displays the iconic "Hello Antigravity" greeting with futuristic visual effects,
 * interactive controls, particle counts, and dynamic state.
 */
export function HelloAntigravity() {
  const [greeting, setGreeting] = useState('Hello Antigravity');
  const [isFloating, setIsFloating] = useState(true);
  const [particleCount, setParticleCount] = useState(42);
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState('preview');
  const [likeCount, setLikeCount] = useState(128);
  const [isLiked, setIsLiked] = useState(false);

  const handleLikeToggle = () => {
    if (isLiked) {
      setLikeCount(prev => prev - 1);
      setIsLiked(false);
    } else {
      setLikeCount(prev => prev + 1);
      setIsLiked(true);
    }
  };

  const handleCopyCode = () => {
    const codeSnippet = `function HelloAntigravity() {\n  return (\n    <h1 className="antigravity-text">\n      Hello Antigravity\n    </h1>\n  );\n}`;
    navigator.clipboard.writeText(codeSnippet);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const triggerZeroGravityPulse = () => {
    setParticleCount(prev => prev + 10);
    const textEl = document.getElementById('main-greeting-heading');
    if (textEl) {
      textEl.classList.add('pulse-anim');
      setTimeout(() => textEl.classList.remove('pulse-anim'), 800);
    }
  };

  return (
    <div className="antigravity-card" id="antigravity-card">
      {/* Top Header Badge */}
      <div className="card-header-badge">
        <span className="live-indicator-dot"></span>
        <span className="badge-text">React 18 Component • Antigravity AI Engine</span>
      </div>

      {/* Main Display Area */}
      <div className={`greeting-display-area ${isFloating ? 'floating-active' : ''}`}>
        <div className="cosmic-glow-orb glow-orb-1"></div>
        <div className="cosmic-glow-orb glow-orb-2"></div>
        
        <div className="text-container">
          <span className="subtitle-tag">// NEXT-GEN AGENTIC REACT COMPONENT</span>
          <h1 className="main-greeting" id="main-greeting-heading">
            {greeting}
          </h1>
          <p className="greeting-subtext">
            Elevating web experiences into zero-gravity precision code.
          </p>
        </div>
      </div>

      {/* Interactive Controls Bar */}
      <div className="interactive-controls">
        <div className="control-group">
          <label htmlFor="custom-greeting-input" className="control-label">
            Customize Greeting:
          </label>
          <input
            id="custom-greeting-input"
            type="text"
            className="custom-input"
            value={greeting}
            onChange={(e) => setGreeting(e.target.value)}
            placeholder="Type your greeting..."
          />
        </div>

        <div className="action-buttons-row">
          <button 
            id="toggle-float-btn"
            className={`btn-secondary ${isFloating ? 'active' : ''}`}
            onClick={() => setIsFloating(!isFloating)}
            title="Toggle floating zero-gravity motion"
          >
            <span className="btn-icon">{isFloating ? '✨' : '⚓'}</span>
            {isFloating ? 'Zero Gravity: ON' : 'Gravity: ON'}
          </button>

          <button 
            id="pulse-particles-btn"
            className="btn-primary"
            onClick={triggerZeroGravityPulse}
          >
            <span className="btn-icon">⚡</span>
            Quantum Pulse ({particleCount})
          </button>

          <button 
            id="like-btn"
            className={`btn-icon-label ${isLiked ? 'liked' : ''}`}
            onClick={handleLikeToggle}
          >
            <span className="btn-icon">{isLiked ? '❤️' : '🤍'}</span>
            <span>{likeCount}</span>
          </button>
        </div>
      </div>

      {/* Tab Switcher & Code Inspector */}
      <div className="code-inspector-section">
        <div className="tab-headers">
          <button 
            id="tab-preview-btn"
            className={`tab-btn ${activeTab === 'preview' ? 'active' : ''}`}
            onClick={() => setActiveTab('preview')}
          >
            🚀 Features & Metrics
          </button>
          <button 
            id="tab-code-btn"
            className={`tab-btn ${activeTab === 'code' ? 'active' : ''}`}
            onClick={() => setActiveTab('code')}
          >
            💻 React Source Code
          </button>
        </div>

        <div className="tab-content">
          {activeTab === 'preview' ? (
            <div className="metrics-grid">
              <div className="metric-card">
                <div className="metric-value">60 FPS</div>
                <div className="metric-label">GPU Accelerated Animations</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">100%</div>
                <div className="metric-label">Vanilla CSS Glassmorphism</div>
              </div>
              <div className="metric-card">
                <div className="metric-value">{particleCount}</div>
                <div className="metric-label">Active Particles in Orbit</div>
              </div>
            </div>
          ) : (
            <div className="code-box-wrapper">
              <button 
                id="copy-code-btn"
                className="copy-code-btn"
                onClick={handleCopyCode}
              >
                {copied ? '✓ Copied!' : '📋 Copy JSX'}
              </button>
              <pre className="code-block">
                <code>
{`import React from 'react';

export function HelloAntigravity() {
  return (
    <div className="antigravity-card">
      <h1 className="main-greeting">
        ${greeting}
      </h1>
    </div>
  );
}`}
                </code>
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
