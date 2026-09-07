function ThreatGauge({ threatScore = 0, severity = 'CLEAN', category = '', confidence = 95 }) {
  const radius = 68;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (threatScore / 100) * circumference;

  let gaugeColor = '#10b981'; // Green clean
  if (threatScore >= 80) gaugeColor = '#ef4444'; // Red critical
  else if (threatScore >= 60) gaugeColor = '#f97316'; // Orange high
  else if (threatScore >= 35) gaugeColor = '#f59e0b'; // Yellow medium
  else if (threatScore >= 15) gaugeColor = '#3b82f6'; // Blue low

  return (
    <div className="threat-gauge-card">
      <div className="gauge-wrapper">
        <svg className="gauge-svg" width="160" height="160" viewBox="0 0 160 160">
          {/* Background circle track */}
          <circle 
            className="gauge-track" 
            cx="80" 
            cy="80" 
            r={radius} 
            strokeWidth="12" 
            fill="transparent"
          />
          {/* Animated score arc */}
          <circle 
            className="gauge-progress" 
            cx="80" 
            cy="80" 
            r={radius} 
            strokeWidth="12" 
            stroke={gaugeColor}
            fill="transparent"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
          />
        </svg>

        <div className="gauge-score-content">
          <span className="gauge-score-value">{threatScore}%</span>
          <span className="gauge-score-label">Spam Score</span>
        </div>
      </div>

      <div className="gauge-details">
        <div className={`severity-badge severity-${severity.toLowerCase()}`}>
          {severity} THREAT
        </div>
        <div className="threat-category-title">{category}</div>
        <div className="confidence-pill">
          <span>🎯 ML Model Confidence:</span> <strong>{confidence}%</strong>
        </div>
      </div>
    </div>
  );
}

window.ThreatGauge = ThreatGauge;
