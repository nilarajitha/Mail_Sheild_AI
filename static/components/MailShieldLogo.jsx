const { useState } = React;

function MailShieldLogo({ theme }) {
  return (
    <div className="brand-logo-container">
      <img 
        src="/static/mailshield_logo.png" 
        alt="MailShield AI Logo" 
        className="brand-logo-img" 
        onError={(e) => {
          e.target.onerror = null;
          e.target.style.display = 'none';
        }}
      />
      <div className="brand-text-group">
        <span className="brand-name">
          MAIL<span className="brand-highlight">SHIELD</span> <span className="brand-ai-tag">AI</span>
        </span>
        <span className="brand-subtext">AI powered email threat detection geo location and forensic intelligence</span>
      </div>
    </div>
  );
}

window.MailShieldLogo = MailShieldLogo;
