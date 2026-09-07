import React, { useState, useEffect } from 'react';
import { HelloAntigravity } from './HelloAntigravity.jsx';

export default function App() {
  const [theme, setTheme] = useState('dark');
  const [stars, setStars] = useState([]);

  // Generate interactive background stars/particles
  useEffect(() => {
    const starList = Array.from({ length: 35 }).map((_, index) => ({
      id: index,
      top: `${Math.random() * 100}%`,
      left: `${Math.random() * 100}%`,
      size: `${Math.random() * 4 + 2}px`,
      duration: `${Math.random() * 5 + 3}s`,
      delay: `${Math.random() * 4}s`
    }));
    setStars(starList);
  }, []);

  const toggleTheme = () => {
    const nextTheme = theme === 'dark' ? 'light' : 'dark';
    setTheme(nextTheme);
    document.documentElement.setAttribute('data-theme', nextTheme);
  };

  return (
    <div className={`app-container ${theme}-mode`}>
      {/* Background Animated Floating Stars */}
      <div className="starfield" aria-hidden="true">
        {stars.map(star => (
          <div
            key={star.id}
            className="star-particle"
            style={{
              top: star.top,
              left: star.left,
              width: star.size,
              height: star.size,
              animationDuration: star.duration,
              animationDelay: star.delay
            }}
          />
        ))}
      </div>

      {/* Main Navigation Header */}
      <header className="app-header">
        <div className="header-brand">
          <div className="brand-logo-icon">🪐</div>
          <span className="brand-title">Antigravity<span className="brand-accent">.React</span></span>
        </div>

        <nav className="header-nav">
          <a href="#features" className="nav-link">Features</a>
          <a href="#component" className="nav-link">Component</a>
          <a href="#architecture" className="nav-link">Architecture</a>
          
          <button 
            id="theme-toggle-btn"
            className="theme-toggle-btn"
            onClick={toggleTheme}
            aria-label="Toggle dark/light theme"
          >
            {theme === 'dark' ? '🌙 Dark Mode' : '☀️ Light Mode'}
          </button>
        </nav>
      </header>

      {/* Main Container */}
      <main className="main-content" id="component">
        <section className="hero-section">
          <div className="hero-badge">
            <span className="sparkle">✨</span> Welcome to Antigravity React Environment
          </div>

          {/* Render the HelloAntigravity Component */}
          <HelloAntigravity />
        </section>

        {/* Feature Cards Grid Section */}
        <section className="features-section" id="features">
          <h2 className="section-title">Built with React & Zero-Gravity Design</h2>
          <p className="section-subtitle">Key highlighting features of your new React component structure</p>

          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">⚡</div>
              <h3 className="feature-title">Ultra Reactive State</h3>
              <p className="feature-desc">
                Powered by React 18 hooks (`useState`, `useEffect`) providing instant UI responsiveness and fluid state transitions.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">💎</div>
              <h3 className="feature-title">Glassmorphism Aesthetics</h3>
              <p className="feature-desc">
                Crafted with layered CSS backdrop filters, neon text gradients, dynamic shadows, and glowing orb accents.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🌌</div>
              <h3 className="feature-title">Antigravity Motion</h3>
              <p className="feature-desc">
                Smooth 60FPS CSS hardware-accelerated float keyframes simulating effortless zero-gravity levitation.
              </p>
            </div>

            <div className="feature-card" id="architecture">
              <div className="feature-icon">🛠️</div>
              <h3 className="feature-title">Modular & Extensible</h3>
              <p className="feature-desc">
                Clean component separation with `HelloAntigravity.jsx` exported as an isolated, reusable React module.
              </p>
            </div>
          </div>
        </section>
      </main>

      {/* App Footer */}
      <footer className="app-footer">
        <div className="footer-content">
          <p>© 2026 Antigravity AI • Built with React & Vanilla CSS</p>
          <div className="footer-status">
            <span className="status-dot"></span> System Status: 100% Operational
          </div>
        </div>
      </footer>
    </div>
  );
}
