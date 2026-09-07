const { useEffect, useRef } = React;

function RadarDashboard({ activeThreatCount = 0 }) {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let scanAngle = 0;

    const width = canvas.width = canvas.parentElement.clientWidth || 650;
    const height = canvas.height = 190;
    const centerX = width / 2;
    const centerY = height / 2;

    // Incoming email packet particles flying towards central shield node
    const emailPackets = Array.from({ length: 18 }).map((_, i) => {
      const angle = (i / 18) * Math.PI * 2;
      const distance = 80 + Math.random() * 140;
      return {
        angle,
        distance,
        speed: 0.6 + Math.random() * 0.8,
        type: i % 4 === 0 ? 'phishing' : (i % 4 === 1 ? 'bec' : (i % 4 === 2 ? 'malware' : 'clean')),
        icon: i % 4 === 0 ? '🎣' : (i % 4 === 1 ? '💼' : (i % 4 === 2 ? '☣️' : '✉️')),
        color: i % 4 === 0 ? '#ef4444' : (i % 4 === 1 ? '#f59e0b' : (i % 4 === 2 ? '#8b5cf6' : '#10b981'))
      };
    });

    const render = () => {
      ctx.clearRect(0, 0, width, height);

      // 1. Draw glowing background grid lines
      ctx.strokeStyle = 'rgba(139, 92, 246, 0.08)';
      ctx.lineWidth = 1;
      const gridSize = 30;
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // 2. Draw central MailShield AI Core pulse rings
      const time = Date.now() * 0.003;
      const pulseRadius1 = 28 + Math.sin(time) * 4;
      const pulseRadius2 = 50 + Math.cos(time * 0.8) * 6;

      ctx.beginPath();
      ctx.arc(centerX, centerY, pulseRadius2, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(6, 182, 212, 0.25)';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(centerX, centerY, pulseRadius1, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(139, 92, 246, 0.5)';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Central Shield Icon Core
      ctx.beginPath();
      ctx.arc(centerX, centerY, 16, 0, Math.PI * 2);
      ctx.fillStyle = '#8b5cf6';
      ctx.shadowColor = '#06b6d4';
      ctx.shadowBlur = 15;
      ctx.fill();
      ctx.shadowBlur = 0;

      ctx.fillStyle = '#ffffff';
      ctx.font = 'bold 12px sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('🛡️', centerX, centerY);

      // 3. Draw sweeping cyber laser beam
      scanAngle += 0.03;
      if (scanAngle > Math.PI * 2) scanAngle = 0;

      ctx.save();
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.arc(centerX, centerY, 160, scanAngle - 0.5, scanAngle);
      ctx.closePath();

      const laserGrad = ctx.createRadialGradient(centerX, centerY, 0, centerX, centerY, 160);
      laserGrad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
      laserGrad.addColorStop(1, 'rgba(139, 92, 246, 0.02)');
      ctx.fillStyle = laserGrad;
      ctx.fill();
      ctx.restore();

      // Sweeping edge line
      ctx.beginPath();
      ctx.moveTo(centerX, centerY);
      ctx.lineTo(centerX + Math.cos(scanAngle) * 160, centerY + Math.sin(scanAngle) * 160);
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = 2;
      ctx.stroke();

      // 4. Update and render email packet particles
      emailPackets.forEach(p => {
        p.distance -= p.speed;
        if (p.distance < 18) {
          p.distance = 130 + Math.random() * 60;
          p.angle = Math.random() * Math.PI * 2;
        }

        const px = centerX + Math.cos(p.angle) * p.distance;
        const py = centerY + Math.sin(p.angle) * p.distance;

        // Packet connection beam to core
        ctx.beginPath();
        ctx.moveTo(px, py);
        ctx.lineTo(centerX, centerY);
        ctx.strokeStyle = p.color;
        ctx.globalAlpha = 0.2;
        ctx.lineWidth = 1;
        ctx.stroke();
        ctx.globalAlpha = 1.0;

        // Packet node dot
        ctx.beginPath();
        ctx.arc(px, py, 4, 0, Math.PI * 2);
        ctx.fillStyle = p.color;
        ctx.shadowColor = p.color;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <div className="radar-banner-card">
      <div className="radar-canvas-container">
        <canvas ref={canvasRef} className="radar-canvas" />
      </div>

      <div className="radar-stats-overlay">
        <div className="radar-status-pill">
          <span className="live-pulse-dot"></span>
          <span>MailShield AI Cyber Envelope Scanner • Live Inspection</span>
        </div>

        <div className="radar-metrics-row">
          <div className="radar-stat">
            <span className="stat-num">99.8%</span>
            <span className="stat-tag">Threat Detection</span>
          </div>
          <div className="radar-stat">
            <span className="stat-num">Real-time</span>
            <span className="stat-tag">Geo IP Tracking</span>
          </div>
          <div className="radar-stat">
            <span className="stat-num">100%</span>
            <span className="stat-tag">Proof Anchored</span>
          </div>
        </div>
      </div>
    </div>
  );
}

window.RadarDashboard = RadarDashboard;
