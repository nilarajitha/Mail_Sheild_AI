function AttackTrace({ attackTraceNodes }) {
  if (!attackTraceNodes || attackTraceNodes.length === 0) return null;

  return (
    <div className="section-card attack-trace-card">
      <h3 className="card-heading">⚡ Attack Trace & Transport Hop Graph</h3>
      <p className="card-sub-text">Visualizing email relay route from source sender client to destination inbox</p>

      <div className="attack-nodes-flow">
        {attackTraceNodes.map((node, index) => (
          <React.Fragment key={index}>
            <div className={`node-box node-status-${node.status.toLowerCase()}`}>
              <div className="node-step-pill">Step {node.step}</div>
              <div className="node-title">{node.node_name}</div>
              <div className="node-ip">IP: <code>{node.ip}</code></div>
              <div className="node-details">{node.details}</div>
              <div className="node-footer">
                <span className="node-latency">⏱️ {node.latency_ms} ms</span>
                <span className={`node-badge status-${node.status.toLowerCase()}`}>{node.status}</span>
              </div>
            </div>

            {index < attackTraceNodes.length - 1 && (
              <div className="flow-arrow-container">
                <div className="flow-line"></div>
                <div className="flow-arrow">➔</div>
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
    </div>
  );
}

window.AttackTrace = AttackTrace;
