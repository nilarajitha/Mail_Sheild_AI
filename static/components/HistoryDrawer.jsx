const { useState } = React;

function HistoryDrawer({ historyItems, onSelectHistoryItem, onDeleteHistoryItem, onClearAllHistory }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  const filteredHistory = (historyItems || []).filter(item => {
    const matchesSearch = 
      item.subject?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sender?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sender_ip?.includes(searchTerm);
    
    const matchesSeverity = filterSeverity === 'ALL' || item.severity === filterSeverity;

    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="section-card history-card">
      <div className="card-title-row">
        <h3 className="card-heading">
          📚 Persistent Scan History & Audit Logs ({historyItems?.length || 0})
        </h3>

        {historyItems && historyItems.length > 0 && (
          <button 
            className="btn-clear-history"
            onClick={onClearAllHistory}
          >
            🗑️ Clear All History
          </button>
        )}
      </div>

      {/* Search & Filter Toolbar */}
      <div className="history-toolbar">
        <input 
          type="text" 
          className="history-search-input"
          placeholder="🔎 Search history by subject, sender, or IP..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
        />

        <select 
          className="history-filter-select"
          value={filterSeverity}
          onChange={(e) => setFilterSeverity(e.target.value)}
        >
          <option value="ALL">All Threat Levels</option>
          <option value="CRITICAL">🔴 Critical</option>
          <option value="HIGH">🟠 High</option>
          <option value="MEDIUM">🟡 Medium</option>
          <option value="LOW">🔵 Low</option>
          <option value="CLEAN">🟢 Clean</option>
        </select>
      </div>

      {/* History Table */}
      {filteredHistory.length > 0 ? (
        <div className="history-table-wrapper">
          <table className="history-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Timestamp</th>
                <th>Subject</th>
                <th>Sender</th>
                <th>Threat Score</th>
                <th>SPF/DKIM</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((item) => (
                <tr key={item.id} className="history-tr">
                  <td><code>{item.id}</code></td>
                  <td>{item.timestamp}</td>
                  <td className="subject-cell">{item.subject}</td>
                  <td><code>{item.sender}</code></td>
                  <td>
                    <span className={`score-badge score-${item.severity?.toLowerCase()}`}>
                      {item.threat_score}% ({item.severity})
                    </span>
                  </td>
                  <td>
                    <span className="auth-mini">
                      SPF:{item.spf_status} | DKIM:{item.dkim_status}
                    </span>
                  </td>
                  <td>
                    <div className="action-btn-group">
                      <button 
                        className="btn-tbl-view"
                        onClick={() => onSelectHistoryItem(item.id)}
                      >
                        👁️ Inspect
                      </button>
                      <button 
                        className="btn-tbl-del"
                        onClick={() => onDeleteHistoryItem(item.id)}
                      >
                        ❌
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="empty-history">
          <p>No scan history records found matching your query.</p>
        </div>
      )}
    </div>
  );
}

window.HistoryDrawer = HistoryDrawer;
