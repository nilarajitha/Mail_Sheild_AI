function BlockchainProof({ proofData, scanId }) {
  if (!proofData) return null;

  const handleDownloadReport = () => {
    window.open(`/api/report/download/${scanId}`, '_blank');
  };

  return (
    <div className="section-card blockchain-card">
      <div className="card-title-row">
        <h3 className="card-heading">
          ⛓️ Immutable Blockchain Evidence Verification
        </h3>
        <span className="chain-status-badge">
          ✓ ANCHORED & VERIFIED
        </span>
      </div>

      <div className="blockchain-grid">
        <div className="blockchain-info-col">
          <div className="proof-row">
            <span className="proof-label">Ledger Network:</span>
            <span className="proof-val">{proofData.blockchain_network}</span>
          </div>
          <div className="proof-row">
            <span className="proof-label">Block Height:</span>
            <span className="proof-val">#{proofData.block_height}</span>
          </div>
          <div className="proof-row">
            <span className="proof-label">Timestamp:</span>
            <span className="proof-val">{proofData.timestamp_iso}</span>
          </div>
          <div className="proof-row">
            <span className="proof-label">Transaction Hash (TxHash):</span>
            <span className="proof-hash"><code>{proofData.transaction_hash}</code></span>
          </div>
          <div className="proof-row">
            <span className="proof-label">Email SHA-256 Proof:</span>
            <span className="proof-hash"><code>{proofData.email_body_sha256}</code></span>
          </div>
        </div>

        <div className="blockchain-action-col">
          <div className="cert-preview-box">
            <div className="cert-icon">📜</div>
            <div className="cert-title">Digital Evidence Certificate</div>
            <div className="cert-sub">Cryptographically signed & timestamped</div>
          </div>
          
          <button 
            className="btn-download-forensic"
            onClick={handleDownloadReport}
          >
            📥 Download Forensic Audit Report (.JSON)
          </button>
        </div>
      </div>
    </div>
  );
}

window.BlockchainProof = BlockchainProof;
