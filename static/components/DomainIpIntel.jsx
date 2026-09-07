function DomainIpIntel({ domainIntel, ipIntel, geoIntel }) {
  if (!domainIntel || !ipIntel || !geoIntel) return null;

  return (
    <div className="section-card intel-card">
      <h3 className="card-heading">🌐 Domain & IP Threat Intelligence</h3>

      <div className="intel-grid">
        {/* Domain Intelligence Block */}
        <div className="intel-block">
          <div className="intel-header">
            <span className="intel-icon">🏷️</span> Domain Intelligence
          </div>
          <div className="intel-row">
            <span className="intel-label">Domain Name:</span>
            <span className="intel-val"><code>{domainIntel.domain_name}</code></span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Estimated Age:</span>
            <span className="intel-val">{domainIntel.domain_age_days} Days</span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Registrar:</span>
            <span className="intel-val">{domainIntel.registrar}</span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Reputation Rating:</span>
            <span className={`intel-val rating-${domainIntel.reputation_score > 70 ? 'good' : 'bad'}`}>
              {domainIntel.reputation} ({domainIntel.reputation_score}/100)
            </span>
          </div>
          {domainIntel.typosquatting_detected && (
            <div className="alert-box-warning">
              ⚠️ <strong>Spoofing Alert:</strong> Domain attempts to impersonate brand <strong>{domainIntel.spoofed_brand}</strong>.
            </div>
          )}
        </div>

        {/* IP Intelligence Block */}
        <div className="intel-block">
          <div className="intel-header">
            <span className="intel-icon">🖥️</span> IP Address Intelligence
          </div>
          <div className="intel-row">
            <span className="intel-label">Origin IP:</span>
            <span className="intel-val"><code>{ipIntel.ip_address}</code></span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Reverse DNS (PTR):</span>
            <span className="intel-val"><code>{ipIntel.reverse_dns}</code></span>
          </div>
          <div className="intel-row">
            <span className="intel-label">IP Reputation:</span>
            <span className="intel-val">{ipIntel.ip_reputation_score}/100</span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Multi-Blacklist Status:</span>
            <span className={`intel-val ${ipIntel.is_blacklisted ? 'status-bad' : 'status-good'}`}>
              {ipIntel.is_blacklisted ? `LISTED ON ${ipIntel.blacklists_hit.length} BLACKLISTS` : 'CLEAN / NOT BLACKLISTED'}
            </span>
          </div>
          {ipIntel.blacklists_hit && ipIntel.blacklists_hit.length > 0 && (
            <div className="blacklist-tags">
              {ipIntel.blacklists_hit.map((bl, i) => (
                <span key={i} className="bl-tag">🚫 {bl}</span>
              ))}
            </div>
          )}
        </div>

        {/* IP Geolocation Block displaying Approximate Location */}
        <div className="intel-block geo-block">
          <div className="intel-header">
            <span className="intel-icon">📍</span> Approximate Location & GeoIP Intelligence
          </div>
          
          <div className="geo-main-row">
            <span className="geo-flag">{geoIntel.flag_emoji}</span>
            <div>
              <div className="geo-location-title">{geoIntel.city}, {geoIntel.region ? geoIntel.region + ', ' : ''}{geoIntel.country} ({geoIntel.country_code})</div>
              <div className="geo-isp-text">ISP: {geoIntel.isp}</div>
            </div>
          </div>

          <div className="intel-row">
            <span className="intel-label">Approximate Location:</span>
            <span className="intel-val"><code>{geoIntel.city}, {geoIntel.country}</code></span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Geo Coordinates:</span>
            <span className="intel-val"><code>{geoIntel.latitude}, {geoIntel.longitude}</code></span>
          </div>
          <div className="intel-row">
            <span className="intel-label">Organization:</span>
            <span className="intel-val">{geoIntel.organization}</span>
          </div>

          {/* Embedded Map Visual Preview */}
          <div className="map-embed-box">
            <iframe 
              title="Approximate Location Map"
              src={geoIntel.embed_map_url || `https://maps.google.com/maps?q=${geoIntel.latitude},${geoIntel.longitude}&z=9&output=embed`} 
              className="map-iframe"
              loading="lazy"
            />
          </div>

          {/* Direct External Map Link */}
          <a 
            href={geoIntel.map_url || `https://www.google.com/maps?q=${geoIntel.latitude},${geoIntel.longitude}`} 
            target="_blank" 
            rel="noopener noreferrer" 
            className="btn-geo-map"
          >
            🗺️ View Approximate Location on Map ➔
          </a>
        </div>
      </div>
    </div>
  );
}

window.DomainIpIntel = DomainIpIntel;
