"""
Web dashboard for the Email Forensics Prototype — SIH 2026, PS ID 26106, Team Tech Titans

Wraps email_forensics.py (same engine, unchanged) in a Flask web UI so the demo
looks like an actual analyst dashboard instead of raw JSON in a terminal.

Run:  python app.py
Then open: http://127.0.0.1:5000 in your browser
"""

import os
import json
from flask import Flask, request, render_template_string, send_file

from email_forensics import build_report
from pdf_report import generate_pdf_report

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
REPORT_FOLDER = "reports"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

PAGE = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Email Forensic Intelligence Platform — Tech Titans</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script>
<script src="https://unpkg.com/leaflet-polylinedecorator@1.6.0/dist/leaflet.polylineDecorator.js"></script>
<style>
  * { box-sizing: border-box; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0f1420;
    color: #e6e9f0;
    margin: 0;
    padding: 0;
  }
  header {
    background: linear-gradient(90deg, #14213d, #1b2a4a);
    padding: 22px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 3px solid #2f7cff;
  }
  header h1 { font-size: 20px; margin: 0; }
  header span { color: #8fa2c7; font-size: 13px; }
  .container { max-width: 1000px; margin: 30px auto; padding: 0 20px; }
  .card {
    background: #161d2e;
    border: 1px solid #253150;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .card h2 {
    font-size: 15px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: #7ea0ff;
    margin-top: 0;
    border-bottom: 1px solid #253150;
    padding-bottom: 10px;
  }
  form { display: flex; gap: 12px; align-items: center; }
  input[type=file] {
    background: #0f1420; border: 1px dashed #3a4a75; padding: 10px;
    border-radius: 6px; color: #e6e9f0; flex: 1;
  }
  button {
    background: #2f7cff; color: white; border: none; padding: 12px 22px;
    border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 14px;
  }
  button:hover { background: #1c63e0; }
  .score-wrap { display: flex; align-items: center; gap: 30px; }
  .score-circle {
    width: 120px; height: 120px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    font-size: 30px; font-weight: 700; flex-shrink: 0;
    border: 6px solid {{ score_color }};
    color: {{ score_color }};
  }
  .verdict-badge {
    display: inline-block; padding: 6px 16px; border-radius: 20px;
    font-weight: 700; font-size: 13px; background: {{ score_color }}22;
    color: {{ score_color }}; border: 1px solid {{ score_color }};
  }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td { padding: 8px 4px; border-bottom: 1px solid #253150; vertical-align: top; }
  td.label { color: #8fa2c7; width: 180px; }
  ul.reasons { margin: 0; padding-left: 20px; }
  ul.reasons li { margin-bottom: 8px; line-height: 1.4; }
  .pass { color: #35d07f; font-weight: 600; }
  .fail { color: #ff5c5c; font-weight: 600; }
  .footer-note { color: #5d6b8f; font-size: 12px; text-align: center; margin-top: 10px; }
  #hop-map { height: 380px; border-radius: 8px; margin-top: 10px; }
  .leaflet-popup-content-wrapper { background: #161d2e; color: #e6e9f0; }
  .leaflet-popup-tip { background: #161d2e; }
  .map-legend { display: flex; gap: 18px; font-size: 12px; margin-top: 8px; color: #8fa2c7; }
  .map-legend span { display: inline-flex; align-items: center; gap: 6px; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; }
  .map-legend-box {
    background: rgba(22,29,46,0.92); color: #e6e9f0; padding: 10px 14px;
    border-radius: 6px; font-size: 12px; line-height: 1.8; box-shadow: 0 2px 8px rgba(0,0,0,0.4);
  }
  .map-legend-box i {
    display: inline-block; width: 10px; height: 10px; border-radius: 50%;
    margin-right: 6px; vertical-align: middle;
  }
  .graph-node {
    padding: 10px 18px; border-radius: 8px; color: white; font-weight: 600;
    white-space: nowrap; font-size: 13px; box-shadow: 0 2px 6px rgba(0,0,0,0.3);
  }
  .graph-edge-label {
    fill: #8fa2c7; font-size: 11px;
  }
  .ip-chip { display: inline-flex; align-items: center; gap: 8px; background: #0f1420; border: 1px solid #253150; border-radius: 6px; padding: 8px 12px; margin: 4px 6px 4px 0; font-size: 13px; }
  .ip-badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 10px; }
  .ip-badge.public { background: #1e8449; color: #d4f5e0; }
  .ip-badge.private { background: #555b6e; color: #d8d8d8; }
</style>
</head>
<body>
<header>
  <h1>🛡️ AI-Powered Email Threat Detection &amp; Forensic Intelligence Platform</h1>
  <span>PS ID 26106 &nbsp;•&nbsp; Team Tech Titans &nbsp;•&nbsp; SIH 2026</span>
</header>

<div class="container">

  <div class="card">
    <h2>Upload Email for Analysis</h2>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="emlfile" accept=".eml" required>
      <button type="submit">Analyze</button>
    </form>
  </div>

  {% if report %}

  <div class="card">
    <h2>Threat Assessment</h2>
    <div class="score-wrap">
      <div class="score-circle">{{ report.threat_assessment.fraud_score }}</div>
      <div>
        <div class="verdict-badge">{{ report.threat_assessment.verdict }}</div>
        <ul class="reasons" style="margin-top:14px;">
          {% for r in report.threat_assessment.reasons %}
            <li>{{ r }}</li>
          {% endfor %}
        </ul>
      </div>
    </div>
    <div style="margin-top:18px;">
      <a href="/download-report" style="text-decoration:none;">
        <button type="button">⬇ Download Forensic Report (PDF)</button>
      </a>
    </div>
  </div>

  <div class="card">
    <h2>Email Summary</h2>
    <table>
      <tr><td class="label">From</td><td>{{ report.email_summary.from }}</td></tr>
      <tr><td class="label">Reply-To</td><td>{{ report.email_summary.reply_to or "—" }}</td></tr>
      <tr><td class="label">Subject</td><td>{{ report.email_summary.subject }}</td></tr>
      <tr><td class="label">Message-ID</td><td>{{ report.email_summary.message_id }}</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Authentication Check (SPF / DKIM / DMARC)</h2>
    <table>
      <tr><td class="label">Sending Domain</td><td>{{ report.authentication_check.from_domain }}</td></tr>
      <tr><td class="label">SPF</td><td class="{{ 'pass' if report.authentication_check.spf.found else 'fail' }}">
        {{ "VALID" if report.authentication_check.spf.found else "MISSING / NOT FOUND" }}
      </td></tr>
      <tr><td class="label">DMARC</td><td class="{{ 'pass' if report.authentication_check.dmarc.found else 'fail' }}">
        {{ "VALID" if report.authentication_check.dmarc.found else "MISSING / NOT FOUND" }}
      </td></tr>
      <tr><td class="label">DKIM Signature</td><td class="{{ 'pass' if report.authentication_check.dkim_signature_present else 'fail' }}">
        {{ "PRESENT" if report.authentication_check.dkim_signature_present else "ABSENT" }}
      </td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Origin Attribution Confidence</h2>
    <table>
      <tr><td class="label">Confidence Score</td><td style="font-weight:700; color:{{ score_color }};">{{ report.attribution_confidence.confidence_percent }}%</td></tr>
    </table>
    <ul class="reasons" style="margin-top:10px;">
      {% for evidence_text, ok in report.attribution_confidence.evidence %}
        <li class="{{ 'pass' if ok else 'fail' }}">{{ "✓" if ok else "✗" }} {{ evidence_text }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>IP Addresses Found</h2>
    <div>
      {% for entry in report.origin_trace.all_ips_tagged %}
      <div class="ip-chip">
        {{ entry.ip }}
        <span class="ip-badge {{ 'public' if entry.tag == 'PUBLIC' else 'private' }}">{{ entry.tag }}</span>
      </div>
      {% endfor %}
      {% if not report.origin_trace.all_ips_tagged %}
        <p style="color:#8fa2c7;">No IP addresses found in header chain.</p>
      {% endif %}
    </div>
    <p class="footer-note" style="text-align:left; margin-top:8px;">Extracted from Received routing headers.</p>
  </div>

  <div class="card">
    <h2>Mail Path Reconstruction</h2>
    <div id="hop-map"></div>

    <h2 style="margin-top:20px;">Routing / IP Intelligence</h2>
    <table>
      <tr>
        <td class="label" style="font-weight:700;">Hop</td>
        <td style="font-weight:700;">IP</td>
        <td style="font-weight:700;">Country / City</td>
        <td style="font-weight:700;">ISP</td>
        <td style="font-weight:700;">ASN</td>
        <td style="font-weight:700;">Reverse DNS</td>
        <td style="font-weight:700;">Proxy/TOR/VPN</td>
        <td style="font-weight:700;">Hosting</td>
      </tr>
      {% for hop in report.mail_path %}
      <tr>
        <td class="label">{{ loop.index }} — {{ hop.role }}</td>
        <td>{{ hop.ip }}</td>
        <td>{{ hop.city ~ ", " ~ hop.country if hop.country else "Unavailable" }}</td>
        <td>{{ hop.isp or "Unavailable" }}</td>
        <td>{{ hop.asn or "Unavailable" }}</td>
        <td>{{ hop.reverse_dns or "Unavailable" }}</td>
        <td class="{{ 'fail' if hop.proxy else 'pass' if hop.proxy is not none else '' }}">
          {{ "YES" if hop.proxy else ("No" if hop.proxy is not none else "Unavailable") }}
        </td>
        <td class="{{ 'fail' if hop.hosting else 'pass' if hop.hosting is not none else '' }}">
          {{ "YES" if hop.hosting else ("No" if hop.hosting is not none else "Unavailable") }}
        </td>
      </tr>
      {% endfor %}
      {% if not report.mail_path %}
      <tr><td colspan="8">No public IP hops found in the header chain.</td></tr>
      {% endif %}
    </table>
    <p class="footer-note" style="text-align:left; margin-top:8px;">Total hops: {{ report.mail_path|length }}</p>
  </div>

  <div class="card">
    <h2>Threat Actor Techniques Observed</h2>
    <ul class="reasons">
      {% for technique, flagged in report.threat_techniques.items() %}
        <li class="{{ 'fail' if flagged else 'pass' }}">{{ "✓" if flagged else "✗" }} {{ technique }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>Indicators of Compromise (IOC)</h2>
    <table>
      <tr><td class="label">Sender IP</td><td>{{ report.iocs.sender_ip or "—" }}</td></tr>
      <tr><td class="label">Sender Domain</td><td>{{ report.iocs.sender_domain or "—" }}</td></tr>
      <tr><td class="label">URLs in body</td><td>
        {% if report.iocs.suspicious_urls %}{% for u in report.iocs.suspicious_urls %}{{ u }}<br>{% endfor %}{% else %}None found{% endif %}
      </td></tr>
      <tr><td class="label">Attachment Hash</td><td>Not analyzed — this prototype does not process attachments (see limitations)</td></tr>
    </table>
  </div>

  <div class="card">
    <h2>Recommended Actions</h2>
    <ul class="reasons">
      {% for action in report.recommended_actions %}
        <li>{{ action }}</li>
      {% endfor %}
    </ul>
  </div>

  <div class="card">
    <h2>Forensic Conclusion</h2>
    <p style="line-height:1.6;">{{ report.forensic_conclusion }}</p>
  </div>

  <div class="card">
    <h2>Campaign Correlation</h2>
    {% if report.campaign_correlation %}
    <table>
      {% for match in report.campaign_correlation %}
      <tr>
        <td class="label fail">Match found</td>
        <td>Shares {{ match.shared_on|join(' + ') }} with a previous email: "{{ match.subject }}" (analyzed {{ match.timestamp[:19] }})</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}
    <table><tr><td class="pass">No overlap with any previously analyzed email — appears to be a new, isolated case.</td></tr></table>
    {% endif %}
  </div>

  <div class="card">
    <h2>Fraud Campaign Intelligence</h2>
    <table>
      <tr><td class="label">Campaign ID</td><td>{{ report.campaign_graph.campaign_id }}</td></tr>
      <tr><td class="label">Campaign Match Score</td><td>{{ report.campaign_graph.match_score }}%</td></tr>
    </table>
    <p class="footer-note" style="text-align:left; margin-top:4px;">
      Match score reflects overlap (shared IP/domain) with previously analyzed cases — 0% means no prior case matched.
    </p>

    <h3 style="font-size:13px; color:#7ea0ff; margin-top:16px; text-transform:uppercase; letter-spacing:.05em;">Graph-Based Attribution</h3>
    <p class="footer-note" style="text-align:left;">Relationship view: Sender Domain ↔ Reply-To Domain / Origin IPs</p>
    <div id="graph-wrap" style="position:relative; height:280px; margin-top:10px;">
      <svg id="graph-svg" style="position:absolute; top:0; left:0; width:100%; height:100%; pointer-events:none;"></svg>
      <div style="position:relative; height:100%; display:flex; justify-content:space-between; align-items:center; padding:0 20px;">
        <div class="graph-node" id="node-sender" style="background:#1b3a5c;">{{ report.campaign_graph.sender_domain }}</div>
        <div style="display:flex; flex-direction:column; justify-content:space-around; height:100%; gap:10px;">
          <div class="graph-node graph-edge-target" data-label="Reply-To"
               style="background:{{ '#8a5a1c' if not report.email_summary.reply_to else '#1b3a5c' }};">
            {{ report.email_summary.reply_to.split('@')[-1].rstrip('>') if report.email_summary.reply_to else "No Reply-To domain" }}
          </div>
          {% for ip in report.campaign_graph.ips %}
          <div class="graph-node graph-edge-target" data-label="origin/routing" style="background:#1b5e3a;">{{ ip }}</div>
          {% endfor %}
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Domain Intelligence</h2>
    <table>
      {% if report.domain_intelligence.lookalike %}
      <tr><td class="label">Lookalike Domain</td><td class="fail">
        FLAGGED — mimics "{{ report.domain_intelligence.lookalike.impersonating }}" (edit distance {{ report.domain_intelligence.lookalike.edit_distance }})
      </td></tr>
      {% else %}
      <tr><td class="label">Lookalike Domain</td><td class="pass">No known brand impersonation detected</td></tr>
      {% endif %}
      <tr><td class="label">MX Records</td><td class="{{ 'pass' if report.domain_intelligence.mx_records else 'fail' }}">
        {{ report.domain_intelligence.mx_records|join(', ') if report.domain_intelligence.mx_records else "None found" }}
      </td></tr>
      {% if report.domain_intelligence.registration.available %}
      <tr><td class="label">Registration Date</td><td>{{ report.domain_intelligence.registration.registration_date or "Unknown" }}</td></tr>
      <tr><td class="label">Registrar</td><td>{{ report.domain_intelligence.registration.registrar or "Unknown" }}</td></tr>
      {% else %}
      <tr><td class="label">WHOIS/RDAP</td><td>Unavailable for this domain</td></tr>
      {% endif %}
    </table>
  </div>

  <div class="card">
    <h2>Origin Trace &amp; Geolocation</h2>
    <table>
      <tr><td class="label">Originating IP</td><td>{{ report.origin_trace.originating_ip or "Not found" }}</td></tr>
      {% if report.geolocation.status == "success" %}
      <tr><td class="label">Country</td><td>{{ report.geolocation.country }}</td></tr>
      <tr><td class="label">City / Region</td><td>{{ report.geolocation.city }}, {{ report.geolocation.regionName }}</td></tr>
      <tr><td class="label">ISP / Org</td><td>{{ report.geolocation.isp }}</td></tr>
      <tr><td class="label">Proxy / TOR / VPN</td><td class="{{ 'fail' if report.geolocation.proxy else 'pass' }}">
        {{ "YES — FLAGGED" if report.geolocation.proxy else "No" }}
      </td></tr>
      <tr><td class="label">Hosting/Cloud IP</td><td class="{{ 'fail' if report.geolocation.hosting else 'pass' }}">
        {{ "YES" if report.geolocation.hosting else "No" }}
      </td></tr>
      {% else %}
      <tr><td class="label">Geolocation</td><td class="fail">{{ report.geolocation.error }}</td></tr>
      {% endif %}
    </table>
  </div>

  {% endif %}

  <p class="footer-note">Prototype scope: rule-based scoring stands in for the production NLP/BERT model;
  Neo4j graph correlation is the planned phase-2 addition for multi-email campaign clustering.</p>

</div>

{% if report %}
<script>
(function() {
  var hops = {{ hops_json|safe }};
  var hopsWithCoords = hops.filter(function(h) { return h.lat !== null && h.lon !== null && h.lat !== undefined && h.lon !== undefined; });

  if (hopsWithCoords.length === 0) {
    document.getElementById('hop-map').innerHTML =
      '<div style="display:flex;align-items:center;justify-content:center;height:100%;color:#5d6b8f;">No geolocated hops available to plot (network/API unavailable for this run).</div>';
    return;
  }

  var map = L.map('hop-map');
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '&copy; OpenStreetMap contributors',
    maxZoom: 18
  }).addTo(map);

  var colors = { "Probable Origin": "#e74c3c", "Intermediate Relay": "#f1c40f", "Final Visible Mail Server": "#2ecc71" };
  var latlngs = [];

  hopsWithCoords.forEach(function(h) {
    var color = colors[h.role] || "#3498db";
    var marker = L.circleMarker([h.lat, h.lon], {
      radius: 8, color: color, fillColor: color, fillOpacity: 0.9, weight: 2
    }).addTo(map);
    marker.bindPopup(
      "<b>" + h.role + "</b><br>IP: " + h.ip +
      (h.reverse_dns ? "<br>Reverse DNS: " + h.reverse_dns : "") +
      (h.city ? "<br>" + h.city + ", " + h.country : "") +
      (h.isp ? "<br>ISP: " + h.isp : "") +
      (h.asn ? "<br>ASN: " + h.asn : "")
    );
    latlngs.push([h.lat, h.lon]);
  });

  if (latlngs.length > 1) {
    var line = L.polyline(latlngs, { color: "#2f7cff", weight: 3, opacity: 0.85 }).addTo(map);
    if (typeof L.polylineDecorator === "function") {
      L.polylineDecorator(line, {
        patterns: [
          { offset: 0, repeat: 30, symbol: L.Symbol.arrowHead({
              pixelSize: 10, polygon: false, pathOptions: { stroke: true, color: "#2f7cff", weight: 3 }
          }) }
        ]
      }).addTo(map);
    }
  }

  if (latlngs.length === 1) {
    map.setView(latlngs[0], 6);
  } else {
    map.fitBounds(latlngs, { padding: [30, 30] });
  }

  L.control.scale({ imperial: true, metric: false, position: "bottomleft" }).addTo(map);

  var legend = L.control({ position: "bottomleft" });
  legend.onAdd = function() {
    var div = L.DomUtil.create('div', 'map-legend-box');
    div.innerHTML =
      '<b>Email Routing Trace</b><br>' +
      '<span><i style="background:#e74c3c"></i> Probable Origin</span><br>' +
      '<span><i style="background:#f1c40f"></i> Intermediate Relay</span><br>' +
      '<span><i style="background:#2ecc71"></i> Final Visible Mail Server</span><br>' +
      '<span><i style="background:#2f7cff; height:2px; width:14px; border-radius:0;"></i> Routing Path</span>';
    return div;
  };
  legend.addTo(map);
})();
</script>

<script>
(function() {
  var wrap = document.getElementById('graph-wrap');
  var svg = document.getElementById('graph-svg');
  var sender = document.getElementById('node-sender');
  var targets = document.querySelectorAll('.graph-edge-target');
  if (!wrap || !svg || !sender || targets.length === 0) return;

  var wrapRect = wrap.getBoundingClientRect();
  var senderRect = sender.getBoundingClientRect();
  var sx = senderRect.right - wrapRect.left;
  var sy = senderRect.top + senderRect.height / 2 - wrapRect.top;

  var svgns = "http://www.w3.org/2000/svg";
  targets.forEach(function(t) {
    var r = t.getBoundingClientRect();
    var tx = r.left - wrapRect.left;
    var ty = r.top + r.height / 2 - wrapRect.top;

    var line = document.createElementNS(svgns, "line");
    line.setAttribute("x1", sx); line.setAttribute("y1", sy);
    line.setAttribute("x2", tx); line.setAttribute("y2", ty);
    line.setAttribute("stroke", "#3a4a75"); line.setAttribute("stroke-width", "1.5");
    svg.appendChild(line);

    var label = document.createElementNS(svgns, "text");
    label.setAttribute("x", (sx + tx) / 2);
    label.setAttribute("y", (sy + ty) / 2 - 6);
    label.setAttribute("class", "graph-edge-label");
    label.setAttribute("text-anchor", "middle");
    label.textContent = t.getAttribute("data-label");
    svg.appendChild(label);
  });
})();
</script>
{% endif %}

</body>
</html>
"""


def score_color(score):
    if score >= 60:
        return "#ff5c5c"
    elif score >= 30:
        return "#ffb020"
    return "#35d07f"


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    color = "#35d07f"
    hops_json = "[]"
    if request.method == "POST":
        f = request.files["emlfile"]
        path = os.path.join(UPLOAD_FOLDER, f.filename)
        f.save(path)
        report = build_report(path)
        color = score_color(report["threat_assessment"]["fraud_score"])
        app.config["LAST_REPORT"] = report
        hops_json = json.dumps(report.get("mail_path", []))
    return render_template_string(PAGE, report=report, score_color=color, hops_json=hops_json)


@app.route("/download-report")
def download_report():
    report = app.config.get("LAST_REPORT")
    if not report:
        return "No report available yet — analyze an email first.", 400
    out_path = os.path.join(REPORT_FOLDER, "forensic_report.pdf")
    case_id = generate_pdf_report(report, out_path)
    return send_file(out_path, as_attachment=True, download_name=f"{case_id}.pdf")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
