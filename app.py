"""
Web dashboard for the Email Forensics Prototype — SIH 2026, PS ID 26106, Team Tech Titans

Wraps email_forensics.py (same engine, unchanged) in a Flask web UI so the demo
looks like an actual analyst dashboard instead of raw JSON in a terminal.

Run:  python app.py
Then open: http://127.0.0.1:5000 in your browser
"""

import os
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
    last_eml_path = None
    if request.method == "POST":
        f = request.files["emlfile"]
        path = os.path.join(UPLOAD_FOLDER, f.filename)
        f.save(path)
        report = build_report(path)
        color = score_color(report["threat_assessment"]["fraud_score"])
        last_eml_path = path
        app.config["LAST_REPORT"] = report
    return render_template_string(PAGE, report=report, score_color=color)


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
