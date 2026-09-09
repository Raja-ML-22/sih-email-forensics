# Email Forensics Prototype — SIH 2026 (PS ID 26106, Team Tech Titans)

Small-scale but REAL working slice of the full platform described in the idea deck.
No BERT/Neo4j/Rust yet — those are named as the production upgrade path (mention
this explicitly to judges, it shows you know the difference between prototype and
final scope).

## What actually works right now
1. Parses raw `.eml` files (headers, body, MIME structure)
2. Checks SPF and DMARC via REAL DNS TXT lookups against the sender's domain
3. Detects presence/absence of a DKIM signature
4. Walks the `Received:` header chain to find the first public (non-internal) IP
5. Geolocates that IP (country/city/ISP/proxy-flag) via a free API
6. Rule-based fraud scoring — flags urgency language, Reply-To vs From domain
   mismatch (classic BEC), suspicious TLDs, missing auth, proxy/hosting IPs
7. Outputs a structured JSON forensic report

## Setup (run this on your own laptop before the demo — needs real internet)
```bash
pip install dnspython requests
python3 email_forensics.py sample_phishing.eml
```

## For the demo
- Run it live on the sample phishing email — show the JSON report, especially
  the `fraud_score` and `reasons` list, that's your "wow" moment.
- Also grab one REAL legitimate email from your own inbox (save as .eml — in
  Gmail: open the email > 3-dot menu > "Show original" > download), run it
  through, and show the score comes out LOW. Judges love seeing it correctly
  NOT flag a clean email — proves it's not just crying wolf on everything.
- If asked "why not BERT right now" — answer: "Rule-based scoring is our
  MVP baseline for the prototype stage; the architecture is built so this
  scoring function is swappable — in production we'd replace `score_email()`
  with a fine-tuned BERT classifier trained on the Enron + PhishTank datasets
  we cited, without touching the parsing/auth/geo pipeline around it."
- If asked "why not Neo4j right now" — answer: "At prototype scale we're
  scoring one email at a time; graph correlation matters once you have
  volume — we'd persist each report's IP/domain/reply-chain into Neo4j and
  query for shared infrastructure across multiple flagged emails to reveal
  campaigns, which is phase 2."

## Files
- `email_forensics.py` — the full pipeline, heavily commented
- `sample_phishing.eml` — synthetic test case (BEC-style invoice fraud)
