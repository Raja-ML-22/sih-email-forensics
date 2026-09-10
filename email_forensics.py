"""
AI-Powered Email Threat Detection, GeoLocation and Forensic Intelligence Platform
Prototype (small-scale) — SIH 2026, PS ID 26106, Team Tech Titans

This is a scoped-down but REAL working version of the pipeline described in the
idea deck. It does not use BERT/Neo4j/Rust yet (those are the production upgrade
path) — it uses lightweight, honest equivalents so every step here actually runs:

  1. Email Parser        -> Python's built-in email library
  2. Auth Check           -> DNS TXT lookups for SPF/DMARC + DKIM signature presence
  3. Origin Extraction    -> Regex walk of Received: header chain, first external hop
  4. Geo & Attribution    -> Free IP geolocation API (ip-api.com)
  5. Threat Intelligence  -> Rule-based fraud scoring (stand-in for the NLP/BERT model)
  6. Report               -> Structured JSON "forensic report"

Run:  python3 email_forensics.py sample.eml
"""

import sys
import re
import json
import email
import ipaddress
from email import policy
from email.parser import BytesParser

import dns.resolver
import requests


# ---------- 1. EMAIL PARSER ----------

def parse_email(filepath):
    with open(filepath, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return {
        "from": str(msg.get("From", "")),
        "reply_to": str(msg.get("Reply-To", "")),
        "to": str(msg.get("To", "")),
        "subject": str(msg.get("Subject", "")),
        "received_headers": msg.get_all("Received", []),
        "dkim_signature_present": msg.get("DKIM-Signature") is not None,
        "message_id": str(msg.get("Message-ID", "")),
        "body": get_body_text(msg),
    }


def get_body_text(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    return part.get_content()
                except Exception:
                    return ""
    else:
        try:
            return msg.get_content()
        except Exception:
            return ""
    return ""


# ---------- 2. AUTH CHECK (SPF / DMARC / DKIM) ----------

def extract_domain(address_field):
    match = re.search(r"@([\w\.-]+)", address_field)
    return match.group(1).lower() if match else None


def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                return {"found": True, "record": txt}
        return {"found": False, "record": None}
    except Exception as e:
        return {"found": False, "error": str(e)}


def check_dmarc(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=DMARC1"):
                return {"found": True, "record": txt}
        return {"found": False, "record": None}
    except Exception as e:
        return {"found": False, "error": str(e)}


def run_auth_check(parsed):
    from_domain = extract_domain(parsed["from"])
    result = {"from_domain": from_domain}
    if from_domain:
        result["spf"] = check_spf(from_domain)
        result["dmarc"] = check_dmarc(from_domain)
    result["dkim_signature_present"] = parsed["dkim_signature_present"]
    return result


# ---------- 3. ORIGIN EXTRACTION ----------

IP_REGEX = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b"
)


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # treat unparsable as "skip"


def extract_originating_ip(received_headers):
    """
    Received headers are prepended by each hop, so the LAST header in the list
    (bottom of the chain, i.e. first line the message physically travelled) is
    closest to the true origin. We walk from the end and return the first
    public (non-private/non-internal) IP we find.
    """
    candidates = []
    for header in reversed(received_headers):
        ips = IP_REGEX.findall(str(header))
        for ip in ips:
            if not is_private_ip(ip):
                candidates.append(ip)
    return candidates[0] if candidates else None, candidates


# ---------- 4. GEO & ATTRIBUTION ----------

def geolocate_ip(ip):
    if not ip:
        return {"error": "no public IP found in header chain"}

    # Primary provider: ip-api.com
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting",
            timeout=5,
        )
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if data.get("status") == "success":
                return data
    except Exception:
        pass  # fall through to backup provider

    # Backup provider: ipwho.is (used if the primary is rate-limited or unreachable)
    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        if resp.status_code == 200 and resp.text.strip():
            data = resp.json()
            if data.get("success", True):
                return {
                    "status": "success",
                    "country": data.get("country"),
                    "regionName": data.get("region"),
                    "city": data.get("city"),
                    "isp": data.get("connection", {}).get("isp"),
                    "org": data.get("connection", {}).get("org"),
                    "as": data.get("connection", {}).get("asn"),
                    "proxy": data.get("security", {}).get("proxy", False),
                    "hosting": data.get("security", {}).get("hosting", False),
                }
    except Exception:
        pass

    return {"error": "Geolocation temporarily unavailable (provider rate-limit or network issue) — origin IP was still successfully extracted above."}


# ---------- 5. THREAT INTELLIGENCE (rule-based stand-in for the NLP/BERT model) ----------

URGENCY_WORDS = ["urgent", "immediately", "verify your account", "suspended",
                  "act now", "click here", "final notice", "wire transfer",
                  "confirm your password", "payment overdue", "invoice attached"]

SUSPICIOUS_TLDS = [".xyz", ".top", ".click", ".zip", ".gq", ".tk"]


def score_email(parsed, auth_result, geo_result):
    score = 0
    reasons = []

    body_lower = parsed["body"].lower()
    subject_lower = parsed["subject"].lower()

    for word in URGENCY_WORDS:
        if word in body_lower or word in subject_lower:
            score += 10
            reasons.append(f"Urgency/social-engineering phrase detected: '{word}'")

    from_domain = extract_domain(parsed["from"])
    reply_domain = extract_domain(parsed["reply_to"]) if parsed["reply_to"] else None
    if reply_domain and from_domain and reply_domain != from_domain:
        score += 25
        reasons.append(f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — classic BEC pattern")

    if from_domain and any(from_domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 15
        reasons.append(f"Sender domain uses a high-abuse TLD: {from_domain}")

    if auth_result.get("spf", {}).get("found") is False:
        score += 20
        reasons.append("No valid SPF record found for sending domain")
    if auth_result.get("dmarc", {}).get("found") is False:
        score += 15
        reasons.append("No DMARC policy published for sending domain")
    if not auth_result.get("dkim_signature_present"):
        score += 10
        reasons.append("No DKIM signature present on message")

    if isinstance(geo_result, dict) and geo_result.get("proxy"):
        score += 20
        reasons.append("Originating IP flagged as VPN/Proxy/TOR by geolocation provider")
    if isinstance(geo_result, dict) and geo_result.get("hosting"):
        score += 10
        reasons.append("Originating IP belongs to a hosting/cloud provider, not a residential/corporate ISP")

    score = min(score, 100)
    if score >= 60:
        verdict = "HIGH RISK — likely phishing/BEC"
    elif score >= 30:
        verdict = "SUSPICIOUS — needs analyst review"
    else:
        verdict = "LOW RISK"

    return {"fraud_score": score, "verdict": verdict, "reasons": reasons}


# ---------- 6. FORENSIC REPORT ----------

def build_report(filepath):
    parsed = parse_email(filepath)
    auth_result = run_auth_check(parsed)
    origin_ip, all_candidates = extract_originating_ip(parsed["received_headers"])
    geo_result = geolocate_ip(origin_ip)
    threat_result = score_email(parsed, auth_result, geo_result)

    report = {
        "email_summary": {
            "from": parsed["from"],
            "reply_to": parsed["reply_to"],
            "subject": parsed["subject"],
            "message_id": parsed["message_id"],
        },
        "authentication_check": auth_result,
        "origin_trace": {
            "originating_ip": origin_ip,
            "all_public_ip_candidates": all_candidates,
        },
        "geolocation": geo_result,
        "threat_assessment": threat_result,
    }
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 email_forensics.py <path_to_email.eml>")
        sys.exit(1)

    report = build_report(sys.argv[1])
    print(json.dumps(report, indent=2, default=str))
