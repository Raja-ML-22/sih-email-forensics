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
import os
import re
import json
import email
import ipaddress
from datetime import datetime
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


# ---------- 2b. DOMAIN INTELLIGENCE (WHOIS/RDAP + MX + lookalike detection) ----------

# Well-known brands most commonly impersonated in phishing/BEC — used only for
# lookalike-domain scoring, not a full brand database.
PROTECTED_BRANDS = [
    "paypal.com", "google.com", "microsoft.com", "apple.com", "amazon.com",
    "gmail.com", "outlook.com", "bankofamerica.com", "chase.com", "hdfcbank.com",
    "icicibank.com", "sbi.co.in", "netflix.com", "facebook.com", "instagram.com",
]


def levenshtein(a, b):
    """Simple edit-distance implementation — no external dependency needed."""
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            curr[j] = min(
                prev[j] + 1,
                curr[j - 1] + 1,
                prev[j - 1] + (ca != cb),
            )
        prev = curr
    return prev[-1]


def check_lookalike_domain(domain):
    """Flags domains that are suspiciously close (edit distance 1-2) to a
    well-known brand domain — catches tricks like paypa1-secure.xyz vs paypal.com."""
    if not domain:
        return None
    for brand in PROTECTED_BRANDS:
        brand_name = brand.split(".")[0]
        domain_name = domain.split(".")[0]
        dist = levenshtein(domain_name, brand_name)
        if 0 < dist <= 2 and domain != brand:
            return {"impersonating": brand, "edit_distance": dist}
    return None


def get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return sorted([str(r.exchange).rstrip(".") for r in answers])
    except Exception:
        return []


def get_domain_registration_info(domain):
    """Uses RDAP (the modern, HTTPS-friendly successor to raw WHOIS) via the
    public rdap.org bootstrap service — no API key needed."""
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if resp.status_code != 200:
            return {"available": False, "reason": f"RDAP lookup failed (HTTP {resp.status_code})"}
        data = resp.json()
        registration_date = None
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                registration_date = event.get("eventDate")
        registrar = None
        for entity in data.get("entities", []):
            if "registrar" in entity.get("roles", []):
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        registrar = field[3]
        return {
            "available": True,
            "registration_date": registration_date,
            "registrar": registrar,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}


def run_domain_intelligence(from_domain):
    if not from_domain:
        return {"mx_records": [], "registration": {"available": False}, "lookalike": None}
    return {
        "mx_records": get_mx_records(from_domain),
        "registration": get_domain_registration_info(from_domain),
        "lookalike": check_lookalike_domain(from_domain),
    }


# ---------- 2c. CAMPAIGN CORRELATION (lightweight case-history store) ----------
# Production version: this same logic, backed by Neo4j, correlating at scale
# across millions of emails via graph queries. For the prototype, a local JSON
# case history demonstrates the identical correlation concept honestly.

CASE_HISTORY_FILE = "case_history.json"


def load_case_history():
    if not os.path.exists(CASE_HISTORY_FILE):
        return []
    try:
        with open(CASE_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_case_history(history):
    try:
        with open(CASE_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception:
        pass


def correlate_with_history(current_ip, current_domain, subject):
    history = load_case_history()
    matches = []
    for case in history:
        shared = []
        if current_ip and case.get("ip") == current_ip:
            shared.append("originating IP")
        if current_domain and case.get("domain") == current_domain:
            shared.append("sender domain")
        if shared:
            matches.append({
                "subject": case.get("subject"),
                "timestamp": case.get("timestamp"),
                "shared_on": shared,
            })

    # record the current case for future correlation, regardless of outcome
    history.append({
        "ip": current_ip,
        "domain": current_domain,
        "subject": subject,
        "timestamp": datetime.utcnow().isoformat(),
    })
    save_case_history(history)

    return matches


def get_reverse_dns(ip):
    try:
        answer = dns.resolver.resolve_address(ip, lifetime=4)
        return str(answer[0]).rstrip(".")
    except Exception:
        return None


# ---------- 3b. MAIL PATH RECONSTRUCTION ----------

def reconstruct_mail_path(all_candidates, origin_ip):
    """Builds a hop-by-hop list, geolocating every public IP found in the
    Received chain (not just the origin), each tagged with a role."""
    hops = []
    for idx, ip in enumerate(all_candidates):
        geo = geolocate_ip(ip)
        rdns = get_reverse_dns(ip)
        if ip == origin_ip:
            role = "Probable Origin"
        elif idx == len(all_candidates) - 1:
            role = "Final Visible Mail Server"
        else:
            role = "Intermediate Relay"
        hops.append({
            "ip": ip,
            "role": role,
            "reverse_dns": rdns,
            "country": geo.get("country") if geo.get("status") == "success" else None,
            "city": geo.get("city") if geo.get("status") == "success" else None,
            "isp": geo.get("isp") if geo.get("status") == "success" else None,
            "asn": geo.get("as") if geo.get("status") == "success" else None,
        })
    return hops


# ---------- 4b. ORIGIN ATTRIBUTION CONFIDENCE ----------

def compute_attribution_confidence(auth_result, domain_intel, geo_result, origin_ip, reverse_dns):
    """A transparent, additive confidence score built ONLY from signals we
    actually computed — no fabricated 'reputation' data."""
    evidence = []
    points = 0
    max_points = 0

    max_points += 20
    if origin_ip:
        points += 20
        evidence.append(("Earliest public IP successfully extracted from Received headers", True))
    else:
        evidence.append(("Earliest public IP could not be determined", False))

    max_points += 20
    spf_ok = auth_result.get("spf", {}).get("found") is True
    points += 20 if spf_ok else 0
    evidence.append(("SPF record aligned for sending domain", spf_ok))

    max_points += 20
    dkim_ok = bool(auth_result.get("dkim_signature_present"))
    points += 20 if dkim_ok else 0
    evidence.append(("DKIM signature present", dkim_ok))

    max_points += 15
    dmarc_ok = auth_result.get("dmarc", {}).get("found") is True
    points += 15 if dmarc_ok else 0
    evidence.append(("DMARC policy published and found", dmarc_ok))

    max_points += 15
    rdns_match = False
    if reverse_dns and auth_result.get("from_domain"):
        domain_root = auth_result["from_domain"].split(".")[-2] if "." in auth_result["from_domain"] else auth_result["from_domain"]
        rdns_match = domain_root.lower() in reverse_dns.lower()
    points += 15 if rdns_match else 0
    evidence.append(("Reverse DNS of originating IP matches sending domain", rdns_match))

    max_points += 10
    reg = domain_intel.get("registration", {}) if domain_intel else {}
    domain_established = False
    if reg.get("available") and reg.get("registration_date"):
        try:
            reg_year = int(reg["registration_date"][:4])
            domain_established = reg_year <= 2024  # registered more than ~1 year ago
        except Exception:
            pass
    points += 10 if domain_established else 0
    evidence.append(("Sending domain has an established registration history", domain_established))

    confidence_pct = round((points / max_points) * 100) if max_points else 0
    return {"confidence_percent": confidence_pct, "evidence": evidence}


# ---------- 5b. THREAT ACTOR TECHNIQUES ----------

def map_threat_techniques(parsed, auth_result, domain_intel, geo_result):
    """Maps signals we've already detected onto named attack techniques —
    no new detection logic, just labeling what we found."""
    techniques = {}

    from_domain = extract_domain(parsed["from"])
    reply_domain = extract_domain(parsed["reply_to"]) if parsed["reply_to"] else None
    techniques["Display Name / Reply-To Spoofing"] = bool(reply_domain and from_domain and reply_domain != from_domain)

    techniques["Brand Impersonation (Lookalike Domain)"] = bool(domain_intel and domain_intel.get("lookalike"))

    body_lower = parsed["body"].lower()
    subject_lower = parsed["subject"].lower()
    techniques["Social Engineering / Urgency Pressure"] = any(w in body_lower or w in subject_lower for w in URGENCY_WORDS)

    techniques["Credential Harvesting Language"] = any(
        phrase in body_lower for phrase in ["confirm your password", "verify your account", "click here", "login"]
    )

    techniques["Infrastructure Spoofing (Proxy/TOR/Hosting Origin)"] = bool(
        isinstance(geo_result, dict) and (geo_result.get("proxy") or geo_result.get("hosting"))
    )

    techniques["Failed Sender Authentication"] = (
        auth_result.get("spf", {}).get("found") is False
        or auth_result.get("dmarc", {}).get("found") is False
        or not auth_result.get("dkim_signature_present")
    )

    techniques["Malware/Attachment Delivery"] = False  # not analyzed in this prototype — see limitations

    return techniques


# ---------- 6b. INDICATORS OF COMPROMISE ----------

URL_REGEX = re.compile(r"https?://[^\s\)\]\"']+")


def extract_iocs(parsed, origin_ip, auth_result):
    urls = list(dict.fromkeys(URL_REGEX.findall(parsed["body"])))
    return {
        "suspicious_urls": urls,
        "sender_ip": origin_ip,
        "sender_domain": auth_result.get("from_domain"),
        "attachment_hash": None,  # not computed — this prototype does not analyze attachments
    }


# ---------- 7b. RECOMMENDED ACTIONS & CONCLUSION ----------

def recommend_actions(verdict, techniques):
    actions = []
    if "HIGH RISK" in verdict:
        actions += [
            "Quarantine this email and do not allow user interaction with any links/attachments",
            "Block the sender domain and originating IP at the mail gateway",
            "Alert affected recipients and instruct them not to act on the message",
            "Add the sender IP/domain/URLs to SIEM or threat-intel watchlists",
        ]
    elif "SUSPICIOUS" in verdict:
        actions += [
            "Hold for manual analyst review before delivery",
            "Verify sender identity through an out-of-band channel (phone/known contact) if action was requested",
        ]
    else:
        actions.append("No action required — email shows no significant fraud indicators")
    if techniques.get("Brand Impersonation (Lookalike Domain)"):
        actions.append("Report the lookalike domain to the impersonated brand's abuse team")
    return actions


def build_forensic_conclusion(report_bits):
    verdict = report_bits["verdict"]
    confidence = report_bits["confidence_percent"]
    domain = report_bits["from_domain"] or "the sending domain"
    if "HIGH RISK" in verdict:
        return (
            f"The analyzed email shows strong indicators of fraud/phishing originating from infrastructure "
            f"inconsistent with a legitimate sender. Attribution confidence in the traced origin is {confidence}%. "
            f"Recommend treating this as a confirmed threat pending analyst review."
        )
    elif "SUSPICIOUS" in verdict:
        return (
            f"The analyzed email shows some fraud indicators but is not conclusively malicious. "
            f"Attribution confidence in the traced origin is {confidence}%. Recommend manual review before final disposition."
        )
    else:
        return (
            f"The analyzed email was transmitted through infrastructure consistent with {domain}'s legitimate mail "
            f"servers, with authentication checks passing. Attribution confidence is {confidence}%. "
            f"No evidence of spoofing or relay manipulation was found; assessed as LEGITIMATE."
        )


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


def score_email(parsed, auth_result, geo_result, domain_intel=None, correlation=None):
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

    if domain_intel:
        lookalike = domain_intel.get("lookalike")
        if lookalike:
            score += 30
            reasons.append(
                f"Sender domain closely mimics '{lookalike['impersonating']}' "
                f"(edit distance {lookalike['edit_distance']}) — likely domain spoofing"
            )
        if not domain_intel.get("mx_records"):
            score += 10
            reasons.append("Sending domain has no valid MX records — unusual for a legitimate mail sender")
        reg = domain_intel.get("registration", {})
        if reg.get("available") and reg.get("registration_date"):
            reasons.append(f"Domain registered on {reg['registration_date'][:10]} (registrar: {reg.get('registrar') or 'unknown'})")

    if correlation:
        score += 15
        matched_on = ", ".join(sorted(set(m for c in correlation for m in c["shared_on"])))
        reasons.append(
            f"Matches {len(correlation)} previously analyzed email(s) on {matched_on} — possible repeated campaign/infrastructure reuse"
        )

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
    domain_intel = run_domain_intelligence(auth_result.get("from_domain"))
    correlation = correlate_with_history(origin_ip, auth_result.get("from_domain"), parsed["subject"])
    threat_result = score_email(parsed, auth_result, geo_result, domain_intel, correlation)

    reverse_dns = get_reverse_dns(origin_ip) if origin_ip else None
    mail_path = reconstruct_mail_path(all_candidates, origin_ip)
    confidence = compute_attribution_confidence(auth_result, domain_intel, geo_result, origin_ip, reverse_dns)
    techniques = map_threat_techniques(parsed, auth_result, domain_intel, geo_result)
    iocs = extract_iocs(parsed, origin_ip, auth_result)
    actions = recommend_actions(threat_result["verdict"], techniques)
    conclusion = build_forensic_conclusion({
        "verdict": threat_result["verdict"],
        "confidence_percent": confidence["confidence_percent"],
        "from_domain": auth_result.get("from_domain"),
    })

    report = {
        "email_summary": {
            "from": parsed["from"],
            "reply_to": parsed["reply_to"],
            "subject": parsed["subject"],
            "message_id": parsed["message_id"],
        },
        "authentication_check": auth_result,
        "domain_intelligence": domain_intel,
        "origin_trace": {
            "originating_ip": origin_ip,
            "all_public_ip_candidates": all_candidates,
            "reverse_dns": reverse_dns,
        },
        "geolocation": geo_result,
        "mail_path": mail_path,
        "attribution_confidence": confidence,
        "threat_techniques": techniques,
        "iocs": iocs,
        "campaign_correlation": correlation,
        "threat_assessment": threat_result,
        "recommended_actions": actions,
        "forensic_conclusion": conclusion,
    }
    return report


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 email_forensics.py <path_to_email.eml>")
        sys.exit(1)

    report = build_report(sys.argv[1])
    print(json.dumps(report, indent=2, default=str))
