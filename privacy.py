"""
Privacy & Retention Module — SIH 2026, PS ID 26106, Team Tech Titans

Answers the PS requirement: "controlled handling of personal data and
metadata... configurable retention and masking mechanisms for sensitive
communication data."

This does NOT alter the underlying analysis (fraud score, verdict,
evidence) — it only controls how much personal identifying detail is
shown in an exported report. This mirrors a real institutional policy
where the finding itself is preserved, but who-sent-it detail is
restricted based on role/retention rules.
"""

import re
import copy


def mask_email(address):
    """billing@paypa1-secure.xyz -> b*****@paypa1-secure.xyz"""
    if not address:
        return address
    match = re.search(r'([\w\.\-\+]+)@([\w\.\-]+)', address)
    if not match:
        return address
    local, domain = match.group(1), match.group(2)
    masked_local = local[0] + "*" * max(len(local) - 1, 3)
    return address.replace(f"{local}@{domain}", f"{masked_local}@{domain}")


def mask_ip(ip):
    """185.220.101.45 -> 185.220.101.xxx — keeps enough for network/ISP
    attribution (which is the forensically useful part) while dropping the
    exact host identifier."""
    if not ip or "." not in ip:
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        parts[-1] = "xxx"
        return ".".join(parts)
    return ip


def mask_domain_partial(domain):
    """Domains are needed for blocking/investigation, so we do NOT mask
    them — kept as a no-op for clarity and to document the decision."""
    return domain


def apply_privacy_mask(report):
    """Returns a deep-copied report with personal identifiers masked.
    The fraud score, verdict, evidence reasons, and all technical findings
    are left completely untouched — only the raw personal fields (email
    addresses, exact IP) are masked."""
    masked = copy.deepcopy(report)

    es = masked.get("email_summary", {})
    es["from"] = mask_email(es.get("from"))
    es["reply_to"] = mask_email(es.get("reply_to")) if es.get("reply_to") else es.get("reply_to")

    ot = masked.get("origin_trace", {})
    if ot.get("originating_ip"):
        ot["originating_ip"] = mask_ip(ot["originating_ip"])
    if ot.get("all_public_ip_candidates"):
        ot["all_public_ip_candidates"] = [mask_ip(ip) for ip in ot["all_public_ip_candidates"]]
    if ot.get("all_ips_tagged"):
        for tagged in ot["all_ips_tagged"]:
            tagged["ip"] = mask_ip(tagged.get("ip"))

    geo = masked.get("geolocation", {})
    # keep country/city/ISP (that's the forensic value) — nothing to mask here

    for hop in masked.get("mail_path", []):
        if hop.get("ip"):
            hop["ip"] = mask_ip(hop["ip"])

    iocs = masked.get("iocs", {})
    if iocs.get("sender_ip"):
        iocs["sender_ip"] = mask_ip(iocs["sender_ip"])

    cg = masked.get("campaign_graph", {})
    if cg.get("ips"):
        cg["ips"] = [mask_ip(ip) for ip in cg["ips"]]

    masked["_privacy_masked"] = True
    return masked


RETENTION_POLICY_TEXT = (
    "Data Retention & Masking Policy: Full technical findings (fraud score, verdict, "
    "authentication results, domain intelligence) are retained indefinitely for "
    "investigative continuity. Personal identifiers (exact sender address, exact "
    "originating IP) may be masked in exported reports per institutional privacy "
    "policy; masking does not affect the underlying case record used for campaign "
    "correlation. Configurable via the 'masked' report option."
)
