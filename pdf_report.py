"""
Forensic Report Generator — SIH 2026, PS ID 26106, Team Tech Titans

Turns an analysis report (dict from email_forensics.build_report) into a
downloadable PDF — a scoped-down version of the "structured forensic reports
for institutional action, legal review, cyber incident response" outcome
named in the problem statement.

Uses reportlab (pure Python, no external binaries/DLLs needed — chosen
deliberately to avoid the Windows dependency issues hit earlier tonight).
"""

import uuid
from datetime import datetime, timezone
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)


def _score_color(score):
    if score >= 60:
        return colors.HexColor("#c0392b")
    elif score >= 30:
        return colors.HexColor("#d68910")
    return colors.HexColor("#1e8449")


def generate_pdf_report(report, output_path):
    case_id = "FR-" + uuid.uuid4().hex[:10].upper()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle", parent=styles["Title"], fontSize=16, spaceAfter=4
    )
    section_style = ParagraphStyle(
        "SectionStyle", parent=styles["Heading2"], fontSize=12,
        spaceBefore=14, spaceAfter=6, textColor=colors.HexColor("#1b2a4a")
    )
    meta_style = ParagraphStyle(
        "MetaStyle", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#555555")
    )
    body_style = styles["Normal"]

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=20 * mm, bottomMargin=20 * mm,
        leftMargin=18 * mm, rightMargin=18 * mm,
    )
    elements = []

    elements.append(Paragraph("Email Forensic Intelligence Report", title_style))
    elements.append(Paragraph(
        "SIH 2026 · PS ID 26106 · Team Tech Titans (Prototype-stage report)",
        meta_style
    ))
    elements.append(Paragraph(f"Case ID: {case_id} &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {generated_at}", meta_style))
    elements.append(Spacer(1, 10))

    # ---- Threat Assessment (headline section) ----
    ta = report["threat_assessment"]
    score_col = _score_color(ta["fraud_score"])
    elements.append(Paragraph("Threat Assessment", section_style))
    score_table = Table(
        [["Fraud Score", f"{ta['fraud_score']} / 100"], ["Verdict", ta["verdict"]]],
        colWidths=[100, 300],
    )
    score_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f4f4")),
        ("TEXTCOLOR", (1, 0), (1, 1), score_col),
        ("FONTNAME", (1, 0), (1, 1), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    elements.append(score_table)
    elements.append(Spacer(1, 6))
    for reason in ta["reasons"]:
        elements.append(Paragraph(f"&bull; {reason}", body_style))

    # ---- Email Summary ----
    es = report["email_summary"]
    elements.append(Paragraph("Email Summary", section_style))
    _add_kv_table(elements, [
        ("From", es["from"]), ("Reply-To", es["reply_to"] or "—"),
        ("Subject", es["subject"]), ("Message-ID", es["message_id"]),
    ])

    # ---- Authentication ----
    ac = report["authentication_check"]
    elements.append(Paragraph("Authentication Check (SPF / DKIM / DMARC)", section_style))
    _add_kv_table(elements, [
        ("Sending Domain", ac.get("from_domain") or "—"),
        ("SPF", "VALID" if ac.get("spf", {}).get("found") else "MISSING"),
        ("DMARC", "VALID" if ac.get("dmarc", {}).get("found") else "MISSING"),
        ("DKIM Signature", "PRESENT" if ac.get("dkim_signature_present") else "ABSENT"),
    ])

    # ---- Domain Intelligence ----
    di = report.get("domain_intelligence", {})
    elements.append(Paragraph("Domain Intelligence", section_style))
    lookalike = di.get("lookalike")
    reg = di.get("registration", {})
    _add_kv_table(elements, [
        ("Lookalike Domain", f"Mimics {lookalike['impersonating']}" if lookalike else "None detected"),
        ("MX Records", ", ".join(di.get("mx_records", [])) or "None found"),
        ("Registration Date", (reg.get("registration_date") or "Unknown")[:10] if reg.get("available") else "Unavailable"),
        ("Registrar", reg.get("registrar") or "Unknown" if reg.get("available") else "Unavailable"),
    ])

    # ---- Mail Path Reconstruction ----
    elements.append(Paragraph("Mail Path Reconstruction", section_style))
    mail_path = report.get("mail_path", [])
    if mail_path:
        for i, hop in enumerate(mail_path, 1):
            loc = f"{hop.get('city')}, {hop.get('country')}" if hop.get("country") else "Geolocation unavailable"
            elements.append(Paragraph(
                f"Hop {i} — {hop['role']}: {hop['ip']}"
                f"{' (' + hop['reverse_dns'] + ')' if hop.get('reverse_dns') else ''} — {loc}"
                f"{' — ' + hop['isp'] if hop.get('isp') else ''}", body_style
            ))
    else:
        elements.append(Paragraph("No public IP hops found in the header chain.", body_style))

    # ---- Origin Attribution Confidence ----
    conf = report.get("attribution_confidence", {})
    elements.append(Paragraph("Origin Attribution Confidence", section_style))
    elements.append(Paragraph(f"<b>Confidence: {conf.get('confidence_percent', 0)}%</b>", body_style))
    for evidence_text, ok in conf.get("evidence", []):
        elements.append(Paragraph(f"{'&#10003;' if ok else '&#10007;'} {evidence_text}", body_style))

    # ---- Threat Actor Techniques ----
    elements.append(Paragraph("Threat Actor Techniques Observed", section_style))
    for technique, flagged in report.get("threat_techniques", {}).items():
        elements.append(Paragraph(f"{'&#10003;' if flagged else '&#10007;'} {technique}", body_style))

    # ---- IOCs ----
    iocs = report.get("iocs", {})
    elements.append(Paragraph("Indicators of Compromise (IOC)", section_style))
    _add_kv_table(elements, [
        ("Sender IP", iocs.get("sender_ip") or "—"),
        ("Sender Domain", iocs.get("sender_domain") or "—"),
        ("URLs in body", ", ".join(iocs.get("suspicious_urls", [])) or "None found"),
        ("Attachment Hash", "Not analyzed — attachments are out of scope for this prototype"),
    ])

    # ---- Origin & Geolocation ----
    ot = report["origin_trace"]
    geo = report["geolocation"]
    elements.append(Paragraph("Origin Trace & Geolocation", section_style))
    geo_rows = [("Originating IP", ot.get("originating_ip") or "Not found")]
    if geo.get("status") == "success":
        geo_rows += [
            ("Country", geo.get("country")),
            ("City / Region", f"{geo.get('city')}, {geo.get('regionName')}"),
            ("ISP / Org", geo.get("isp")),
            ("Proxy / TOR / VPN", "YES" if geo.get("proxy") else "No"),
            ("Hosting/Cloud IP", "YES" if geo.get("hosting") else "No"),
        ]
    else:
        geo_rows.append(("Geolocation", geo.get("error", "Unavailable")))
    _add_kv_table(elements, geo_rows)

    # ---- Campaign Correlation ----
    corr = report.get("campaign_correlation") or []
    elements.append(Paragraph("Campaign Correlation", section_style))
    if corr:
        for m in corr:
            elements.append(Paragraph(
                f"&bull; Shares {' + '.join(m['shared_on'])} with previous case: "
                f"\"{m['subject']}\" (analyzed {m['timestamp'][:19]})", body_style
            ))
    else:
        elements.append(Paragraph("No overlap with previously analyzed cases.", body_style))

    # ---- Recommended Actions ----
    elements.append(Paragraph("Recommended Actions", section_style))
    for action in report.get("recommended_actions", []):
        elements.append(Paragraph(f"&bull; {action}", body_style))

    # ---- Forensic Conclusion ----
    elements.append(Paragraph("Forensic Conclusion", section_style))
    elements.append(Paragraph(report.get("forensic_conclusion", ""), body_style))

    elements.append(Spacer(1, 16))
    elements.append(Paragraph(
        "Prototype scope note: this report is generated by a rule-based scoring engine "
        "standing in for the production NLP/BERT model; cross-case correlation uses a local "
        "case store standing in for the planned Neo4j graph-scale implementation. "
        "This is not a substitute for professional legal or security review.",
        meta_style
    ))

    doc.build(elements)
    return case_id


def _add_kv_table(elements, rows):
    cell_style = ParagraphStyle("KVCell", fontSize=9, leading=12)
    label_style = ParagraphStyle("KVLabel", fontSize=9, leading=12, fontName="Helvetica-Bold")
    data = [[Paragraph(str(k), label_style), Paragraph(str(v), cell_style)] for k, v in rows]
    t = Table(data, colWidths=[130, 340])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef1f8")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
        ("PADDING", (0, 0), (-1, -1), 5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 4))
