"""
Neo4j Graph Correlation Module — SIH 2026, PS ID 26106, Team Tech Titans

Real graph-database backed campaign correlation, replacing the local JSON
store with actual Neo4j graph queries — directly answering the PS
requirement: "graph-based relationship analysis between sender domains,
IP addresses, aliases, reply chains, and linked infrastructure."

Design choice: this module is a drop-in replacement for
correlate_with_history() in email_forensics.py. If Neo4j credentials are
not configured (via environment variables), it automatically falls back
to the local JSON store so the app never breaks — this matters because
this sandbox cannot reach Neo4j Aura's servers to test the real
connection; that test has to happen on your machine.

Environment variables required for real Neo4j:
    NEO4J_URI       e.g. neo4j+s://xxxxxxxx.databases.neo4j.io
    NEO4J_USER      usually "neo4j"
    NEO4J_PASSWORD  the password Aura showed you once at creation
"""

import os
import json
from datetime import datetime

_driver = None
_NEO4J_AVAILABLE = None


def _get_driver():
    """Lazily creates and caches the Neo4j driver. Returns None if not
    configured or if the connection fails, so callers can fall back."""
    global _driver, _NEO4J_AVAILABLE
    if _NEO4J_AVAILABLE is not None:
        return _driver if _NEO4J_AVAILABLE else None

    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")

    if not (uri and user and password):
        _NEO4J_AVAILABLE = False
        return None

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        _driver = driver
        _NEO4J_AVAILABLE = True
        return _driver
    except Exception as e:
        print(f"[neo4j_graph] Could not connect to Neo4j, falling back to local store: {e}")
        _NEO4J_AVAILABLE = False
        return None


def is_neo4j_active():
    """Lets the UI honestly show which backend is actually in use."""
    return _get_driver() is not None


# ---------- REAL NEO4J PATH ----------

def _neo4j_record_and_correlate(ip, domain, subject):
    driver = _get_driver()
    matches = []
    with driver.session() as session:
        # Find prior emails sharing this IP or this domain
        result = session.run(
            """
            MATCH (e:Email)
            WHERE (e.ip = $ip AND $ip IS NOT NULL)
               OR (e.domain = $domain AND $domain IS NOT NULL)
            RETURN e.subject AS subject, e.timestamp AS timestamp,
                   e.ip AS ip, e.domain AS domain
            ORDER BY e.timestamp DESC
            LIMIT 20
            """,
            ip=ip, domain=domain,
        )
        for record in result:
            shared = []
            if ip and record["ip"] == ip:
                shared.append("originating IP")
            if domain and record["domain"] == domain:
                shared.append("sender domain")
            if shared:
                matches.append({
                    "subject": record["subject"],
                    "timestamp": record["timestamp"],
                    "shared_on": shared,
                })

        # Record the current case as a node, and link it to shared IP/domain nodes
        timestamp = datetime.utcnow().isoformat()
        session.run(
            """
            CREATE (e:Email {subject: $subject, ip: $ip, domain: $domain, timestamp: $timestamp})
            WITH e
            FOREACH (_ IN CASE WHEN $ip IS NOT NULL THEN [1] ELSE [] END |
                MERGE (ipNode:IP {address: $ip})
                MERGE (e)-[:ORIGINATES_FROM]->(ipNode)
            )
            FOREACH (_ IN CASE WHEN $domain IS NOT NULL THEN [1] ELSE [] END |
                MERGE (domNode:Domain {name: $domain})
                MERGE (e)-[:SENT_FROM_DOMAIN]->(domNode)
            )
            """,
            subject=subject, ip=ip, domain=domain, timestamp=timestamp,
        )
    return matches


# ---------- LOCAL JSON FALLBACK (unchanged behavior from before) ----------

CASE_HISTORY_FILE = "case_history.json"


def _load_case_history():
    if not os.path.exists(CASE_HISTORY_FILE):
        return []
    try:
        with open(CASE_HISTORY_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def _save_case_history(history):
    try:
        with open(CASE_HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception:
        pass


def _json_record_and_correlate(ip, domain, subject):
    history = _load_case_history()
    matches = []
    for case in history:
        shared = []
        if ip and case.get("ip") == ip:
            shared.append("originating IP")
        if domain and case.get("domain") == domain:
            shared.append("sender domain")
        if shared:
            matches.append({
                "subject": case.get("subject"),
                "timestamp": case.get("timestamp"),
                "shared_on": shared,
            })
    history.append({
        "ip": ip, "domain": domain, "subject": subject,
        "timestamp": datetime.utcnow().isoformat(),
    })
    _save_case_history(history)
    return matches


# ---------- PUBLIC ENTRY POINT (same signature as the old function) ----------

def correlate_with_history(ip, domain, subject):
    """Drop-in replacement for the old JSON-only correlate_with_history().
    Uses real Neo4j graph queries when configured; otherwise transparently
    falls back to the local JSON store so the app keeps working."""
    if is_neo4j_active():
        try:
            return _neo4j_record_and_correlate(ip, domain, subject)
        except Exception as e:
            print(f"[neo4j_graph] Query failed, falling back to local store: {e}")
    return _json_record_and_correlate(ip, domain, subject)


def backend_name():
    return "Neo4j (live graph database)" if is_neo4j_active() else "Local JSON store (Neo4j not configured)"
