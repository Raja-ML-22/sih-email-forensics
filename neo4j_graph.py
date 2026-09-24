"""
Neo4j Graph Correlation Module — SIH 2026, PS ID 26106, Team Tech Titans

Real graph-database backed campaign correlation. Falls back automatically
to a local JSON store if Neo4j credentials aren't configured or the
connection fails, so the app never breaks because of this dependency.

Required environment variables for real Neo4j:
    NEO4J_URI       e.g. neo4j+s://xxxxxxxx.databases.neo4j.io
    NEO4J_USER      the Aura-generated username
    NEO4J_PASSWORD  the Aura-generated password

IMPORTANT for deployment: environment variables set on your LOCAL machine
(via setx) do NOT carry over to a cloud host like Render. If deploying,
these three variables must be set again in that platform's own
Environment Variables settings.
"""

import os
import json
from datetime import datetime

_driver = None
_neo4j_available = None
_connect_error = None


def _get_driver():
    global _driver, _neo4j_available, _connect_error
    if _neo4j_available is not None:
        return _driver if _neo4j_available else None

    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")

    if not (uri and user and password):
        _neo4j_available = False
        _connect_error = "NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD not all set in environment"
        return None

    try:
        from neo4j import GraphDatabase
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
        _driver = driver
        _neo4j_available = True
        return _driver
    except Exception as e:
        _connect_error = str(e)
        _neo4j_available = False
        return None


def is_neo4j_active():
    return _get_driver() is not None


def connection_error():
    _get_driver()
    return _connect_error


def _neo4j_record_and_correlate(ip, domain, subject):
    driver = _get_driver()
    matches = []
    with driver.session() as session:
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
                matches.append({"subject": record["subject"], "timestamp": record["timestamp"], "shared_on": shared})

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


CASE_HISTORY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "case_history.json")


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
            matches.append({"subject": case.get("subject"), "timestamp": case.get("timestamp"), "shared_on": shared})
    history.append({"ip": ip, "domain": domain, "subject": subject, "timestamp": datetime.utcnow().isoformat()})
    _save_case_history(history)
    return matches


def correlate_with_history(ip, domain, subject):
    if is_neo4j_active():
        try:
            return _neo4j_record_and_correlate(ip, domain, subject)
        except Exception:
            pass  # fall through to JSON so a mid-session Neo4j hiccup doesn't crash the app
    return _json_record_and_correlate(ip, domain, subject)


def backend_name():
    return "Neo4j (live graph database)" if is_neo4j_active() else "Local JSON store (Neo4j not configured)"
