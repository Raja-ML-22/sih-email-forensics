"""
Digital Signature Module — SIH 2026, PS ID 26106, Team Tech Titans

Answers the PS requirement: "generation of structured forensic reports...
cryptographically signed, court-ready reports."

Design: we sign a canonical JSON representation of the report DATA (not
the final PDF bytes) with an RSA-2048 keypair. This avoids the circularity
problem of trying to sign a PDF that then has to contain its own
signature. The signature proves the underlying findings were not altered
after analysis — anyone with the public key can independently verify it,
which is the actual point of "chain of custody."

The private key is generated once and kept on the server; the public key
is safe to share/publish for independent verification.
"""

import os
import json
import base64
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

_KEY_DIR = os.path.dirname(os.path.abspath(__file__))
_PRIVATE_KEY_PATH = os.path.join(_KEY_DIR, "signing_private_key.pem")
_PUBLIC_KEY_PATH = os.path.join(_KEY_DIR, "signing_public_key.pem")


def _ensure_keypair():
    """Generates a 2048-bit RSA keypair on first run; reuses it after that
    so signatures stay verifiable across restarts."""
    if os.path.exists(_PRIVATE_KEY_PATH) and os.path.exists(_PUBLIC_KEY_PATH):
        return
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(_PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(_PUBLIC_KEY_PATH, "wb") as f:
        f.write(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))


def _load_private_key():
    _ensure_keypair()
    with open(_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def _load_public_key():
    _ensure_keypair()
    with open(_PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def canonicalize(report_core):
    """Deterministic JSON encoding so the same data always hashes the same
    way, regardless of dict ordering."""
    return json.dumps(report_core, sort_keys=True, default=str).encode("utf-8")


def _signable_core(report):
    """Pulls out just the factual findings to sign — not UI-only fields
    like correlation_backend's display string, so re-signing is stable."""
    return {
        "case_id": report.get("case_id"),
        "email_summary": report.get("email_summary"),
        "authentication_check": report.get("authentication_check"),
        "origin_trace": {
            "originating_ip": report.get("origin_trace", {}).get("originating_ip"),
            "reverse_dns": report.get("origin_trace", {}).get("reverse_dns"),
        },
        "threat_assessment": {
            "fraud_score": report.get("threat_assessment", {}).get("fraud_score"),
            "verdict": report.get("threat_assessment", {}).get("verdict"),
            "reasons": report.get("threat_assessment", {}).get("reasons"),
        },
        "domain_intelligence": report.get("domain_intelligence"),
    }


def sign_report(report):
    """Returns a signature block: hash, base64 signature, algorithm, and
    timestamp. Call this once per report and embed the result in the PDF
    and/or store it alongside the case record."""
    private_key = _load_private_key()
    core = _signable_core(report)
    data = canonicalize(core)
    digest = hashlib.sha256(data).hexdigest()

    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "sha256_hash": digest,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "algorithm": "RSA-2048 / PSS / SHA-256",
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_report(report, signature_block):
    """Independently verifies a report against a previously issued
    signature block. Returns True only if the underlying findings are
    byte-for-byte identical to what was originally signed."""
    public_key = _load_public_key()
    core = _signable_core(report)
    data = canonicalize(core)

    try:
        signature = base64.b64decode(signature_block["signature_b64"])
        public_key.verify(
            signature, data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        actual_hash = hashlib.sha256(data).hexdigest()
        return actual_hash == signature_block.get("sha256_hash")
    except Exception:
        return False


def get_public_key_pem():
    _ensure_keypair()
    with open(_PUBLIC_KEY_PATH, "r") as f:
        return f.read()


if __name__ == "__main__":
    # self-test: sign a fake report, verify it, then tamper and confirm it fails
    fake_report = {
        "case_id": "TEST123",
        "email_summary": {"from": "test@example.com", "subject": "Test"},
        "authentication_check": {"from_domain": "example.com"},
        "origin_trace": {"originating_ip": "1.2.3.4", "reverse_dns": None},
        "threat_assessment": {"fraud_score": 80, "verdict": "HIGH RISK", "reasons": ["test reason"]},
        "domain_intelligence": {},
    }
    sig = sign_report(fake_report)
    print("Signature block:", json.dumps(sig, indent=2)[:300], "...")
    print("Verify (should be True):", verify_report(fake_report, sig))

    tampered = dict(fake_report)
    tampered["threat_assessment"] = dict(fake_report["threat_assessment"])
    tampered["threat_assessment"]["fraud_score"] = 10
    print("Verify tampered data (should be False):", verify_report(tampered, sig))
