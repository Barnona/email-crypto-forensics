from __future__ import annotations

from typing import Callable, Optional

from ecforensics.certificates import validator as certvalidator
from ecforensics.models.session import EmailSession, RiskFinding, Severity
from ecforensics.tls import cipher_suites as cs


def rule_no_encryption(session: EmailSession) -> Optional[RiskFinding]:
    if session.tls_session is None:
        return RiskFinding(
            rule_id="CRYPTO-001",
            severity=Severity.CRITICAL,
            category="ENCRYPTION",
            description=(
                f"{session.protocol.value} session on port {session.dst_port} "
                "carried no TLS encryption at any point (credentials and "
                "message content sent in cleartext)."
            ),
            recommendation=(
                "Enforce mandatory TLS -- either move the service to an "
                "implicit-TLS port or configure the server to require "
                "STARTTLS before accepting authentication/mail commands."
            ),
        )
    return None


def rule_deprecated_tls_version(session: EmailSession) -> Optional[RiskFinding]:
    if session.tls_session and cs.is_deprecated_version(session.tls_session.tls_version):
        return RiskFinding(
            rule_id="CRYPTO-002",
            severity=Severity.HIGH,
            category="TLS_VERSION",
            description=(
                f"Negotiated {session.tls_session.tls_version}, which is "
                "deprecated and vulnerable to known downgrade and protocol attacks."
            ),
            recommendation="Disable TLS versions below 1.2 on the server; require TLS 1.2 or 1.3 only.",
        )
    return None


def rule_weak_cipher_suite(session: EmailSession) -> Optional[RiskFinding]:
    if session.tls_session and cs.is_weak_cipher_suite(session.tls_session.cipher_suite):
        return RiskFinding(
            rule_id="CRYPTO-003",
            severity=Severity.HIGH,
            category="CIPHER_SUITE",
            description=(
                f"Negotiated cipher suite {session.tls_session.cipher_suite} is "
                "considered weak (export-grade, NULL, RC4/DES/3DES, or MD5-based)."
            ),
            recommendation="Reconfigure the server's cipher suite preference list to exclude weak ciphers.",
        )
    return None


def rule_no_forward_secrecy(session: EmailSession) -> Optional[RiskFinding]:
    if session.tls_session and not session.tls_session.forward_secrecy:
        return RiskFinding(
            rule_id="CRYPTO-004",
            severity=Severity.MEDIUM,
            category="KEY_EXCHANGE",
            description=(
                "Negotiated key exchange does not provide forward secrecy -- "
                "a compromised private key would expose all past traffic recorded under it."
            ),
            recommendation="Prefer ECDHE/DHE cipher suites over static RSA key exchange.",
        )
    return None


def rule_expired_certificate(session: EmailSession) -> Optional[RiskFinding]:
    if not session.tls_session:
        return None
    for cert in session.tls_session.certificates:
        if cert.is_expired:
            return RiskFinding(
                rule_id="CRYPTO-005",
                severity=Severity.HIGH,
                category="CERTIFICATE",
                description=f"Certificate for '{cert.subject}' expired on {cert.not_after}.",
                recommendation="Renew the certificate immediately.",
            )
    return None


def rule_weak_certificate_key(session: EmailSession) -> Optional[RiskFinding]:
    """Flags the first certificate in the chain with an insufficient key size."""
    if not session.tls_session:
        return None
    for cert in session.tls_session.certificates:
        if not certvalidator.is_key_size_sufficient(cert.public_key_algorithm, cert.key_size_bits):
            return RiskFinding(
                rule_id="CRYPTO-008",
                severity=Severity.HIGH,
                category="CERTIFICATE",
                description=(
                    f"Certificate for '{cert.subject}' uses a {cert.public_key_algorithm} "
                    f"key of only {cert.key_size_bits} bits, below the recommended minimum."
                ),
                recommendation=(
                    "Reissue the certificate with a stronger key -- at least 2048-bit RSA "
                    "or 224-bit EC."
                ),
            )
    return None


def rule_self_signed_certificate(session: EmailSession) -> Optional[RiskFinding]:
    if not session.tls_session:
        return None
    for cert in session.tls_session.certificates:
        if cert.is_self_signed:
            return RiskFinding(
                rule_id="CRYPTO-006",
                severity=Severity.MEDIUM,
                category="CERTIFICATE",
                description=f"Certificate for '{cert.subject}' is self-signed.",
                recommendation=(
                    "Issue a certificate from a trusted CA, or explicitly "
                    "document and pin this certificate if self-signed use is "
                    "intentional (e.g. an internal mail relay)."
                ),
            )
    return None


def rule_starttls_offered_but_unused(session: EmailSession) -> Optional[RiskFinding]:
    if session.starttls_offered and not session.starttls_used:
        return RiskFinding(
            rule_id="CRYPTO-007",
            severity=Severity.HIGH,
            category="ENCRYPTION",
            description=(
                "Server advertised STARTTLS support but the client session "
                "proceeded in plaintext anyway."
            ),
            recommendation=(
                "Enforce STARTTLS on the server -- reject AUTH/mail commands "
                "until TLS has been negotiated (many MTAs support a "
                "'require STARTTLS' setting for exactly this)."
            ),
        )
    return None


ALL_RULES: list[Callable[[EmailSession], Optional[RiskFinding]]] = [
    rule_no_encryption,
    rule_deprecated_tls_version,
    rule_weak_cipher_suite,
    rule_no_forward_secrecy,
    rule_expired_certificate,
    rule_weak_certificate_key,
    rule_self_signed_certificate,
    rule_starttls_offered_but_unused,
]
