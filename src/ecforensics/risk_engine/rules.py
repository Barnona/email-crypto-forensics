from __future__ import annotations
from typing import Callable, Optional
from ecforensics.certificates import validator as certvalidator
from ecforensics.models.session import EmailSession, RiskFinding, Severity
from ecforensics.tls import cipher_suites as cs


def _finding(rule_id, severity, category, description, recommendation):
    return RiskFinding(rule_id, severity, category, description, recommendation)


def rule_no_encryption(session: EmailSession) -> Optional[RiskFinding]:
    if session.tls_session is not None or session.tls_attempted:
        return None
    if not session.capture_complete:
        return _finding("CRYPTO-000", Severity.INFO, "OBSERVABILITY",
                        f"TLS status could not be conclusively determined for {session.protocol.value}: the capture is incomplete.",
                        "Collect a complete session before concluding that the connection was plaintext.")
    return _finding("CRYPTO-001", Severity.CRITICAL, "ENCRYPTION",
                    f"{session.protocol.value} session on port {session.dst_port} carried no observed TLS encryption.",
                    "Enforce mandatory TLS or require STARTTLS before authentication and mail commands.")


def rule_deprecated_tls_version(session):
    if session.tls_session and cs.is_deprecated_version(session.tls_session.tls_version):
        return _finding("CRYPTO-002", Severity.HIGH, "TLS_VERSION", f"Negotiated {session.tls_session.tls_version}, which is deprecated.", "Disable TLS versions below 1.2; require TLS 1.2 or 1.3.")


def rule_weak_cipher_suite(session):
    if session.tls_session and cs.is_weak_cipher_suite(session.tls_session.cipher_suite):
        return _finding("CRYPTO-003", Severity.HIGH, "CIPHER_SUITE", f"Negotiated cipher suite {session.tls_session.cipher_suite} is considered weak.", "Exclude weak cipher suites from the server configuration.")


def rule_no_forward_secrecy(session):
    if session.tls_session and not session.tls_session.forward_secrecy:
        return _finding("CRYPTO-004", Severity.MEDIUM, "KEY_EXCHANGE", "Negotiated key exchange does not provide forward secrecy.", "Prefer ECDHE/DHE key exchange; TLS 1.3 provides ephemeral key exchange.")


def rule_expired_certificate(session):
    if session.tls_session:
        for cert in session.tls_session.certificates:
            if cert.is_expired:
                return _finding("CRYPTO-005", Severity.HIGH, "CERTIFICATE", f"Certificate for '{cert.subject}' expired on {cert.not_after}.", "Renew the certificate immediately.")


def rule_weak_certificate_key(session):
    if session.tls_session:
        for cert in session.tls_session.certificates:
            if not certvalidator.is_key_size_sufficient(cert.public_key_algorithm, cert.key_size_bits):
                return _finding("CRYPTO-008", Severity.HIGH, "CERTIFICATE", f"Certificate for '{cert.subject}' uses an insufficient {cert.public_key_algorithm} key ({cert.key_size_bits} bits).", "Reissue the certificate with a stronger key.")


def rule_self_signed_certificate(session):
    if session.tls_session:
        for cert in session.tls_session.certificates:
            if cert.is_self_signed:
                return _finding("CRYPTO-006", Severity.MEDIUM, "CERTIFICATE", f"Certificate for '{cert.subject}' is self-signed.", "Use a trusted CA or document an intentional private trust model.")


def rule_invalid_presented_chain(session):
    if session.tls_session and session.tls_session.certificates and all(c.chain_valid is False for c in session.tls_session.certificates):
        return _finding("CRYPTO-009", Severity.HIGH, "CERTIFICATE", "The presented certificate chain is cryptographically inconsistent or incomplete.", "Provide the correct leaf/intermediate chain and verify it against the intended trust model.")


def rule_starttls_offered_but_unused(session):
    if session.starttls_offered and not session.starttls_used and session.capture_complete:
        return _finding("CRYPTO-007", Severity.HIGH, "ENCRYPTION", "Server advertised STARTTLS but the observed session proceeded without upgrading.", "Require STARTTLS before authentication and mail commands.")


ALL_RULES: list[Callable[[EmailSession], Optional[RiskFinding]]] = [
    rule_no_encryption, rule_deprecated_tls_version, rule_weak_cipher_suite,
    rule_no_forward_secrecy, rule_expired_certificate, rule_weak_certificate_key,
    rule_self_signed_certificate, rule_invalid_presented_chain, rule_starttls_offered_but_unused,
]
