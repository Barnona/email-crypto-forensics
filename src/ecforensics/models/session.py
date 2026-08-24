"""
Core data models shared across the email cryptographic forensics pipeline.

These dataclasses are the contract between pipeline stages: ingestion produces
EmailSession objects, the TLS/certificate stages populate them, the risk engine
and ML layer attach findings and scores, and the reporting layer serializes them.
Changing a field here has ripple effects across nearly every other module --
treat this file as the schema it effectively is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EmailProtocol(str, Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class Certificate:
    """A parsed X.509 certificate extracted from a TLS handshake."""

    subject: str
    issuer: str
    serial_number: str
    not_before: datetime
    not_after: datetime
    public_key_algorithm: str
    key_size_bits: int
    signature_algorithm: str
    is_self_signed: bool = False
    is_expired: bool = False
    chain_valid: Optional[bool] = None  # None until validated against a trust store
    raw_der: Optional[bytes] = field(default=None, repr=False)

    # TODO(certificates/validator.py): populate is_expired / chain_valid via
    # cryptography.x509 + a trust store (certifi) at validation time.


@dataclass
class TLSSession:
    """Everything learned from parsing a single TLS handshake."""

    tls_version: str                 # e.g. "TLSv1.2", "TLSv1.0", "SSLv3"
    cipher_suite: str                # e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    key_exchange: Optional[str] = None
    forward_secrecy: bool = False
    sni_hostname: Optional[str] = None
    certificates: list[Certificate] = field(default_factory=list)
    handshake_duration_ms: Optional[float] = None

    # TODO(tls/handshake_parser.py): populate from the parsed ClientHello/
    # ServerHello/Certificate handshake messages. Note: for TLS 1.3 sessions,
    # `certificates` will be empty unless SSLKEYLOGFILE was captured alongside
    # the PCAP -- the Certificate message is encrypted in 1.3. Document this
    # as a known limitation rather than silently under-reporting.


@dataclass
class RiskFinding:
    """A single cryptographic weakness identified by the rule engine or ML layer."""

    rule_id: str
    severity: Severity
    category: str            # e.g. "TLS_VERSION", "CIPHER_SUITE", "CERTIFICATE"
    description: str
    recommendation: str
    source: str = "rule"     # "rule" or "ml"


@dataclass
class EmailSession:
    """A single reconstructed email protocol session (one TCP stream)."""

    session_id: str
    protocol: EmailProtocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_time: datetime
    end_time: Optional[datetime] = None
    starttls_offered: bool = False
    starttls_used: bool = False
    tls_session: Optional[TLSSession] = None
    findings: list[RiskFinding] = field(default_factory=list)
    risk_score: Optional[float] = None        # 0-100, from risk_engine.scorer
    ml_anomaly_score: Optional[float] = None  # from ml.anomaly_detector

    @property
    def is_encrypted(self) -> bool:
        return self.tls_session is not None

    # TODO: add to_dict()/from_dict() helpers once the reporting layer's exact
    # JSON schema is finalized (reporting/json_report.py currently uses
    # dataclasses.asdict() directly, which is fine until this needs custom
    # serialization logic beyond datetime handling).
