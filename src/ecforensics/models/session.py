"""Core data models shared across the SecureMailScope pipeline."""
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
    chain_valid: Optional[bool] = None
    raw_der: Optional[bytes] = field(default=None, repr=False)


@dataclass
class TLSSession:
    tls_version: str
    cipher_suite: str
    key_exchange: Optional[str] = None
    forward_secrecy: bool = False
    sni_hostname: Optional[str] = None
    certificates: list[Certificate] = field(default_factory=list)
    handshake_duration_ms: Optional[float] = None


@dataclass
class RiskFinding:
    rule_id: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    source: str = "rule"


@dataclass
class EmailSession:
    """One observed email-protocol TCP session.

    ``tls_session is None`` means TLS details were not reconstructed; it does
    not by itself prove plaintext. ``tls_attempted`` and ``capture_complete``
    preserve that distinction for forensic decisions.
    """
    session_id: str
    protocol: EmailProtocol
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_time: datetime
    end_time: Optional[datetime] = None
    capture_complete: bool = True
    starttls_offered: bool = False
    starttls_used: bool = False
    tls_attempted: bool = False
    tls_session: Optional[TLSSession] = None
    analysis_notes: list[str] = field(default_factory=list)
    findings: list[RiskFinding] = field(default_factory=list)
    risk_score: Optional[float] = None
    ml_risk_class: Optional[str] = None
    ml_anomaly_score: Optional[float] = None

    @property
    def is_encrypted(self) -> bool:
        return self.tls_session is not None
