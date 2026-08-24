"""
Aggregates rule findings into a single 0-100 cryptographic risk score and an
overall severity rating per session.
"""

from __future__ import annotations

from ecforensics.models.session import EmailSession, Severity
from ecforensics.risk_engine.rules import ALL_RULES

# Points deducted per finding, by severity. These starting values are a
# reasonable prior, not a validated scale -- tune them by comparing output
# against known-good and known-bad reference server configurations (e.g.
# servers already graded by testssl.sh or Qualys SSL Labs-style tooling).
_SEVERITY_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}

# Worst-to-best ordering used to pick a session's single headline severity.
_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def assess_session(session: EmailSession) -> EmailSession:
    """Run all rules against a session, attach findings, and set risk_score in place."""
    session.findings = [
        finding for rule in ALL_RULES
        if (finding := rule(session)) is not None
    ]
    score = 100
    for finding in session.findings:
        score -= _SEVERITY_PENALTY[finding.severity]
    session.risk_score = max(0, score)
    return session


def assess_sessions(sessions: list[EmailSession]) -> list[EmailSession]:
    """Batch convenience wrapper around assess_session."""
    return [assess_session(s) for s in sessions]


def overall_severity(session: EmailSession) -> Severity:
    """The single worst finding determines the session's headline severity."""
    if not session.findings:
        return Severity.INFO
    for severity in _SEVERITY_ORDER:
        if any(f.severity == severity for f in session.findings):
            return severity
    return Severity.INFO
