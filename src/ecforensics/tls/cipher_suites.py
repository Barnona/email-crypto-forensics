"""
Reference data for TLS version and cipher suite security classification.

This registry is what the risk engine (risk_engine/rules.py) checks negotiated
sessions against. Keep it in sync with current guidance -- e.g. Mozilla's TLS
configuration guidelines and NIST SP 800-52 Rev. 2.

TODO: this is a starter set, not exhaustive. Expand using the full IANA TLS
Cipher Suite Registry and re-derive the WEAK/DEPRECATED sets from an
authoritative, periodically-refreshed source rather than hand-maintaining
them indefinitely.
"""

from __future__ import annotations

# TLS protocol versions considered insecure/deprecated.
DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
RECOMMENDED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}

# Substrings in a cipher suite name that indicate a known weakness:
# export-grade, NULL/anonymous, RC4/DES/3DES ciphers, or MD5-based MACs.
WEAK_CIPHER_SUITE_PATTERNS = (
    "NULL", "EXPORT", "anon", "RC4", "DES", "3DES", "MD5",
)

# Key exchange mechanisms that provide (perfect) forward secrecy.
FORWARD_SECRECY_KEY_EXCHANGES = {"ECDHE", "DHE"}

# Minimum recommended key sizes, in bits.
MIN_RSA_KEY_SIZE_BITS = 2048
MIN_EC_KEY_SIZE_BITS = 224


def is_weak_cipher_suite(cipher_suite_name: str) -> bool:
    """Heuristic check against WEAK_CIPHER_SUITE_PATTERNS."""
    return any(pattern in cipher_suite_name for pattern in WEAK_CIPHER_SUITE_PATTERNS)


def provides_forward_secrecy(cipher_suite_name: str) -> bool:
    return any(kex in cipher_suite_name for kex in FORWARD_SECRECY_KEY_EXCHANGES)


def is_deprecated_version(tls_version: str) -> bool:
    return tls_version in DEPRECATED_TLS_VERSIONS
