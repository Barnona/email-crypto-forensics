"""Reference data for TLS version and cipher suite security classification."""
from __future__ import annotations

DEPRECATED_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
RECOMMENDED_TLS_VERSIONS = {"TLSv1.2", "TLSv1.3"}
WEAK_CIPHER_SUITE_PATTERNS = (
    "NULL", "EXPORT", "anon", "RC4", "DES", "3DES", "MD5",
)
FORWARD_SECRECY_KEY_EXCHANGES = {"ECDHE", "DHE"}
MIN_RSA_KEY_SIZE_BITS = 2048
MIN_EC_KEY_SIZE_BITS = 224


def is_weak_cipher_suite(cipher_suite_name: str) -> bool:
    return any(pattern in cipher_suite_name for pattern in WEAK_CIPHER_SUITE_PATTERNS)


def provides_forward_secrecy(cipher_suite_name: str) -> bool:
    return any(kex in cipher_suite_name for kex in FORWARD_SECRECY_KEY_EXCHANGES)


def is_deprecated_version(tls_version: str) -> bool:
    return tls_version in DEPRECATED_TLS_VERSIONS
