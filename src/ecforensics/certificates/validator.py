"""
X.509 certificate validation and analysis.

Turns raw DER certificate bytes into the Certificate model, with all the
security-relevant fields the risk engine needs: expiry, key strength,
signature algorithm, self-signed status, and chain validity.
"""

from __future__ import annotations

from ecforensics.models.session import Certificate
from ecforensics.tls.cipher_suites import MIN_EC_KEY_SIZE_BITS, MIN_RSA_KEY_SIZE_BITS

try:
    from cryptography import x509  # noqa: F401  (imported for the TODO below)
except ImportError:  # pragma: no cover
    x509 = None


def parse_certificate(der_bytes: bytes) -> Certificate:
    """
    Parse a DER certificate into the Certificate model using pyca/cryptography.

    TODO: implement with x509.load_der_x509_certificate(der_bytes), reading
    .subject, .issuer, .serial_number, .not_valid_before_utc,
    .not_valid_after_utc, .signature_algorithm_oid, and .public_key()
    (branch on isinstance to read RSAPublicKey.key_size vs.
    EllipticCurvePublicKey.curve.key_size). Set is_self_signed by comparing
    subject == issuer (a heuristic -- true self-signed detection also checks
    the signature verifies against the certificate's own public key).
    """
    if x509 is None:
        raise ImportError("pip install cryptography")
    raise NotImplementedError


def is_key_size_sufficient(public_key_algorithm: str, key_size_bits: int) -> bool:
    """Check key size against MIN_RSA_KEY_SIZE_BITS / MIN_EC_KEY_SIZE_BITS."""
    algo = public_key_algorithm.upper()
    if algo in ("RSA", "DSA"):
        return key_size_bits >= MIN_RSA_KEY_SIZE_BITS
    if algo in ("EC", "ECDSA"):
        return key_size_bits >= MIN_EC_KEY_SIZE_BITS
    return True  # unknown algorithm -- don't flag without more information


def validate_chain(certificates: list[Certificate]) -> bool:
    """
    Validate a certificate chain against a trust store.

    TODO:
        - Use pyOpenSSL's X509StoreContext, or cryptography + certifi's CA
          bundle, to build and verify the chain up to a trusted root.
        - Passive capture means you only see what the server presented -- you
          cannot verify the hostname match against the *client's* expected
          hostname without also knowing what the client connected to. Use
          tls_session.sni_hostname as the reference name for that check.
        - Enterprise mail relays legitimately use internal/private CAs;
          "chain doesn't validate against the public trust store" and "chain
          is actually broken" are different findings -- consider accepting
          an optional custom trust store path for internal CA scenarios.
    """
    raise NotImplementedError
