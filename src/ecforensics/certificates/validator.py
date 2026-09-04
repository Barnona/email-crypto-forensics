"""
X.509 certificate validation and analysis.

Turns raw DER certificate bytes into the Certificate model, with all the
security-relevant fields the risk engine needs: expiry, key strength,
signature algorithm, self-signed status, and chain validity.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ecforensics.models.session import Certificate
from ecforensics.tls.cipher_suites import MIN_EC_KEY_SIZE_BITS, MIN_RSA_KEY_SIZE_BITS

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
except ImportError:  # pragma: no cover
    x509 = None


def parse_certificate(der_bytes: bytes) -> Certificate:
    """
    Parse a DER certificate into the Certificate model using pyca/cryptography.

    is_self_signed is a heuristic (subject == issuer) -- true self-signed
    verification would also check the signature validates against the
    certificate's own public key, which matters for detecting a forged cert
    presenting a subject==issuer identity it doesn't actually control. Good
    enough for a first pass; documented so it isn't mistaken for a stronger
    guarantee than it is.
    """
    if x509 is None:
        raise ImportError("pip install cryptography")

    cert = x509.load_der_x509_certificate(der_bytes)

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key_algorithm = "RSA"
        key_size_bits = public_key.key_size
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key_algorithm = "EC"
        key_size_bits = public_key.key_size
    elif isinstance(public_key, dsa.DSAPublicKey):
        public_key_algorithm = "DSA"
        key_size_bits = public_key.key_size
    else:
        public_key_algorithm = type(public_key).__name__
        key_size_bits = -1

    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    is_expired = datetime.now(timezone.utc) > not_after

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    is_self_signed = subject == issuer

    return Certificate(
        subject=subject,
        issuer=issuer,
        serial_number=format(cert.serial_number, "x"),
        not_before=not_before,
        not_after=not_after,
        public_key_algorithm=public_key_algorithm,
        key_size_bits=key_size_bits,
        signature_algorithm=cert.signature_algorithm_oid._name,
        is_self_signed=is_self_signed,
        is_expired=is_expired,
        raw_der=der_bytes,
    )


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
