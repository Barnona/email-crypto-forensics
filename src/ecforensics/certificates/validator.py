"""X.509 parsing and passive certificate-chain validation."""
from __future__ import annotations

from datetime import datetime, timezone

from ecforensics.models.session import Certificate
from ecforensics.tls.cipher_suites import MIN_EC_KEY_SIZE_BITS, MIN_RSA_KEY_SIZE_BITS

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, padding, rsa
except ImportError:  # pragma: no cover
    x509 = None


def parse_certificate(der_bytes: bytes) -> Certificate:
    if x509 is None:
        raise ImportError("pip install cryptography")
    cert = x509.load_der_x509_certificate(der_bytes)
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        algorithm, size = "RSA", key.key_size
    elif isinstance(key, ec.EllipticCurvePublicKey):
        algorithm, size = "EC", key.key_size
    elif isinstance(key, dsa.DSAPublicKey):
        algorithm, size = "DSA", key.key_size
    else:
        algorithm, size = type(key).__name__, -1
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    return Certificate(
        subject=subject, issuer=issuer, serial_number=format(cert.serial_number, "x"),
        not_before=not_before, not_after=not_after, public_key_algorithm=algorithm,
        key_size_bits=size, signature_algorithm=cert.signature_algorithm_oid._name,
        is_self_signed=subject == issuer,
        is_expired=datetime.now(timezone.utc) > not_after,
        raw_der=der_bytes,
    )


def is_key_size_sufficient(public_key_algorithm: str, key_size_bits: int) -> bool:
    algo = public_key_algorithm.upper()
    if algo in ("RSA", "DSA"):
        return key_size_bits >= MIN_RSA_KEY_SIZE_BITS
    if algo in ("EC", "ECDSA"):
        return key_size_bits >= MIN_EC_KEY_SIZE_BITS
    return True


def _verify_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, child.signature_hash_algorithm)
        else:
            return False
        return True
    except Exception:
        return False


def validate_chain(certificates: list[Certificate]) -> bool:
    """Validate the presented chain's issuer links and signatures.

    This is deliberately a *presented-chain* validation, not public-CA trust
    validation: a passive capture may contain a private enterprise CA. The
    function therefore answers whether the captured certificates form a
    cryptographically consistent chain. Trust-store validation is a separate
    deployment concern.
    """
    if x509 is None or not certificates:
        return False
    parsed = []
    for cert in certificates:
        if not cert.raw_der:
            return False
        try:
            parsed.append(x509.load_der_x509_certificate(cert.raw_der))
        except Exception:
            return False
    for index, child in enumerate(parsed[:-1]):
        issuer = parsed[index + 1]
        if child.issuer != issuer.subject or not _verify_signature(child, issuer):
            return False
    root = parsed[-1]
    if root.subject == root.issuer and not _verify_signature(root, root):
        return False
    return True
