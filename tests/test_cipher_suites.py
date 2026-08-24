from ecforensics.tls.cipher_suites import (
    is_deprecated_version,
    is_weak_cipher_suite,
    provides_forward_secrecy,
)


def test_weak_cipher_detected():
    assert is_weak_cipher_suite("TLS_RSA_WITH_RC4_128_SHA")


def test_strong_cipher_not_flagged():
    assert not is_weak_cipher_suite("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")


def test_deprecated_version():
    assert is_deprecated_version("TLSv1.0")
    assert not is_deprecated_version("TLSv1.3")


def test_forward_secrecy_detection():
    assert provides_forward_secrecy("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
    assert not provides_forward_secrecy("TLS_RSA_WITH_AES_128_GCM_SHA256")
