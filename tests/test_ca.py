"""Tests for the CA / leaf forging module (spec §3.2)."""

from __future__ import annotations

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from windows_dlp_agent.ca import CertificateAuthority


def test_generate_produces_ca_cert():
    ca = CertificateAuthority.generate()
    bc = ca._cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value
    assert bc.ca is True


def test_leaf_is_signed_by_ca_and_has_san():
    ca = CertificateAuthority.generate()
    leaf, _key = ca.forge_leaf("chatgpt.com")

    # issuer of the leaf == subject of the CA
    assert leaf.issuer == ca._cert.subject

    # signature verifies against the CA public key (raises on mismatch)
    ca._cert.public_key().verify(
        leaf.signature,
        leaf.tbs_certificate_bytes,
        __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]).PKCS1v15(),
        leaf.signature_hash_algorithm,
    )

    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    assert "chatgpt.com" in san.get_values_for_type(x509.DNSName)


def test_context_cache_reuses_same_context():
    ca = CertificateAuthority.generate()
    c1 = ca.context_for("claude.ai")
    c2 = ca.context_for("claude.ai")
    assert c1 is c2


def test_load_or_generate_persists_and_reloads(tmp_path):
    ca_dir = tmp_path / "ca"
    ca1 = CertificateAuthority.load_or_generate(ca_dir)
    assert (ca_dir / "proxy-ca.crt").exists()
    assert (ca_dir / "proxy-ca.key").exists()

    # second call loads the same CA (same subject + serial)
    ca2 = CertificateAuthority.load_or_generate(ca_dir)
    assert ca1._cert.serial_number == ca2._cert.serial_number


def test_ip_host_gets_ip_san():
    ca = CertificateAuthority.generate()
    leaf, _ = ca.forge_leaf("127.0.0.1")
    san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    import ipaddress

    assert ipaddress.ip_address("127.0.0.1") in san.get_values_for_type(x509.IPAddress)
