"""Certificate authority + per-host leaf forging (spec §3.2/§3.4).

The proxy terminates client TLS with a leaf certificate it forges on the fly
for the requested SNI host, signed by a root CA the endpoint already trusts.
This module owns:

    * bootstrapping / loading the root CA (option B in §3.2 — self-generated),
    * forging and caching leaf certs per host,
    * building an ssl.SSLContext whose sni_callback swaps in the right leaf.

The CA private key must stay off disk-in-git (.gitignore covers *.key/*.pem).
"""

from __future__ import annotations

import datetime as _dt
import ipaddress
import ssl
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

__all__ = ["CertificateAuthority"]

# Fixed epoch so cert "not before" never depends on wall clock in a way that
# surprises tests; validity window is wide enough for a long-running service.
_NOT_BEFORE = _dt.datetime(2020, 1, 1, tzinfo=_dt.timezone.utc)
_NOT_AFTER = _dt.datetime(2035, 1, 1, tzinfo=_dt.timezone.utc)
_LEAF_NOT_AFTER = _dt.datetime(2034, 1, 1, tzinfo=_dt.timezone.utc)


class CertificateAuthority:
    """Loads (or generates) a root CA and forges leaf certs for MITM."""

    def __init__(self, cert: x509.Certificate, key: rsa.RSAPrivateKey):
        self._cert = cert
        self._key = key
        self._lock = threading.Lock()
        # host -> ssl context serving that host's forged leaf
        self._ctx_cache: dict[str, ssl.SSLContext] = {}

    # -- construction ---------------------------------------------------------

    @classmethod
    def generate(cls, common_name: str = "Windows DLP Agent Root CA") -> "CertificateAuthority":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Windows DLP Agent"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOT_BEFORE)
            .not_valid_after(_NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return cls(cert, key)

    @classmethod
    def load(cls, cert_path: Path, key_path: Path) -> "CertificateAuthority":
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise TypeError("CA key must be RSA")
        return cls(cert, key)

    @classmethod
    def load_or_generate(cls, ca_dir: Path) -> "CertificateAuthority":
        """Load the CA under ca_dir, generating + persisting one if absent."""
        ca_dir = Path(ca_dir)
        cert_path = ca_dir / "proxy-ca.crt"
        key_path = ca_dir / "proxy-ca.key"
        if cert_path.exists() and key_path.exists():
            return cls.load(cert_path, key_path)
        ca = cls.generate()
        ca.save(ca_dir)
        return ca

    # -- persistence ----------------------------------------------------------

    def save(self, ca_dir: Path) -> tuple[Path, Path]:
        ca_dir = Path(ca_dir)
        ca_dir.mkdir(parents=True, exist_ok=True)
        cert_path = ca_dir / "proxy-ca.crt"
        key_path = ca_dir / "proxy-ca.key"
        cert_path.write_bytes(self.cert_pem())
        key_path.write_bytes(
            self._key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        try:  # best-effort: restrict the private key perms where the OS supports it
            key_path.chmod(0o600)
        except (OSError, NotImplementedError):
            pass
        return cert_path, key_path

    def cert_pem(self) -> bytes:
        return self._cert.public_bytes(serialization.Encoding.PEM)

    # -- leaf forging ---------------------------------------------------------

    def forge_leaf(self, host: str) -> tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Forge a leaf certificate for `host` signed by this CA."""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_NOT_BEFORE)
            .not_valid_after(_LEAF_NOT_AFTER)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_san_for(host), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
        )
        cert = builder.sign(self._key, hashes.SHA256())
        return cert, key

    def context_for(self, host: str) -> ssl.SSLContext:
        """Return (cached) server SSLContext presenting a forged leaf for host.

        ALPN is pinned to http/1.1 (§3.4) so the browser speaks HTTP/1.1 to us
        and we never have to parse HTTP/2 frames.
        """
        with self._lock:
            ctx = self._ctx_cache.get(host)
            if ctx is not None:
                return ctx

            cert, key = self.forge_leaf(host)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM)
            key_pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # load_cert_chain needs files; write to a temp pair per host.
            import tempfile

            with tempfile.NamedTemporaryFile("wb", suffix=".pem", delete=False) as cf:
                cf.write(cert_pem)
                cert_file = cf.name
            with tempfile.NamedTemporaryFile("wb", suffix=".key", delete=False) as kf:
                kf.write(key_pem)
                key_file = kf.name
            try:
                ctx.load_cert_chain(cert_file, key_file)
            finally:
                Path(cert_file).unlink(missing_ok=True)
                Path(key_file).unlink(missing_ok=True)
            try:
                ctx.set_alpn_protocols(["http/1.1"])
            except NotImplementedError:
                pass
            self._ctx_cache[host] = ctx
            return ctx


def _san_for(host: str) -> x509.SubjectAlternativeName:
    try:
        ip = ipaddress.ip_address(host)
        return x509.SubjectAlternativeName([x509.IPAddress(ip)])
    except ValueError:
        return x509.SubjectAlternativeName([x509.DNSName(host)])
