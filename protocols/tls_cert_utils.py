"""
X.509 Certificate and PKI Utilities for Real TLS 1.3 Testing and Deployment
Generates self-signed Root CAs, Server Certificates with Subject Alternative Names (SAN),
and untrusted/expired certificates for security and rejection verification.
"""

import os
import shutil
import tempfile
import datetime
import ipaddress
from typing import Tuple, Dict, Any

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class PKIManager:
    """
    Manages temporary or persistent X.509 PKI assets for TLS 1.3 testing.
    """

    def __init__(self, base_dir: str = None):
        if base_dir:
            self.dir = base_dir
            self._cleanup = False
            os.makedirs(self.dir, exist_ok=True)
        else:
            self.dir = tempfile.mkdtemp(prefix="pqc_tls_pki_")
            self._cleanup = True

        self.ca_cert_path = os.path.join(self.dir, "ca_cert.pem")
        self.ca_key_path = os.path.join(self.dir, "ca_key.pem")
        self.server_cert_path = os.path.join(self.dir, "server_cert.pem")
        self.server_key_path = os.path.join(self.dir, "server_key.pem")
        self.rogue_cert_path = os.path.join(self.dir, "rogue_cert.pem")
        self.rogue_key_path = os.path.join(self.dir, "rogue_key.pem")
        self.expired_cert_path = os.path.join(self.dir, "expired_cert.pem")
        self.expired_key_path = os.path.join(self.dir, "expired_key.pem")

        self._generate_all()

    def _generate_all(self):
        # 1. Root CA (ECDSA P-256 / SHA-256)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hybrid PQC Research Group"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Hybrid PQC Test Root CA")
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self._write_pem(self.ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(self.ca_key_path, ca_key)

        # 2. Server Certificate signed by CA (ECDSA P-256 / SHA-256)
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Hybrid PQC Research Group"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
        ])
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(server_name)
            .issuer_name(ca_name)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self._write_pem(self.server_cert_path, server_cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(self.server_key_path, server_key)

        # 3. Rogue Untrusted Certificate (Self-signed by unknown entity)
        rogue_key = ec.generate_private_key(ec.SECP256R1())
        rogue_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "untrusted-attacker.local")
        ])
        rogue_cert = (
            x509.CertificateBuilder()
            .subject_name(rogue_name)
            .issuer_name(rogue_name)
            .public_key(rogue_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(rogue_key, hashes.SHA256())
        )

        self._write_pem(self.rogue_cert_path, rogue_cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(self.rogue_key_path, rogue_key)

        # 4. Expired Certificate (Valid CA signature, but expired validity dates)
        expired_key = ec.generate_private_key(ec.SECP256R1())
        expired_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
        ])
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(expired_name)
            .issuer_name(ca_name)
            .public_key(expired_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=60))
            .not_valid_after(now - datetime.timedelta(days=10))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        self._write_pem(self.expired_cert_path, expired_cert.public_bytes(serialization.Encoding.PEM))
        self._write_key(self.expired_key_path, expired_key)

    def _write_pem(self, path: str, data: bytes):
        with open(path, "wb") as f:
            f.write(data)

    def _write_key(self, path: str, key):
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(path, "wb") as f:
            f.write(pem)

    def cleanup(self):
        if self._cleanup and os.path.exists(self.dir):
            shutil.rmtree(self.dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()
