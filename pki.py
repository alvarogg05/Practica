"""Gestión de la infraestructura de clave pública (PKI)."""

import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from config import CERTS_DIR, KEYS_DIR, logger


class CertificateAuthority:
    """Autoridad de Certificación para la emisión de certificados X.509."""

    def __init__(self, ca_name: str, is_root: bool = True, parent_ca: Optional['CertificateAuthority'] = None):
        self.ca_name = ca_name
        self.is_root = is_root
        self.parent_ca = parent_ca
        self.key_path = KEYS_DIR / f"{ca_name}_key.pem"
        self.cert_path = CERTS_DIR / f"{ca_name}_cert.pem"
        if not self.key_path.exists():
            self._generate_ca_certificate()

    def _generate_ca_certificate(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.key_path, "wb") as file:
            file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction Platform PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])

        builder = x509.CertificateBuilder().subject_name(subject)
        if self.is_root:
            builder = builder.issuer_name(subject)
            signing_key = private_key
        else:
            if not self.parent_ca:
                raise ValueError("Una Sub-CA requiere una CA padre")
            parent_cert = self._load_certificate(self.parent_ca.cert_path)
            builder = builder.issuer_name(parent_cert.subject)
            signing_key = self._load_private_key(self.parent_ca.key_path)

        builder = (builder.public_key(private_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime.utcnow())
                   .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(
                        key_cert_sign=True, crl_sign=True,
                        digital_signature=False, content_commitment=False,
                        key_encipherment=False, data_encipherment=False, key_agreement=False,
                        encipher_only=False, decipher_only=False
                    ), critical=True))

        certificate = builder.sign(signing_key, hashes.SHA256())
        with open(self.cert_path, "wb") as file:
            file.write(certificate.public_bytes(serialization.Encoding.PEM))

        logger.info(
            f"[OK] Certificado CA '{self.ca_name}' generado (Raíz: {self.is_root}) | RSA-2048 | SHA-256"
        )

    def issue_certificate(self, username: str, public_key_path: str) -> str:
        with open(public_key_path, "rb") as file:
            user_public_key = serialization.load_pem_public_key(file.read())
        ca_private_key = self._load_private_key(self.key_path)
        ca_cert = self._load_certificate(self.cert_path)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction Platform Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])

        builder = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(ca_cert.subject)
                   .public_key(user_public_key)
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.datetime.utcnow())
                   .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .add_extension(x509.KeyUsage(
                        digital_signature=True, content_commitment=True,
                        key_encipherment=True, data_encipherment=False, key_agreement=False,
                        key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False
                    ), critical=True))

        certificate = builder.sign(ca_private_key, hashes.SHA256())
        cert_path = CERTS_DIR / f"{username}_cert.pem"
        with open(cert_path, "wb") as file:
            file.write(certificate.public_bytes(serialization.Encoding.PEM))

        logger.info(f"[OK] Certificado emitido para '{username}' por '{self.ca_name}'")
        return str(cert_path)

    @staticmethod
    def _load_private_key(path):
        with open(path, "rb") as file:
            return load_pem_private_key(file.read(), password=None)

    @staticmethod
    def _load_certificate(path):
        with open(path, "rb") as file:
            return x509.load_pem_x509_certificate(file.read())
