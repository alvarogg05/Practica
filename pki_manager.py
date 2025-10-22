#!/usr/bin/env python3
"""
Módulo de PKI (Public Key Infrastructure).
Gestiona las autoridades de certificación (CA) y la emisión de certificados.
Es la parte más "enterprise" del proyecto jaja
"""

import datetime
import logging
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key

logger = logging.getLogger(__name__)

# Directorios para guardar las keys y certificados
KEYS_DIR = Path("keys")
CERTS_DIR = Path("certs")

# Crear los dirs si no existen
for dir_path in [KEYS_DIR, CERTS_DIR]:
    dir_path.mkdir(exist_ok=True)


class CertificateAuthority:
    """
    Autoridad de Certificación (CA).
    Puede ser raíz (self-signed) o subordinada (firmada por otra CA).
    Básicamente es quien firma y valida los certificados digitales.
    """
    
    def __init__(self, ca_name: str, is_root: bool = True, 
                 parent_ca: Optional['CertificateAuthority'] = None):
        """
        Inicializa una CA.
        
        Args:
            ca_name: Nombre de la CA (ej: "Root-CA", "Sub-CA")
            is_root: Si es True, es una CA raíz (se autofirma)
            parent_ca: Si no es raíz, necesita una CA padre que la firme
        """
        self.ca_name = ca_name
        self.is_root = is_root
        self.parent_ca = parent_ca
        
        # Paths donde se guardan la clave privada y el certificado
        self.key_path = KEYS_DIR / f"{ca_name}_key.pem"
        self.cert_path = CERTS_DIR / f"{ca_name}_cert.pem"
        
        # Si no existe, la generamos
        if not self.key_path.exists():
            self._generate_ca_certificate()
    
    def _generate_ca_certificate(self):
        """
        Genera el par de claves RSA y el certificado X.509 de la CA.
        Si es raíz se autofirma, si no, la firma el parent_ca.
        """
        # Generar par de claves RSA de 2048 bits
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Guardar la clave privada sin cifrar (en prod esto sería con password)
        with open(self.key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Crear el subject (info de la CA)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction Platform PKI"),
            x509.NameAttribute(NameOID.COMMON_NAME, self.ca_name),
        ])
        
        # Construir el certificado
        builder = x509.CertificateBuilder().subject_name(subject)
        
        # Si es raíz, el issuer es ella misma (self-signed)
        if self.is_root:
            builder = builder.issuer_name(subject)
            signing_key = private_key
        else:
            # Si no, el issuer es el parent y firma con su clave
            parent_cert = self._load_certificate(self.parent_ca.cert_path)
            builder = builder.issuer_name(parent_cert.subject)
            signing_key = self._load_private_key(self.parent_ca.key_path)
        
        # Añadir la info del certificado (clave pública, validez, extensiones...)
        builder = (builder
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            # Esta extensión marca que es una CA (puede firmar otros certs)
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            )
            # Permisos: solo puede firmar certificados (key_cert_sign)
            .add_extension(
                x509.KeyUsage(
                    key_cert_sign=True, 
                    crl_sign=True,
                    digital_signature=False, 
                    content_commitment=False,
                    key_encipherment=False, 
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False, 
                    decipher_only=False
                ),
                critical=True
            )
        )
        
        # Firmar el certificado con SHA-256
        certificate = builder.sign(signing_key, hashes.SHA256())
        
        # Guardar el certificado
        with open(self.cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"✓ Certificado CA '{self.ca_name}' generado (Raíz: {self.is_root}) | RSA-2048 | SHA-256")
    
    def issue_certificate(self, username: str, public_key_path: str) -> str:
        """
        Emite un certificado X.509 para un usuario.
        
        Args:
            username: Nombre del usuario
            public_key_path: Path a la clave pública RSA del usuario
            
        Returns:
            Path del certificado generado
        """
        # Cargar la clave pública del usuario
        with open(public_key_path, "rb") as f:
            user_public_key = serialization.load_pem_public_key(f.read())
        
        # Cargar la clave privada y cert de esta CA (para firmar)
        ca_private_key = self._load_private_key(self.key_path)
        ca_cert = self._load_certificate(self.cert_path)
        
        # Info del usuario
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Madrid"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Auction Platform Users"),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        
        # Construir el certificado del usuario
        builder = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)  # Lo firma esta CA
            .public_key(user_public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            # NO es una CA (ca=False)
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True
            )
            # Permisos de usuario: firmar y cifrar
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,  # Para firmar cosas
                    content_commitment=True,
                    key_encipherment=True,   # Para cifrar
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,     # NO puede emitir certificados
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                critical=True
            )
        )
        
        # Firmar con la clave de la CA
        certificate = builder.sign(ca_private_key, hashes.SHA256())
        
        # Guardar el certificado del usuario
        cert_path = CERTS_DIR / f"{username}_cert.pem"
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        logger.info(f"✓ Certificado emitido para '{username}' por '{self.ca_name}'")
        return str(cert_path)
    
    @staticmethod
    def _load_private_key(path):
        """Carga una clave privada desde un archivo PEM"""
        with open(path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def _load_certificate(path):
        """Carga un certificado X.509 desde un archivo PEM"""
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())


class PKIManager:
    """
    Gestor del sistema PKI completo.
    Inicializa la jerarquía de CAs (Root CA → Sub CA).
    """
    
    def __init__(self):
        """Inicializa la infraestructura PKI con Root CA y Sub CA"""
        logger.info("=== Inicializando PKI ===")
        
        # Crear CA raíz (se autofirma)
        self.root_ca = CertificateAuthority("Root-CA", is_root=True)
        
        # Crear Sub-CA (firmada por Root CA)
        self.sub_ca = CertificateAuthority(
            "Sub-CA-Madrid", 
            is_root=False, 
            parent_ca=self.root_ca
        )
        
        logger.info("✓ PKI inicializada (Root CA + Sub-CA)")
    
    def issue_user_certificate(self, username: str, public_key_path: str) -> str:
        """
        Emite un certificado para un usuario usando la Sub-CA.
        
        Args:
            username: Nombre del usuario
            public_key_path: Path a su clave pública
            
        Returns:
            Path del certificado generado
        """
        return self.sub_ca.issue_certificate(username, public_key_path)
    
    def verify_certificate_chain(self, user_cert_path: str) -> bool:
        """
        Verifica la cadena de certificación completa.
        La cadena debe ser: User Cert ← Sub-CA ← Root CA
        
        Args:
            user_cert_path: Path al certificado del usuario
            
        Returns:
            True si la cadena es válida, False en caso contrario
        """
        try:
            # Cargar los tres certificados
            with open(user_cert_path, "rb") as f:
                user_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.sub_ca.cert_path, "rb") as f:
                sub_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.root_ca.cert_path, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read())
            
            # Verificar que la cadena es correcta
            if user_cert.issuer == sub_cert.subject and sub_cert.issuer == root_cert.subject:
                logger.info("✓ Cadena de certificación: User ← SubCA ← Root")
                return True
            
            logger.error("✗ Cadena de certificación inválida")
            return False
            
        except Exception as e:
            logger.error(f"✗ Error al verificar cadena PKI: {e}")
            return False
