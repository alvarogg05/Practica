#!/usr/bin/env python3
"""
Utilidades criptográficas para el sistema.
Incluye funciones para cifrado AES, HMAC, firmas digitales, etc.
Todo lo que hace cosas con crypto va aquí.
"""

import os
import base64
import hashlib
import hmac as std_hmac
import logging
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509

logger = logging.getLogger(__name__)

# Directorio para datos cifrados y keys temporales
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


class CryptoUtils:
    """
    Clase con métodos estáticos para operaciones criptográficas.
    Es como una caja de herramientas crypto.
    """
    
    @staticmethod
    def hash_password(password: str, salt: str, iterations: int = 100_000) -> str:
        """
        Hashea una contraseña usando PBKDF2-HMAC-SHA256.
        
        Args:
            password: La contraseña en texto plano
            salt: Salt para añadir aleatoriedad
            iterations: Número de iteraciones (más = más seguro pero más lento)
            
        Returns:
            Hash en base64
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=salt.encode(),
            iterations=iterations
        )
        password_hash = kdf.derive(password.encode())
        return base64.b64encode(password_hash).decode()
    
    @staticmethod
    def verify_password(password: str, salt: str, stored_hash: str, 
                       iterations: int = 100_000) -> bool:
        """
        Verifica que una contraseña coincida con el hash almacenado.
        
        Args:
            password: Contraseña a verificar
            salt: Salt usado en el hash original
            stored_hash: Hash almacenado en la BD
            iterations: Número de iteraciones usado
            
        Returns:
            True si coincide, False si no
        """
        try:
            computed_hash = CryptoUtils.hash_password(password, salt, iterations)
            return computed_hash == stored_hash
        except Exception as e:
            logger.error(f"Error al verificar contraseña: {e}")
            return False
    
    @staticmethod
    def encrypt_aes_cbc(plaintext: str) -> tuple:
        """
        Cifra un texto con AES-256-CBC.
        Genera una clave y un IV aleatorios.
        
        Args:
            plaintext: Texto a cifrar
            
        Returns:
            Tupla (ciphertext_base64, key_file_path)
        """
        # Asegurar que existe el directorio
        DATA_DIR.mkdir(exist_ok=True)
        
        # Generar clave AES de 256 bits (32 bytes) e IV de 128 bits (16 bytes)
        key = os.urandom(32)
        iv = os.urandom(16)
        
        # Crear el cifrador AES en modo CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Padding PKCS#7 manual (para que el texto sea múltiplo de 16 bytes)
        data = plaintext.encode()
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len]) * pad_len
        
        # Cifrar
        encrypted = encryptor.update(data) + encryptor.finalize()
        ciphertext_b64 = base64.b64encode(encrypted).decode()
        
        # Guardar key+iv en un archivo (en prod esto iría a un KMS)
        import datetime
        key_file = DATA_DIR / f"aes_key_{datetime.datetime.now().timestamp()}.bin"
        with open(key_file, "wb") as f:
            f.write(key + iv)  # Los primeros 32 bytes son key, los últimos 16 son IV
        
        logger.info(f"✓ Texto cifrado con AES-256-CBC (key guardada en {key_file.name})")
        return ciphertext_b64, str(key_file)
    
    @staticmethod
    def decrypt_aes_cbc(ciphertext_b64: str, key_file_path: str) -> str:
        """
        Descifra un texto cifrado con AES-256-CBC.
        
        Args:
            ciphertext_b64: Texto cifrado en base64
            key_file_path: Path al archivo con la clave+IV
            
        Returns:
            Texto en claro
        """
        # Leer key + IV del archivo
        with open(key_file_path, "rb") as f:
            key_iv = f.read()
        key = key_iv[:32]  # Primeros 32 bytes
        iv = key_iv[32:]   # Últimos 16 bytes
        
        # Descifrar
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        encrypted = base64.b64decode(ciphertext_b64)
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        
        # Quitar padding PKCS#7
        pad_len = decrypted[-1]
        plaintext = decrypted[:-pad_len].decode()
        
        return plaintext
    
    @staticmethod
    def generate_hmac(data: str) -> tuple:
        """
        Genera un HMAC-SHA256 para verificar integridad de datos.
        
        Args:
            data: Datos a proteger
            
        Returns:
            Tupla (hmac_hex, key_file_path)
        """
        # Asegurar que existe el directorio
        DATA_DIR.mkdir(exist_ok=True)
        
        # Generar clave HMAC de 256 bits
        hmac_key = os.urandom(32)
        
        # Calcular HMAC
        tag = std_hmac.new(hmac_key, data.encode(), hashlib.sha256).hexdigest()
        
        # Guardar la clave HMAC
        import datetime
        hmac_file = DATA_DIR / f"hmac_key_{datetime.datetime.now().timestamp()}.bin"
        with open(hmac_file, "wb") as f:
            f.write(hmac_key)
        
        logger.info("✓ HMAC-SHA256 generado (clave de 256 bits)")
        return tag, str(hmac_file)
    
    @staticmethod
    def verify_hmac(data: str, tag: str, key_file_path: str) -> bool:
        """
        Verifica un HMAC para comprobar integridad.
        
        Args:
            data: Datos originales
            tag: HMAC calculado previamente
            key_file_path: Path a la clave HMAC
            
        Returns:
            True si el HMAC es válido, False si no
        """
        try:
            # Leer la clave
            with open(key_file_path, "rb") as f:
                hmac_key = f.read()
            
            # Recalcular el HMAC
            computed_tag = std_hmac.new(hmac_key, data.encode(), hashlib.sha256).hexdigest()
            
            # Comparar de forma segura (constant-time comparison)
            if std_hmac.compare_digest(computed_tag, tag):
                logger.info("✓ HMAC verificado correctamente")
                return True
            
            logger.error("✗ HMAC inválido - los datos han sido modificados")
            return False
            
        except Exception as e:
            logger.error(f"✗ Error al verificar HMAC: {e}")
            return False
    
    @staticmethod
    def sign_data(data: str, private_key_path: str, password: str) -> str:
        """
        Firma digitalmente unos datos con RSA-PSS.
        
        Args:
            data: Datos a firmar
            private_key_path: Path a la clave privada RSA
            password: Contraseña de la clave privada
            
        Returns:
            Firma en base64
        """
        try:
            # Cargar la clave privada
            with open(private_key_path, "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=password.encode()
                )
            
            # Firmar con RSA-PSS + SHA-256
            signature = private_key.sign(
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signature_b64 = base64.b64encode(signature).decode()
            logger.info("✓ Firma digital RSA-PSS generada (RSA-2048 + SHA-256)")
            return signature_b64
            
        except Exception as e:
            logger.error(f"✗ Error al firmar datos: {e}")
            raise
    
    @staticmethod
    def verify_signature(data: str, signature_b64: str, cert_path: str) -> bool:
        """
        Verifica una firma digital usando el certificado del firmante.
        
        Args:
            data: Datos originales
            signature_b64: Firma en base64
            cert_path: Path al certificado X.509 del firmante
            
        Returns:
            True si la firma es válida, False si no
        """
        try:
            # Cargar el certificado y extraer la clave pública
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            public_key = cert.public_key()
            
            # Decodificar la firma
            signature = base64.b64decode(signature_b64)
            
            # Verificar con RSA-PSS
            public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            logger.info("✓ Firma digital verificada correctamente")
            return True
            
        except Exception as e:
            logger.error(f"✗ Firma inválida: {e}")
            return False
