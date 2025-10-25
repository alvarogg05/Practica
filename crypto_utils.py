"""
Funciones criptográficas auxiliares utilizadas en la plataforma.

Se concentran aquí utilidades de hashing de contraseñas, cifrado simétrico
y generación de HMAC.
"""

import base64
import hashlib
import hmac as std_hmac
import os
from typing import Tuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import logger


def derive_password_hash(password: str, salt_hex: str) -> str:
    """Genera un hash de contraseña usando PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt_hex.encode(),
        iterations=100_000
    )
    return base64.b64encode(kdf.derive(password.encode())).decode()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    """Verifica una contraseña contrastando con el hash almacenado."""
    computed = derive_password_hash(password, salt_hex)
    return std_hmac.compare_digest(computed, expected_hash)


def encrypt_description(description: str) -> Tuple[str, Optional[bytes]]:
    """Cifra una descripción con AES-256-CBC y devuelve (ciphertext_b64, None)."""
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    data = description.encode()
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    # Arriba aplicamos un padding PKCS#7 manual para que CBC acepte múltiplos de bloque

    encrypted_desc = encryptor.update(data) + encryptor.finalize()
    description_enc = base64.b64encode(encrypted_desc).decode()

    # No persistimos key/iv en disco 
    logger.info("[OK] Descripción cifrada | AES-256-CBC (IV 128b)")
    return description_enc, None


def generate_bid_hmac(bid_data: str) -> Tuple[str, bytes]:
    """Genera un HMAC-SHA256 para la puja y devuelve (tag_hex, key_bytes).

    La clave HMAC es efímera y no se persiste; se usa para verificación inmediata.
    """
    hmac_key = os.urandom(32)
    tag = std_hmac.new(hmac_key, bid_data.encode(), hashlib.sha256).hexdigest()
    logger.info("[OK] HMAC-SHA256 generado (key 256b)")
    return tag, hmac_key
