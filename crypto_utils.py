"""Funciones criptográficas auxiliares utilizadas en la plataforma.

Se concentran aquí utilidades de hashing de contraseñas, cifrado simétrico
y generación de HMAC para mantener el resto del código más limpio.
"""

import base64
import datetime
import hashlib
import hmac as std_hmac
import os
from pathlib import Path
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from config import DATA_DIR, logger


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


def encrypt_description(description: str) -> Tuple[str, Path]:
    """Cifra una descripción de subasta con AES-256-CBC y devuelve datos y clave."""
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

    # Guardamos key+iv juntos para poder recuperar después (sólo para la práctica)
    key_file = DATA_DIR / f"auction_key_{datetime.datetime.now().timestamp()}.bin"
    with open(key_file, "wb") as file:
        file.write(key + iv)

    logger.info("[OK] Descripción cifrada | AES-256-CBC (IV 128b)")
    return description_enc, key_file


def generate_bid_hmac(bid_data: str, timestamp: str) -> Tuple[str, Path]:
    """Genera un HMAC-SHA256 para una puja y almacena la clave utilizada."""
    hmac_key = os.urandom(32)
    tag = std_hmac.new(hmac_key, bid_data.encode(), hashlib.sha256).hexdigest()

    hmac_file = DATA_DIR / f"bid_hmac_{timestamp.replace(':', '-')}.key"
    with open(hmac_file, "wb") as file:
        file.write(hmac_key)

    logger.info("[OK] HMAC-SHA256 generado (key 256b)")
    return tag, hmac_file
