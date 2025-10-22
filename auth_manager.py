#!/usr/bin/env python3
"""
Gestor de autenticación y usuarios.
Se encarga del registro, login y gestión de credenciales.
"""

import secrets
import logging
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from database import Database
from crypto_utils import CryptoUtils
from pki_manager import PKIManager

logger = logging.getLogger(__name__)

# Directorio para las claves de usuario
KEYS_DIR = Path("keys")
KEYS_DIR.mkdir(exist_ok=True)


class AuthManager:
    """
    Gestor de autenticación.
    Maneja registro de usuarios, login y gestión de claves RSA.
    """
    
    def __init__(self, db: Database, pki: PKIManager):
        """
        Inicializa el gestor de autenticación.
        
        Args:
            db: Instancia de la base de datos
            pki: Instancia del gestor PKI
        """
        self.db = db
        self.pki = pki
        self.current_user: Optional[str] = None
    
    def register_user(self, username: str, password: str) -> bool:
        """
        Registra un nuevo usuario en el sistema.
        
        Pasos:
        1. Verifica que el usuario no exista
        2. Genera el hash de la contraseña con PBKDF2
        3. Genera par de claves RSA para el usuario
        4. Solicita un certificado X.509 a la Sub-CA
        5. Guarda todo en la BD
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            True si el registro fue exitoso, False si ya existe
        """
        cur = self.db.get_cursor()
        
        # Verificar que el usuario no exista ya
        cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cur.fetchone():
            logger.error(f"El usuario '{username}' ya existe")
            return False
        
        # Generar salt aleatorio (16 bytes = 32 caracteres hex)
        salt = secrets.token_hex(16)
        
        # Hashear la contraseña con PBKDF2-HMAC-SHA256
        password_hash = CryptoUtils.hash_password(password, salt)
        
        # Generar par de claves RSA-2048 para el usuario
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Guardar clave privada (cifrada con la contraseña del usuario)
        private_key_path = KEYS_DIR / f"{username}_private.pem"
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        
        # Guardar clave pública
        public_key_path = KEYS_DIR / f"{username}_public.pem"
        with open(public_key_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        
        # Solicitar certificado X.509 a la Sub-CA
        cert_path = self.pki.issue_user_certificate(username, str(public_key_path))
        
        # Guardar todo en la BD
        cur.execute('''
            INSERT INTO users (username, password_hash, salt, public_key_path, 
                             private_key_path, certificate_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, str(public_key_path), 
              str(private_key_path), cert_path))
        self.db.commit()
        
        logger.info(f"✓ Usuario '{username}' registrado | PBKDF2-HMAC-SHA256 (100k iters) | RSA-2048 | Cert emitido")
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """
        Autentica un usuario verificando su contraseña.
        
        Args:
            username: Nombre de usuario
            password: Contraseña en texto plano
            
        Returns:
            True si las credenciales son correctas, False si no
        """
        cur = self.db.get_cursor()
        
        # Buscar el usuario en la BD
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        
        if not row:
            logger.error(f"Usuario '{username}' no encontrado")
            return False
        
        stored_hash, salt = row
        
        # Verificar la contraseña
        if CryptoUtils.verify_password(password, salt, stored_hash):
            self.current_user = username
            logger.info(f"✓ Usuario '{username}' autenticado correctamente")
            return True
        else:
            logger.error("Credenciales incorrectas")
            return False
    
    def logout(self):
        """Cierra la sesión del usuario actual"""
        if self.current_user:
            logger.info(f"Usuario '{self.current_user}' cerró sesión")
            self.current_user = None
    
    def is_authenticated(self) -> bool:
        """Verifica si hay un usuario autenticado"""
        return self.current_user is not None
    
    def get_current_user(self) -> Optional[str]:
        """Devuelve el nombre del usuario actual (o None si no hay)"""
        return self.current_user
    
    def get_user_private_key_path(self, username: Optional[str] = None) -> Optional[str]:
        """
        Obtiene el path a la clave privada de un usuario.
        
        Args:
            username: Usuario del que obtener la clave (usa current_user si no se especifica)
            
        Returns:
            Path a la clave privada, o None si no existe
        """
        if username is None:
            username = self.current_user
        
        if not username:
            return None
        
        cur = self.db.get_cursor()
        cur.execute("SELECT private_key_path FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        
        return row[0] if row else None
    
    def get_user_certificate_path(self, username: str) -> Optional[str]:
        """
        Obtiene el path al certificado de un usuario.
        
        Args:
            username: Usuario del que obtener el certificado
            
        Returns:
            Path al certificado, o None si no existe
        """
        cur = self.db.get_cursor()
        cur.execute("SELECT certificate_path FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        
        return row[0] if row else None
