#!/usr/bin/env python3
"""
Plataforma de Subastas Electrónicas con Criptografía
Requisitos:
1. Registro y autenticación (PBKDF2-HMAC-SHA256 + salt)
2. Cifrado simétrico (AES-256-CBC) de descripciones
3. HMAC-SHA256 de pujas (integridad)
4. Firma digital RSA-PSS y verificación
5. PKI: CA raíz + Sub-CA que emite certificados X.509 a usuarios
"""

import os
import json
import hashlib
import hmac as std_hmac
import secrets
import logging
import datetime
import sqlite3
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import getpass

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    handlers=[logging.FileHandler('auction_platform.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Constantes de configuración
DB_FILE = "auction_platform.db"
KEYS_DIR = Path("keys")
CERTS_DIR = Path("certs")
DATA_DIR = Path("data")

# Crear directorios necesarios
for dir_path in [KEYS_DIR, CERTS_DIR, DATA_DIR]:
    dir_path.mkdir(exist_ok=True)

class CertificateAuthority:
    """Autoridad de Certificación para gestión de PKI"""
    def __init__(self, ca_name: str, is_root: bool = True, parent_ca: Optional['CertificateAuthority']=None):
        self.ca_name = ca_name
        self.is_root = is_root
        self.parent_ca = parent_ca
        self.key_path = KEYS_DIR / f"{ca_name}_key.pem"
        self.cert_path = CERTS_DIR / f"{ca_name}_cert.pem"
        if not self.key_path.exists():
            self._generate_ca_certificate()

    def _generate_ca_certificate(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(self.key_path, "wb") as f:
            f.write(private_key.private_bytes(
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
        with open(self.cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        logger.info(f"✓ Certificado CA '{self.ca_name}' generado (Raíz: {self.is_root}) | RSA-2048 | SHA-256")

    def issue_certificate(self, username: str, public_key_path: str) -> str:
        with open(public_key_path, "rb") as f:
            user_public_key = serialization.load_pem_public_key(f.read())
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
        with open(cert_path, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))

        logger.info(f"✓ Certificado emitido para '{username}' por '{self.ca_name}'")
        return str(cert_path)

    @staticmethod
    def _load_private_key(path):
        with open(path, "rb") as f:
            return load_pem_private_key(f.read(), password=None)

    @staticmethod
    def _load_certificate(path):
        with open(path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

class AuctionPlatform:
    """Plataforma principal de subastas electrónicas"""
    def __init__(self):
        self.db_conn = None
        self.current_user: Optional[str] = None
        self.root_ca: Optional[CertificateAuthority] = None
        self.sub_ca: Optional[CertificateAuthority] = None
        self._init_database()
        self._init_pki()

    def _init_database(self):
        self.db_conn = sqlite3.connect(DB_FILE)
        cur = self.db_conn.cursor()

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                public_key_path TEXT,
                private_key_path TEXT,
                certificate_path TEXT
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS auctions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                seller TEXT NOT NULL,
                start_price REAL NOT NULL,
                current_price REAL NOT NULL,
                highest_bidder TEXT,
                end_date TEXT NOT NULL,
                status TEXT NOT NULL,
                encrypted INTEGER DEFAULT 0,
                FOREIGN KEY (seller) REFERENCES users(username)
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS bids (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                auction_id INTEGER NOT NULL,
                bidder TEXT NOT NULL,
                amount REAL NOT NULL,
                timestamp TEXT NOT NULL,
                bid_data TEXT,
                hmac_tag TEXT,
                signature TEXT,
                FOREIGN KEY (auction_id) REFERENCES auctions(id),
                FOREIGN KEY (bidder) REFERENCES users(username)
            )
        ''')
        self.db_conn.commit()

    def _init_pki(self):
        logger.info("=== Inicializando PKI ===")
        self.root_ca = CertificateAuthority("Root-CA", is_root=True)
        self.sub_ca = CertificateAuthority("Sub-CA-Madrid", is_root=False, parent_ca=self.root_ca)
        logger.info("✓ PKI inicializada (Root CA + Sub-CA)")

    # ---------- Registro / Autenticación ----------

    def register_user(self, username: str, password: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cur.fetchone():
            logger.error(f"El usuario '{username}' ya existe")
            return False

        salt = secrets.token_hex(16)  # 16 bytes -> 32 hex
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=100_000)
        password_hash = base64.b64encode(kdf.derive(password.encode())).decode()

        # Generar par RSA (usuario)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_path = KEYS_DIR / f"{username}_private.pem"
        with open(private_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        public_key_path = KEYS_DIR / f"{username}_public.pem"
        with open(public_key_path, "wb") as f:
            f.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        cert_path = self.sub_ca.issue_certificate(username, str(public_key_path))

        cur.execute('''
            INSERT INTO users (username, password_hash, salt, public_key_path, private_key_path, certificate_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, str(public_key_path), str(private_key_path), cert_path))
        self.db_conn.commit()

        logger.info(f"✓ Usuario '{username}' registrado | PBKDF2-HMAC-SHA256 (100k iters) | RSA-2048 | Cert emitido")
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            logger.error(f"Usuario '{username}' no encontrado")
            return False
        stored_hash, salt = row
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=100_000)
        try:
            computed = base64.b64encode(kdf.derive(password.encode())).decode()
            ok = (computed == stored_hash)
            if ok:
                self.current_user = username
                logger.info(f"✓ Usuario '{username}' autenticado")
            else:
                logger.error("Credenciales incorrectas")
            return ok
        except Exception as e:
            logger.error(f"Error en autenticación: {e}")
            return False

    # ---------- Subastas ----------

    def create_auction(self, title: str, description: str, start_price: float, end_date: str, encrypt: bool=True) -> int:
        if not self.current_user:
            logger.error("Debe iniciar sesión para crear una subasta")
            return -1

        if encrypt:
            # AES-256-CBC con padding PKCS#7 manual
            key = os.urandom(32)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            data = description.encode()
            pad_len = 16 - (len(data) % 16)
            data += bytes([pad_len]) * pad_len
            encrypted_desc = encryptor.update(data) + encryptor.finalize()
            description_enc = base64.b64encode(encrypted_desc).decode()
            # Guardar key+iv en fichero (demo; en producción, KMS)
            key_file = DATA_DIR / f"auction_key_{datetime.datetime.now().timestamp()}.bin"
            with open(key_file, "wb") as f:
                f.write(key + iv)
            logger.info("✓ Descripción cifrada | AES-256-CBC (IV 128b)")
            final_description = description_enc
            enc_flag = 1
        else:
            final_description = description
            enc_flag = 0

        cur = self.db_conn.cursor()
        cur.execute('''
            INSERT INTO auctions (title, description, seller, start_price, current_price,
                                  highest_bidder, end_date, status, encrypted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, final_description, self.current_user, start_price, start_price,
              None, end_date, 'active', enc_flag))
        self.db_conn.commit()
        aid = cur.lastrowid
        logger.info(f"✓ Subasta #{aid} creada por '{self.current_user}'")
        return aid

    def place_bid(self, auction_id: int, amount: float) -> bool:
        if not self.current_user:
            logger.error("Debe iniciar sesión para pujar")
            return False

        cur = self.db_conn.cursor()
        cur.execute("SELECT current_price, status FROM auctions WHERE id=?", (auction_id,))
        row = cur.fetchone()
        if not row:
            logger.error(f"Subasta #{auction_id} no encontrada")
            return False
        current_price, status = row
        if status != 'active':
            logger.error("La subasta no está activa")
            return False
        if amount <= current_price:
            logger.error(f"La puja debe ser mayor a {current_price}")
            return False

        ts = datetime.datetime.now().isoformat()
        bid_data = json.dumps({'auction_id': auction_id, 'bidder': self.current_user, 'amount': amount, 'timestamp': ts})

        # HMAC-SHA256 (integridad)
        hmac_key = os.urandom(32)
        tag = std_hmac.new(hmac_key, bid_data.encode(), hashlib.sha256).hexdigest()
        hmac_file = DATA_DIR / f"bid_hmac_{ts.replace(':','-')}.key"
        with open(hmac_file, "wb") as f:
            f.write(hmac_key)
        logger.info("✓ HMAC-SHA256 generado (key 256b)")

        # Firma digital RSA-PSS
        cur.execute("SELECT private_key_path FROM users WHERE username=?", (self.current_user,))
        private_key_path = cur.fetchone()[0]
        password = getpass.getpass("Contraseña para firmar la puja: ")
        try:
            with open(private_key_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=password.encode())
            signature = priv.sign(
                bid_data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            sig_b64 = base64.b64encode(signature).decode()
            logger.info("✓ Firma RSA-PSS generada | RSA-2048 | SHA-256")

            cur.execute('''
                INSERT INTO bids (auction_id, bidder, amount, timestamp, bid_data, hmac_tag, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (auction_id, self.current_user, amount, ts, bid_data, tag, sig_b64))
            cur.execute('UPDATE auctions SET current_price=?, highest_bidder=? WHERE id=?',
                        (amount, self.current_user, auction_id))
            self.db_conn.commit()

            # Verificaciones inmediatas
            self._verify_bid_integrity(bid_data, tag, hmac_file)
            self._verify_bid_signature(bid_data, sig_b64, self.current_user)
            logger.info(f"✓ Puja de {amount}€ registrada en subasta #{auction_id}")
            return True
        except Exception as e:
            logger.error(f"Error al firmar la puja: {e}")
            return False

    def _verify_bid_integrity(self, bid_data: str, hmac_tag: str, hmac_file: Path) -> bool:
        with open(hmac_file, "rb") as f:
            key = f.read()
        comp = std_hmac.new(key, bid_data.encode(), hashlib.sha256).hexdigest()
        if std_hmac.compare_digest(comp, hmac_tag):
            logger.info("✓ HMAC verificado OK")
            return True
        logger.error("✗ HMAC inválido")
        return False

    def _verify_bid_signature(self, bid_data: str, signature_b64: str, username: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT certificate_path FROM users WHERE username=?", (username,))
        cert_path = cur.fetchone()[0]
        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        pub = cert.public_key()
        sig = base64.b64decode(signature_b64)
        try:
            pub.verify(sig, bid_data.encode(),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                       hashes.SHA256())
            logger.info(f"✓ Firma verificada para '{username}'")
            self._verify_certificate_chain(cert_path)
            return True
        except Exception as e:
            logger.error(f"✗ Firma inválida: {e}")
            return False

    def _verify_certificate_chain(self, user_cert_path: str) -> bool:
        try:
            with open(user_cert_path, "rb") as f:
                user_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.sub_ca.cert_path, "rb") as f:
                sub_cert = x509.load_pem_x509_certificate(f.read())
            with open(self.root_ca.cert_path, "rb") as f:
                root_cert = x509.load_pem_x509_certificate(f.read())

            if user_cert.issuer == sub_cert.subject and sub_cert.issuer == root_cert.subject:
                logger.info("✓ Cadena de certificación: User ← SubCA ← Root")
                return True
            logger.error("✗ Cadena de certificación inválida")
            return False
        except Exception as e:
            logger.error(f"✗ Error cadena PKI: {e}")
            return False

    def close_auction(self, auction_id: int) -> bool:
        if not self.current_user:
            logger.error("Debe iniciar sesión")
            return False
        cur = self.db_conn.cursor()
        cur.execute("SELECT seller, highest_bidder, current_price, title FROM auctions WHERE id=?", (auction_id,))
        row = cur.fetchone()
        if not row:
            logger.error("Subasta no encontrada")
            return False
        seller, winner, final_price, title = row
        if seller != self.current_user:
            logger.error("Solo el vendedor puede cerrar la subasta")
            return False

        cur.execute("UPDATE auctions SET status='closed' WHERE id=?", (auction_id,))
        self.db_conn.commit()

        if not winner:
            logger.info(f"✓ Subasta #{auction_id} cerrada sin pujas")
            return True

        close_doc = {
            'auction_id': auction_id, 'title': title, 'seller': seller,
            'winner': winner, 'final_price': final_price, 'close_date': datetime.datetime.now().isoformat()
        }
        doc_json = json.dumps(close_doc, indent=2)
        cur.execute("SELECT private_key_path FROM users WHERE username=?", (self.current_user,))
        private_key_path = cur.fetchone()[0]
        password = getpass.getpass("Contraseña para firmar cierre: ")
        try:
            with open(private_key_path, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=password.encode())
            signature = priv.sign(
                doc_json.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            doc_file = DATA_DIR / f"auction_{auction_id}_close.json"
            sig_file = DATA_DIR / f"auction_{auction_id}_close.sig"
            with open(doc_file, "w") as f: f.write(doc_json)
            with open(sig_file, "wb") as f: f.write(signature)
            logger.info(f"✓ Subasta #{auction_id} cerrada | Ganador: {winner} | Doc firmado")
            return True
        except Exception as e:
            logger.error(f"Error al firmar cierre: {e}")
            return False

    def list_auctions(self):
        cur = self.db_conn.cursor()
        cur.execute('''
            SELECT id, title, seller, current_price, highest_bidder, end_date, status
            FROM auctions ORDER BY status, id DESC
        ''')
        auctions = cur.fetchall()
        if not auctions:
            print("\nNo hay subastas disponibles")
            return
        print("\n" + "="*70)
        print("LISTADO DE SUBASTAS")
        print("="*70)
        for (id_, title, seller, price, winner, end_date, status) in auctions:
            print(f"\n#{id_} - {title}")
            print(f"  Vendedor: {seller}")
            print(f"  Precio actual: {price}€")
            print(f"  Mejor postor: {winner if winner else 'Sin pujas'}")
            print(f"  Fecha fin: {end_date}")
            print(f"  Estado: {status}")
            print("-"*50)

def main_menu():
    platform = AuctionPlatform()
    while True:
        print("\n" + "="*50)
        print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS")
        print("="*50)
        print(f"Usuario actual: {platform.current_user or 'No autenticado'}")
        print("\n1. Registrar nuevo usuario")
        print("2. Iniciar sesión")
        print("3. Crear subasta")
        print("4. Realizar puja")
        print("5. Listar subastas")
        print("6. Cerrar subasta")
        print("7. Cerrar sesión")
        print("8. Salir")

        choice = input("\nSeleccione una opción: ").strip()
        if choice == '1':
            username = input("Nombre de usuario: ").strip()
            password = getpass.getpass("Contraseña: ")
            password2 = getpass.getpass("Confirmar contraseña: ")
            if password != password2:
                print("Las contraseñas no coinciden"); continue
            if len(password) < 8:
                print("La contraseña debe tener al menos 8 caracteres"); continue
            platform.register_user(username, password)
        elif choice == '2':
            username = input("Nombre de usuario: ").strip()
            password = getpass.getpass("Contraseña: ")
            if platform.authenticate_user(username, password):
                print(f"Bienvenido, {username}!")
            else:
                print("Credenciales incorrectas")
        elif choice == '3':
            if not platform.current_user:
                print("Debe iniciar sesión primero"); continue
            title = input("Título de la subasta: ")
            description = input("Descripción: ")
            start_price = float(input("Precio inicial (€): "))
            days = int(input("Duración (días): "))
            encrypt = input("¿Cifrar descripción? (s/n): ").lower() == 's'
            end_date = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
            aid = platform.create_auction(title, description, start_price, end_date, encrypt)
            if aid > 0: print(f"Subasta #{aid} creada")
        elif choice == '4':
            if not platform.current_user:
                print("Debe iniciar sesión primero"); continue
            auction_id = int(input("ID de la subasta: "))
            amount = float(input("Monto de la puja (€): "))
            if platform.place_bid(auction_id, amount):
                print("Puja realizada")
        elif choice == '5':
            platform.list_auctions()
        elif choice == '6':
            if not platform.current_user:
                print("Debe iniciar sesión primero"); continue
            auction_id = int(input("ID de la subasta a cerrar: "))
            if platform.close_auction(auction_id):
                print("Subasta cerrada")
        elif choice == '7':
            platform.current_user = None
            print("Sesión cerrada")
        elif choice == '8':
            print("¡Hasta luego!"); break
        else:
            print("Opción no válida")

if __name__ == "__main__":
    print("\n" + "="*70)
    print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS CON CRIPTOGRAFÍA")
    print("Práctica de Criptografía y Seguridad Informática")
    print("="*70)
    logger.info("=== Iniciando Plataforma de Subastas ===")
    main_menu()
