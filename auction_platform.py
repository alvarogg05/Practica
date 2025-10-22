"""Lógica principal de la plataforma de subastas electrónicas."""

import base64
import datetime
import getpass
import json
import secrets
import sqlite3
from pathlib import Path
from typing import Optional

import hashlib
import hmac as std_hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from config import DB_FILE, DATA_DIR, KEYS_DIR, logger
from crypto_utils import derive_password_hash, encrypt_description, generate_bid_hmac, verify_password
from pki import CertificateAuthority


class AuctionPlatform:
    """Plataforma principal de subastas electrónicas."""

    def __init__(self):
        self.db_conn = None
        self.current_user: Optional[str] = None
        self.root_ca: Optional[CertificateAuthority] = None
        self.sub_ca: Optional[CertificateAuthority] = None
        self._init_database()
        self._init_pki()

    def _init_database(self) -> None:
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

    def _init_pki(self) -> None:
        logger.info("=== Inicializando PKI ===")
        self.root_ca = CertificateAuthority("Root-CA", is_root=True)
        self.sub_ca = CertificateAuthority("Sub-CA-Madrid", is_root=False, parent_ca=self.root_ca)
        logger.info("[OK] PKI inicializada (Root CA + Sub-CA)")

    def register_user(self, username: str, password: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cur.fetchone():
            logger.error(f"El usuario '{username}' ya existe")
            return False

        salt = secrets.token_hex(16)
        password_hash = derive_password_hash(password, salt)

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_path = KEYS_DIR / f"{username}_private.pem"
        with open(private_key_path, "wb") as file:
            file.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ))
        public_key_path = KEYS_DIR / f"{username}_public.pem"
        with open(public_key_path, "wb") as file:
            file.write(private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        cert_path = self.sub_ca.issue_certificate(username, str(public_key_path))

        cur.execute('''
            INSERT INTO users (username, password_hash, salt, public_key_path, private_key_path, certificate_path)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, str(public_key_path), str(private_key_path), cert_path))
        self.db_conn.commit()
        logger.info(
            f"[OK] Usuario '{username}' registrado | PBKDF2-HMAC-SHA256 (100k iters) | RSA-2048 | Cert emitido"
        )
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT password_hash, salt FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row:
            logger.error(f"Usuario '{username}' no encontrado")
            return False
        stored_hash, salt = row
        ok = verify_password(password, salt, stored_hash)
        if ok:
            self.current_user = username
            logger.info(f"[OK] Usuario '{username}' autenticado")
        else:
            logger.error("Credenciales incorrectas")
        return ok

    def create_auction(self, title: str, description: str, start_price: float, end_date: str, encrypt: bool = True) -> int:
        if not self.current_user:
            logger.error("Debe iniciar sesión para crear una subasta")
            return -1

        final_description = description
        enc_flag = 0
        if encrypt:
            final_description, _ = encrypt_description(description)
            enc_flag = 1

        cur = self.db_conn.cursor()
        cur.execute('''
            INSERT INTO auctions (title, description, seller, start_price, current_price,
                                  highest_bidder, end_date, status, encrypted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, final_description, self.current_user, start_price, start_price,
              None, end_date, 'active', enc_flag))
        self.db_conn.commit()
        auction_id = cur.lastrowid
        logger.info(f"[OK] Subasta #{auction_id} creada por '{self.current_user}'")
        return auction_id

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

        timestamp = datetime.datetime.now().isoformat()
        bid_data = json.dumps({
            'auction_id': auction_id,
            'bidder': self.current_user,
            'amount': amount,
            'timestamp': timestamp
        })

        tag, hmac_file = generate_bid_hmac(bid_data, timestamp)

        cur.execute("SELECT private_key_path FROM users WHERE username=?", (self.current_user,))
        private_key_path = cur.fetchone()[0]
        password = getpass.getpass("Contraseña para firmar la puja: ")
        try:
            with open(private_key_path, "rb") as file:
                private_key = serialization.load_pem_private_key(file.read(), password=password.encode())
            signature = private_key.sign(
                bid_data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            signature_b64 = base64.b64encode(signature).decode()
            logger.info("[OK] Firma RSA-PSS generada | RSA-2048 | SHA-256")

            cur.execute('''
                INSERT INTO bids (auction_id, bidder, amount, timestamp, bid_data, hmac_tag, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (auction_id, self.current_user, amount, timestamp, bid_data, tag, signature_b64))
            cur.execute('UPDATE auctions SET current_price=?, highest_bidder=? WHERE id=?',
                        (amount, self.current_user, auction_id))
            self.db_conn.commit()

            self._verify_bid_integrity(bid_data, tag, hmac_file)
            self._verify_bid_signature(bid_data, signature_b64, self.current_user)
            logger.info(f"[OK] Puja de {amount}€ registrada en subasta #{auction_id}")
            return True
        except Exception as error:
            logger.error(f"Error al firmar la puja: {error}")
            return False

    def _verify_bid_integrity(self, bid_data: str, hmac_tag: str, hmac_file: Path) -> bool:
        with open(hmac_file, "rb") as file:
            key = file.read()
        computed = std_hmac.new(key, bid_data.encode(), hashlib.sha256).hexdigest()
        if std_hmac.compare_digest(computed, hmac_tag):
            logger.info("[OK] HMAC verificado OK")
            return True
        logger.error("[ERR] HMAC inválido")
        return False

    def _verify_bid_signature(self, bid_data: str, signature_b64: str, username: str) -> bool:
        cur = self.db_conn.cursor()
        cur.execute("SELECT certificate_path FROM users WHERE username=?", (username,))
        cert_path = cur.fetchone()[0]
        with open(cert_path, "rb") as file:
            cert = x509.load_pem_x509_certificate(file.read())
        public_key = cert.public_key()
        signature = base64.b64decode(signature_b64)
        try:
            public_key.verify(
                signature,
                bid_data.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            logger.info(f"[OK] Firma verificada para '{username}'")
            self._verify_certificate_chain(cert_path)
            return True
        except Exception as error:
            logger.error(f"[ERR] Firma inválida: {error}")
            return False

    def _verify_certificate_chain(self, user_cert_path: str) -> bool:
        try:
            with open(user_cert_path, "rb") as file:
                user_cert = x509.load_pem_x509_certificate(file.read())
            with open(self.sub_ca.cert_path, "rb") as file:
                sub_cert = x509.load_pem_x509_certificate(file.read())
            with open(self.root_ca.cert_path, "rb") as file:
                root_cert = x509.load_pem_x509_certificate(file.read())

            if user_cert.issuer == sub_cert.subject and sub_cert.issuer == root_cert.subject:
                logger.info("[OK] Cadena de certificación: User <- SubCA <- Root")
                return True
            logger.error("[ERR] Cadena de certificación inválida")
            return False
        except Exception as error:
            logger.error(f"[ERR] Error cadena PKI: {error}")
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
            logger.info(f"[OK] Subasta #{auction_id} cerrada sin pujas")
            return True

        close_doc = {
            'auction_id': auction_id,
            'title': title,
            'seller': seller,
            'winner': winner,
            'final_price': final_price,
            'close_date': datetime.datetime.now().isoformat()
        }
        doc_json = json.dumps(close_doc, indent=2)
        cur.execute("SELECT private_key_path FROM users WHERE username=?", (self.current_user,))
        private_key_path = cur.fetchone()[0]
        password = getpass.getpass("Contraseña para firmar cierre: ")
        try:
            with open(private_key_path, "rb") as file:
                private_key = serialization.load_pem_private_key(file.read(), password=password.encode())
            signature = private_key.sign(
                doc_json.encode(),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            doc_file = DATA_DIR / f"auction_{auction_id}_close.json"
            sig_file = DATA_DIR / f"auction_{auction_id}_close.sig"
            with open(doc_file, "w") as file:
                file.write(doc_json)
            with open(sig_file, "wb") as file:
                file.write(signature)
            logger.info(f"[OK] Subasta #{auction_id} cerrada | Ganador: {winner} | Doc firmado")
            return True
        except Exception as error:
            logger.error(f"Error al firmar cierre: {error}")
            return False

    def list_auctions(self) -> None:
        cur = self.db_conn.cursor()
        cur.execute('''
            SELECT id, title, seller, current_price, highest_bidder, end_date, status
            FROM auctions ORDER BY status, id DESC
        ''')
        auctions = cur.fetchall()
        if not auctions:
            print("\nNo hay subastas disponibles")
            return
        print("\n" + "=" * 70)
        print("LISTADO DE SUBASTAS")
        print("=" * 70)
        for (auction_id, title, seller, price, winner, end_date, status) in auctions:
            print(f"\n#{auction_id} - {title}")
            print(f"  Vendedor: {seller}")
            print(f"  Precio actual: {price}€")
            print(f"  Mejor postor: {winner if winner else 'Sin pujas'}")
            print(f"  Fecha fin: {end_date}")
            print(f"  Estado: {status}")
            print("-" * 50)
