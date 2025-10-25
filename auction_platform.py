"""
Lógica principal de la plataforma de subastas electrónicas.

Este módulo concentra la capa de aplicación: alta/login de usuarios, creación de
subastas, pujas y cierre. Se apoya en config para constantes y logging y en
crypto_utils para operaciones criptográficas reutilizables.
"""

import datetime
import json
import secrets
import sqlite3
from typing import Optional

import hashlib
import hmac as std_hmac

from config import DB_FILE, DATA_DIR, SAVE_ACTA_JSON, logger
from crypto_utils import derive_password_hash, encrypt_description, generate_bid_hmac, verify_password


class AuctionPlatform:
    """Plataforma principal de subastas electrónicas."""

    def __init__(self):
        """Inicializa recursos base: BD y estructuras internas."""
        self.db_conn = sqlite3.connect(DB_FILE)
        self.current_user: Optional[str] = None
        self._init_database()

    def _init_database(self) -> None:
        """Crea (si hace falta) el esquema SQLite para usuarios, subastas y pujas."""
        cur = self.db_conn.cursor()

        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL
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
                FOREIGN KEY (auction_id) REFERENCES auctions(id),
                FOREIGN KEY (bidder) REFERENCES users(username)
            )
        ''')
        self.db_conn.commit()

    def register_user(self, username: str, password: str) -> bool:
        """Registra un usuario aplicando PBKDF2-HMAC-SHA256 a la contraseña."""
        cur = self.db_conn.cursor()
        cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
        if cur.fetchone():
            logger.error(f"El usuario '{username}' ya existe")
            return False

        salt = secrets.token_hex(16)
        password_hash = derive_password_hash(password, salt)

        cur.execute('''
            INSERT INTO users (username, password_hash, salt)
            VALUES (?, ?, ?)
        ''', (username, password_hash, salt))
        self.db_conn.commit()
        logger.info(
            f"[OK] Usuario '{username}' registrado | PBKDF2-HMAC-SHA256 (100k iters)"
        )
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        """Autentica al usuario volviendo a derivar el hash y comparándolo."""
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
        """Crea una subasta; opcionalmente cifra la descripción (AES-256-CBC)."""
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
        assert auction_id is not None
        logger.info(f"[OK] Subasta #{auction_id} creada por '{self.current_user}'")
        return auction_id

    def place_bid(self, auction_id: int, amount: float) -> bool:
        """Registra una puja válida y la protege con HMAC-SHA256."""
        if not self.current_user:
            logger.error("Debe iniciar sesión para pujar")
            return False

        cur = self.db_conn.cursor()
        cur.execute("SELECT current_price, status, seller FROM auctions WHERE id=?", (auction_id,))
        row = cur.fetchone()
        if not row:
            logger.error(f"Subasta #{auction_id} no encontrada")
            return False
        current_price, status, seller = row
        if status != 'active':
            logger.error("La subasta no está activa")
            return False
        if seller == self.current_user:
            logger.error("El vendedor no puede pujar en su propia subasta")
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
        # HMAC: integridad con clave simétrica efímera (no persistimos la clave)
        tag, hmac_key = generate_bid_hmac(bid_data)

        cur.execute('''
            INSERT INTO bids (auction_id, bidder, amount, timestamp, bid_data, hmac_tag)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (auction_id, self.current_user, amount, timestamp, bid_data, tag))
        cur.execute('UPDATE auctions SET current_price=?, highest_bidder=? WHERE id=?',
                    (amount, self.current_user, auction_id))
        self.db_conn.commit()

        # Verificamos inmediatamente usando la clave efímera en memoria
        self._verify_bid_integrity(bid_data, tag, hmac_key)
        logger.info(f"[OK] Puja de {amount}€ registrada en subasta #{auction_id}")
        return True

    def _verify_bid_integrity(self, bid_data: str, hmac_tag: str, hmac_key: bytes) -> bool:
        """Recalcula HMAC y lo compara de forma segura (compare_digest)."""
        computed = std_hmac.new(hmac_key, bid_data.encode(), hashlib.sha256).hexdigest()
        if std_hmac.compare_digest(computed, hmac_tag):
            logger.info("[OK] HMAC verificado OK")
            return True
        logger.error("[ERR] HMAC inválido")
        return False

    def close_auction(self, auction_id: int) -> bool:
        """
        Cierra una subasta y registra el resultado. 
        Según configuración (SAVE_ACTA_JSON), puede generarse un acta JSON en disco.
        """
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

        # Documento de cierre con metadatos mínimos
        close_doc = {
            'auction_id': auction_id,
            'title': title,
            'seller': seller,
            'winner': winner,
            'final_price': final_price,
            'close_date': datetime.datetime.now().isoformat()
        }
        if SAVE_ACTA_JSON:
            doc_file = DATA_DIR / f"auction_{auction_id}_close.json"
            with open(doc_file, "w", encoding="utf-8") as file:
                json.dump(close_doc, file, indent=2)
            logger.info(f"[OK] Subasta #{auction_id} cerrada | Ganador: {winner} | Acta almacenada")
        else:
            logger.info(f"[OK] Subasta #{auction_id} cerrada | Ganador: {winner}")
        return True

    def list_auctions(self) -> None:
        """Muestra por consola un listado simple de subastas ordenado por estado."""
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
