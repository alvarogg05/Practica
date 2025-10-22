#!/usr/bin/env python3
"""
Módulo para gestionar la base de datos de la plataforma de subastas.
Aquí va todo lo relacionado con SQLite y las operaciones CRUD básicas.
"""

import sqlite3
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

# Config de la BD
DB_FILE = "auction_platform.db"


class Database:
    """
    Clase para manejar la conexión y operaciones con la base de datos.
    Básicamente es un wrapper de SQLite para no tener que escribir
    las mismas queries mil veces.
    """
    
    def __init__(self, db_file: str = DB_FILE):
        """Inicializa la conexión y crea las tablas si no existen"""
        self.db_file = db_file
        self.conn = None
        self._connect()
        self._create_tables()
    
    def _connect(self):
        """Conecta con la BD (o la crea si no existe)"""
        self.conn = sqlite3.connect(self.db_file)
        logger.info(f"Conectado a la base de datos: {self.db_file}")
    
    def _create_tables(self):
        """
        Crea las tablas necesarias para el sistema.
        Tenemos: usuarios, subastas y pujas.
        """
        cur = self.conn.cursor()
        
        # Tabla de usuarios - guarda las credenciales y paths de keys
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
        
        # Tabla de subastas - info de cada subasta
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
        
        # Tabla de pujas - historial de todas las pujas
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
        
        self.conn.commit()
        logger.info("Tablas de la BD inicializadas correctamente")
    
    def get_cursor(self):
        """Devuelve un cursor para hacer queries custom si hace falta"""
        return self.conn.cursor()
    
    def commit(self):
        """Guarda los cambios en la BD"""
        self.conn.commit()
    
    def close(self):
        """Cierra la conexión (importante hacerlo al terminar)"""
        if self.conn:
            self.conn.close()
            logger.info("Conexión a BD cerrada")
