#!/usr/bin/env python3
"""
Gestor de subastas.
Maneja creación, cierre y listado de subastas.
"""

import json
import datetime
import logging
import getpass
from pathlib import Path

from database import Database
from crypto_utils import CryptoUtils
from auth_manager import AuthManager

logger = logging.getLogger(__name__)

# Directorio para datos de subastas
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


class AuctionManager:
    """
    Gestor de subastas.
    Crea subastas (con cifrado opcional de descripción), las cierra y lista.
    """
    
    def __init__(self, db: Database, auth: AuthManager):
        """
        Inicializa el gestor de subastas.
        
        Args:
            db: Instancia de la base de datos
            auth: Gestor de autenticación
        """
        self.db = db
        self.auth = auth
    
    def create_auction(self, title: str, description: str, start_price: float,
                      end_date: str, encrypt: bool = True) -> int:
        """
        Crea una nueva subasta.
        
        Args:
            title: Título de la subasta
            description: Descripción del artículo
            start_price: Precio inicial (en €)
            end_date: Fecha de finalización (ISO format)
            encrypt: Si True, cifra la descripción con AES-256-CBC
            
        Returns:
            ID de la subasta creada, o -1 si hubo error
        """
        # Verificar que hay un usuario autenticado
        if not self.auth.is_authenticated():
            logger.error("Debe iniciar sesión para crear una subasta")
            return -1
        
        username = self.auth.get_current_user()
        
        # Asegurar que existe el directorio de datos
        DATA_DIR.mkdir(exist_ok=True)
        
        # Cifrar descripción si se solicita
        if encrypt:
            description_enc, key_file = CryptoUtils.encrypt_aes_cbc(description)
            final_description = description_enc
            enc_flag = 1
        else:
            final_description = description
            enc_flag = 0
        
        # Guardar en la BD
        cur = self.db.get_cursor()
        cur.execute('''
            INSERT INTO auctions (title, description, seller, start_price, 
                                current_price, highest_bidder, end_date, 
                                status, encrypted)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (title, final_description, username, start_price, start_price,
              None, end_date, 'active', enc_flag))
        
        self.db.commit()
        auction_id = cur.lastrowid
        
        logger.info(f"✓ Subasta #{auction_id} creada por '{username}'")
        return auction_id
    
    def close_auction(self, auction_id: int) -> bool:
        """
        Cierra una subasta y genera un documento firmado con el resultado.
        
        Solo el vendedor puede cerrar su propia subasta.
        Si hay ganador, se genera un documento JSON firmado digitalmente.
        
        Args:
            auction_id: ID de la subasta a cerrar
            
        Returns:
            True si se cerró correctamente, False si hubo error
        """
        # Verificar que hay un usuario autenticado
        if not self.auth.is_authenticated():
            logger.error("Debe iniciar sesión para cerrar una subasta")
            return False
        
        username = self.auth.get_current_user()
        cur = self.db.get_cursor()
        
        # Obtener datos de la subasta
        cur.execute('''
            SELECT seller, highest_bidder, current_price, title, status
            FROM auctions WHERE id=?
        ''', (auction_id,))
        
        row = cur.fetchone()
        
        if not row:
            logger.error(f"Subasta #{auction_id} no encontrada")
            return False
        
        seller, winner, final_price, title, status = row
        
        # Verificar que el usuario actual es el vendedor
        if seller != username:
            logger.error("Solo el vendedor puede cerrar la subasta")
            return False
        
        # Verificar que no esté ya cerrada
        if status == 'closed':
            logger.error("La subasta ya está cerrada")
            return False
        
        # Cerrar la subasta
        cur.execute("UPDATE auctions SET status='closed' WHERE id=?", (auction_id,))
        self.db.commit()
        
        # Si no hubo pujas, terminar aquí
        if not winner:
            logger.info(f"✓ Subasta #{auction_id} cerrada sin pujas")
            return True
        
        # Asegurar que existe el directorio de datos
        DATA_DIR.mkdir(exist_ok=True)
        
        # Generar documento de cierre (JSON con info del resultado)
        close_doc = {
            'auction_id': auction_id,
            'title': title,
            'seller': seller,
            'winner': winner,
            'final_price': final_price,
            'close_date': datetime.datetime.now().isoformat()
        }
        doc_json = json.dumps(close_doc, indent=2)
        
        # Obtener clave privada para firmar el documento
        private_key_path = self.auth.get_user_private_key_path()
        password = getpass.getpass("Contraseña para firmar el cierre: ")
        
        try:
            # Firmar el documento con RSA-PSS
            signature = CryptoUtils.sign_data(doc_json, private_key_path, password)
            
            # Guardar documento y firma
            doc_file = DATA_DIR / f"auction_{auction_id}_close.json"
            sig_file = DATA_DIR / f"auction_{auction_id}_close.sig"
            
            with open(doc_file, "w") as f:
                f.write(doc_json)
            
            with open(sig_file, "w") as f:
                f.write(signature)
            
            logger.info(f"✓ Subasta #{auction_id} cerrada | Ganador: {winner} | Precio: {final_price}€ | Doc firmado")
            return True
            
        except Exception as e:
            logger.error(f"Error al firmar el documento de cierre: {e}")
            return False
    
    def list_auctions(self):
        """
        Lista todas las subastas del sistema.
        Muestra ID, título, vendedor, precio actual, mejor postor, fecha fin y estado.
        """
        cur = self.db.get_cursor()
        cur.execute('''
            SELECT id, title, seller, current_price, highest_bidder, 
                   end_date, status
            FROM auctions 
            ORDER BY status DESC, id DESC
        ''')
        
        auctions = cur.fetchall()
        
        if not auctions:
            print("\nNo hay subastas disponibles")
            return
        
        # Mostrar las subastas de forma bonita
        print("\n" + "=" * 70)
        print("LISTADO DE SUBASTAS")
        print("=" * 70)
        
        for (id_, title, seller, price, winner, end_date, status) in auctions:
            print(f"\n#{id_} - {title}")
            print(f"  Vendedor: {seller}")
            print(f"  Precio actual: {price}€")
            print(f"  Mejor postor: {winner if winner else 'Sin pujas'}")
            print(f"  Fecha fin: {end_date}")
            print(f"  Estado: {status}")
            print("-" * 50)
    
    def get_auction_details(self, auction_id: int) -> dict:
        """
        Obtiene los detalles de una subasta específica.
        
        Args:
            auction_id: ID de la subasta
            
        Returns:
            Diccionario con los datos de la subasta, o None si no existe
        """
        cur = self.db.get_cursor()
        cur.execute('''
            SELECT id, title, description, seller, start_price, current_price,
                   highest_bidder, end_date, status, encrypted
            FROM auctions WHERE id=?
        ''', (auction_id,))
        
        row = cur.fetchone()
        
        if not row:
            return None
        
        return {
            'id': row[0],
            'title': row[1],
            'description': row[2],
            'seller': row[3],
            'start_price': row[4],
            'current_price': row[5],
            'highest_bidder': row[6],
            'end_date': row[7],
            'status': row[8],
            'encrypted': row[9]
        }
