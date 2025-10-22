#!/usr/bin/env python3
"""
Gestor de pujas.
Maneja todo lo relacionado con las pujas: creación, validación, firmas, etc.
"""

import json
import datetime
import logging
import getpass
from pathlib import Path

from database import Database
from crypto_utils import CryptoUtils
from auth_manager import AuthManager
from pki_manager import PKIManager

logger = logging.getLogger(__name__)

# Directorio para datos de pujas
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)


class BidManager:
    """
    Gestor de pujas.
    Crea pujas con HMAC (integridad) y firmas digitales (autenticidad).
    """
    
    def __init__(self, db: Database, auth: AuthManager, pki: PKIManager):
        """
        Inicializa el gestor de pujas.
        
        Args:
            db: Instancia de la base de datos
            auth: Gestor de autenticación
            pki: Gestor PKI
        """
        self.db = db
        self.auth = auth
        self.pki = pki
    
    def place_bid(self, auction_id: int, amount: float) -> bool:
        """
        Registra una nueva puja en una subasta.
        
        El proceso incluye:
        1. Verificar que la subasta existe y está activa
        2. Verificar que la puja es mayor que el precio actual
        3. Generar datos de la puja en JSON
        4. Calcular HMAC-SHA256 para integridad
        5. Firmar digitalmente con RSA-PSS
        6. Guardar en la BD
        7. Verificar inmediatamente HMAC y firma
        
        Args:
            auction_id: ID de la subasta
            amount: Cantidad a pujar (en €)
            
        Returns:
            True si la puja se registró correctamente, False si hubo error
        """
        # Verificar que hay un usuario autenticado
        if not self.auth.is_authenticated():
            logger.error("Debe iniciar sesión para pujar")
            return False
        
        username = self.auth.get_current_user()
        cur = self.db.get_cursor()
        
        # Verificar que la subasta existe y está activa
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
            logger.error(f"La puja debe ser mayor a {current_price}€")
            return False
        
        # Crear datos de la puja en formato JSON
        timestamp = datetime.datetime.now().isoformat()
        bid_data = json.dumps({
            'auction_id': auction_id,
            'bidder': username,
            'amount': amount,
            'timestamp': timestamp
        })
        
        # Generar HMAC-SHA256 para integridad
        hmac_tag, hmac_file = CryptoUtils.generate_hmac(bid_data)
        
        # Obtener la clave privada del usuario para firmar
        private_key_path = self.auth.get_user_private_key_path()
        
        # Pedir contraseña para desbloquear la clave privada
        password = getpass.getpass("Contraseña para firmar la puja: ")
        
        try:
            # Firmar digitalmente la puja con RSA-PSS
            signature_b64 = CryptoUtils.sign_data(bid_data, private_key_path, password)
            
            # Guardar la puja en la BD
            cur.execute('''
                INSERT INTO bids (auction_id, bidder, amount, timestamp, 
                                bid_data, hmac_tag, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (auction_id, username, amount, timestamp, 
                  bid_data, hmac_tag, signature_b64))
            
            # Actualizar el precio actual y mejor postor de la subasta
            cur.execute('''
                UPDATE auctions 
                SET current_price=?, highest_bidder=? 
                WHERE id=?
            ''', (amount, username, auction_id))
            
            self.db.commit()
            
            # Verificaciones inmediatas (para asegurar que todo está OK)
            self._verify_bid_integrity(bid_data, hmac_tag, hmac_file)
            self._verify_bid_signature(bid_data, signature_b64, username)
            
            logger.info(f"✓ Puja de {amount}€ registrada en subasta #{auction_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error al firmar la puja: {e}")
            return False
    
    def _verify_bid_integrity(self, bid_data: str, hmac_tag: str, hmac_file: str) -> bool:
        """
        Verifica la integridad de una puja usando HMAC.
        
        Args:
            bid_data: Datos de la puja en JSON
            hmac_tag: Tag HMAC calculado
            hmac_file: Path al archivo con la clave HMAC
            
        Returns:
            True si el HMAC es válido, False si no
        """
        return CryptoUtils.verify_hmac(bid_data, hmac_tag, hmac_file)
    
    def _verify_bid_signature(self, bid_data: str, signature_b64: str, username: str) -> bool:
        """
        Verifica la firma digital de una puja.
        
        Args:
            bid_data: Datos de la puja en JSON
            signature_b64: Firma en base64
            username: Usuario que firmó
            
        Returns:
            True si la firma es válida, False si no
        """
        # Obtener el certificado del usuario
        cert_path = self.auth.get_user_certificate_path(username)
        
        if not cert_path:
            logger.error(f"No se encontró certificado para '{username}'")
            return False
        
        # Verificar la firma
        if not CryptoUtils.verify_signature(bid_data, signature_b64, cert_path):
            return False
        
        # Verificar la cadena de certificación
        return self.pki.verify_certificate_chain(cert_path)
    
    def get_auction_bids(self, auction_id: int) -> list:
        """
        Obtiene todas las pujas de una subasta.
        
        Args:
            auction_id: ID de la subasta
            
        Returns:
            Lista de tuplas con (id, bidder, amount, timestamp)
        """
        cur = self.db.get_cursor()
        cur.execute('''
            SELECT id, bidder, amount, timestamp
            FROM bids
            WHERE auction_id=?
            ORDER BY timestamp DESC
        ''', (auction_id,))
        
        return cur.fetchall()
