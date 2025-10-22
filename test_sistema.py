#!/usr/bin/env python3
"""
Script de prueba básico para verificar que el sistema funciona correctamente.
Prueba las funciones principales sin intervención del usuario.
"""

import os
import sys
import datetime
import shutil
from pathlib import Path

# Importar los módulos del sistema
from database import Database
from pki_manager import PKIManager
from auth_manager import AuthManager
from auction_manager import AuctionManager
from bid_manager import BidManager
from crypto_utils import CryptoUtils

# Limpiar datos de pruebas anteriores
def cleanup_test_data():
    """Limpia archivos de pruebas anteriores"""
    files_to_remove = [
        "auction_platform.db",
        "auction_platform.log"
    ]
    dirs_to_remove = ["keys", "certs", "data"]
    
    for f in files_to_remove:
        if os.path.exists(f):
            os.remove(f)
    
    for d in dirs_to_remove:
        if os.path.exists(d):
            shutil.rmtree(d)
    
    print("✓ Datos de prueba anteriores eliminados")

def test_crypto_utils():
    """Prueba las utilidades criptográficas"""
    print("\n=== Probando CryptoUtils ===")
    
    # Test hash de contraseña
    password = "test123"
    salt = "randomsalt"
    hash1 = CryptoUtils.hash_password(password, salt)
    assert len(hash1) > 0, "El hash debe tener contenido"
    
    # Verificar que el mismo password da el mismo hash
    hash2 = CryptoUtils.hash_password(password, salt)
    assert hash1 == hash2, "El mismo password debe dar el mismo hash"
    print("✓ Hash de contraseña funciona")
    
    # Test cifrado AES
    plaintext = "Este es un mensaje secreto"
    ciphertext, key_file = CryptoUtils.encrypt_aes_cbc(plaintext)
    assert ciphertext != plaintext, "El texto cifrado debe ser diferente"
    
    decrypted = CryptoUtils.decrypt_aes_cbc(ciphertext, key_file)
    assert decrypted == plaintext, "El descifrado debe recuperar el texto original"
    print("✓ Cifrado/descifrado AES funciona")
    
    # Test HMAC
    data = "datos importantes"
    hmac_tag, hmac_file = CryptoUtils.generate_hmac(data)
    assert len(hmac_tag) > 0, "El HMAC debe tener contenido"
    
    valid = CryptoUtils.verify_hmac(data, hmac_tag, hmac_file)
    assert valid, "El HMAC debe ser válido"
    print("✓ HMAC funciona")
    
    print("✓ Todas las pruebas de CryptoUtils pasaron")

def test_database():
    """Prueba las operaciones de base de datos"""
    print("\n=== Probando Database ===")
    
    db = Database()
    cur = db.get_cursor()
    
    # Verificar que las tablas existen
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [row[0] for row in cur.fetchall()]
    
    assert 'users' in tables, "Debe existir la tabla users"
    assert 'auctions' in tables, "Debe existir la tabla auctions"
    assert 'bids' in tables, "Debe existir la tabla bids"
    print("✓ Tablas de BD creadas correctamente")
    
    db.close()
    print("✓ Todas las pruebas de Database pasaron")

def test_pki():
    """Prueba el sistema PKI"""
    print("\n=== Probando PKIManager ===")
    
    pki = PKIManager()
    
    # Verificar que las CAs se crearon
    assert pki.root_ca is not None, "Debe existir la Root CA"
    assert pki.sub_ca is not None, "Debe existir la Sub CA"
    print("✓ CAs creadas correctamente")
    
    # Verificar que existen los archivos de certificados
    assert pki.root_ca.cert_path.exists(), "Debe existir el certificado de Root CA"
    assert pki.sub_ca.cert_path.exists(), "Debe existir el certificado de Sub CA"
    print("✓ Certificados de CA guardados correctamente")
    
    print("✓ Todas las pruebas de PKI pasaron")

def test_auth_manager():
    """Prueba el gestor de autenticación"""
    print("\n=== Probando AuthManager ===")
    
    db = Database()
    pki = PKIManager()
    auth = AuthManager(db, pki)
    
    # Registrar un usuario
    username = "testuser"
    password = "testpass123"
    success = auth.register_user(username, password)
    assert success, "El registro debe ser exitoso"
    print(f"✓ Usuario '{username}' registrado correctamente")
    
    # Intentar registrar el mismo usuario (debe fallar)
    success = auth.register_user(username, password)
    assert not success, "No se debe poder registrar el mismo usuario dos veces"
    print("✓ Prevención de usuarios duplicados funciona")
    
    # Autenticar al usuario
    success = auth.authenticate_user(username, password)
    assert success, "La autenticación debe ser exitosa"
    assert auth.get_current_user() == username, "El usuario actual debe ser el autenticado"
    print(f"✓ Usuario '{username}' autenticado correctamente")
    
    # Intentar con contraseña incorrecta
    success = auth.authenticate_user(username, "wrongpass")
    assert not success, "La autenticación con contraseña incorrecta debe fallar"
    print("✓ Verificación de contraseña funciona")
    
    # Cerrar sesión
    auth.logout()
    assert auth.get_current_user() is None, "El usuario actual debe ser None después de logout"
    print("✓ Logout funciona correctamente")
    
    db.close()
    print("✓ Todas las pruebas de AuthManager pasaron")

def test_auction_manager():
    """Prueba el gestor de subastas"""
    print("\n=== Probando AuctionManager ===")
    
    db = Database()
    pki = PKIManager()
    auth = AuthManager(db, pki)
    auction_mgr = AuctionManager(db, auth)
    
    # Crear un usuario y autenticarlo
    username = "seller1"
    password = "pass123456"
    auth.register_user(username, password)
    auth.authenticate_user(username, password)
    
    # Crear una subasta sin cifrado
    end_date = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
    auction_id = auction_mgr.create_auction(
        title="Laptop Gaming",
        description="Laptop de alta gama para gaming",
        start_price=500.0,
        end_date=end_date,
        encrypt=False
    )
    assert auction_id > 0, "Debe devolver un ID de subasta válido"
    print(f"✓ Subasta #{auction_id} creada correctamente (sin cifrado)")
    
    # Crear una subasta con cifrado
    auction_id2 = auction_mgr.create_auction(
        title="iPhone 15",
        description="iPhone 15 Pro Max nuevo",
        start_price=1000.0,
        end_date=end_date,
        encrypt=True
    )
    assert auction_id2 > 0, "Debe devolver un ID de subasta válido"
    print(f"✓ Subasta #{auction_id2} creada correctamente (con cifrado)")
    
    # Obtener detalles de la subasta
    details = auction_mgr.get_auction_details(auction_id)
    assert details is not None, "Debe poder obtener los detalles"
    assert details['title'] == "Laptop Gaming", "El título debe coincidir"
    assert details['seller'] == username, "El vendedor debe coincidir"
    print("✓ Obtención de detalles de subasta funciona")
    
    db.close()
    print("✓ Todas las pruebas de AuctionManager pasaron")

def test_integrated_flow():
    """Prueba un flujo completo: registro, crear subasta, pujar"""
    print("\n=== Probando flujo integrado ===")
    
    db = Database()
    pki = PKIManager()
    auth = AuthManager(db, pki)
    auction_mgr = AuctionManager(db, auth)
    
    # Crear vendedor
    seller = "seller_test"
    auth.register_user(seller, "pass123456")
    auth.authenticate_user(seller, "pass123456")
    
    # Crear subasta
    end_date = (datetime.datetime.now() + datetime.timedelta(days=7)).isoformat()
    auction_id = auction_mgr.create_auction(
        title="Bicicleta de montaña",
        description="Bicicleta Trek X-Caliber",
        start_price=300.0,
        end_date=end_date,
        encrypt=False
    )
    
    print(f"✓ Flujo completo: subasta #{auction_id} creada por '{seller}'")
    
    # Listar subastas (solo para verificar que no de error)
    print("\n--- Listado de subastas ---")
    auction_mgr.list_auctions()
    
    db.close()
    print("\n✓ Todas las pruebas del flujo integrado pasaron")

def main():
    """Ejecuta todas las pruebas"""
    print("=" * 70)
    print("EJECUTANDO PRUEBAS DEL SISTEMA DE SUBASTAS")
    print("=" * 70)
    
    try:
        # Limpiar datos anteriores
        cleanup_test_data()
        
        # Ejecutar pruebas
        test_crypto_utils()
        test_database()
        test_pki()
        test_auth_manager()
        test_auction_manager()
        test_integrated_flow()
        
        print("\n" + "=" * 70)
        print("✓ TODAS LAS PRUEBAS PASARON EXITOSAMENTE")
        print("=" * 70)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ ERROR EN PRUEBA: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ ERROR INESPERADO: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
