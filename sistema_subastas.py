#!/usr/bin/env python3
"""
Plataforma de Subastas Electrónicas con Criptografía
Requisitos:
1. Registro y autenticación (PBKDF2-HMAC-SHA256 + salt)
2. Cifrado simétrico (AES-256-CBC) de descripciones
3. HMAC-SHA256 de pujas (integridad)
4. Firma digital RSA-PSS y verificación
5. PKI: CA raíz + Sub-CA que emite certificados X.509 a usuarios

Código refactorizado en módulos separados para mejor organización.
"""

import logging
import datetime
import getpass

# Importar los módulos que hemos creado
from database import Database
from pki_manager import PKIManager
from auth_manager import AuthManager
from auction_manager import AuctionManager
from bid_manager import BidManager

# Config de logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    handlers=[logging.FileHandler('auction_platform.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


class AuctionPlatform:
    """
    Plataforma principal de subastas electrónicas.
    
    Esta clase es el punto de entrada principal y coordina todos los módulos:
    - Database: maneja la BD SQLite
    - PKIManager: gestiona la infraestructura de clave pública
    - AuthManager: registro y autenticación de usuarios
    - AuctionManager: creación y gestión de subastas
    - BidManager: gestión de pujas
    """
    
    def __init__(self):
        """Inicializa todos los componentes del sistema"""
        # Inicializar BD
        self.db = Database()
        
        # Inicializar PKI (Root CA + Sub CA)
        self.pki = PKIManager()
        
        # Inicializar gestor de autenticación
        self.auth = AuthManager(self.db, self.pki)
        
        # Inicializar gestores de subastas y pujas
        self.auction_manager = AuctionManager(self.db, self.auth)
        self.bid_manager = BidManager(self.db, self.auth, self.pki)
    
    # ===== Métodos de autenticación =====
    
    def register_user(self, username: str, password: str) -> bool:
        """Registra un nuevo usuario"""
        return self.auth.register_user(username, password)
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Autentica un usuario"""
        return self.auth.authenticate_user(username, password)
    
    def logout(self):
        """Cierra la sesión actual"""
        self.auth.logout()
    
    @property
    def current_user(self) -> str:
        """Obtiene el usuario actual"""
        return self.auth.get_current_user()
    
    # ===== Métodos de subastas =====
    
    def create_auction(self, title: str, description: str, start_price: float, 
                      end_date: str, encrypt: bool = True) -> int:
        """Crea una nueva subasta"""
        return self.auction_manager.create_auction(
            title, description, start_price, end_date, encrypt
        )
    
    def close_auction(self, auction_id: int) -> bool:
        """Cierra una subasta"""
        return self.auction_manager.close_auction(auction_id)
    
    def list_auctions(self):
        """Lista todas las subastas"""
        self.auction_manager.list_auctions()
    
    # ===== Métodos de pujas =====
    
    def place_bid(self, auction_id: int, amount: float) -> bool:
        """Realiza una puja"""
        return self.bid_manager.place_bid(auction_id, amount)
    
    def __del__(self):
        """Cierra la conexión a la BD al destruir el objeto"""
        if hasattr(self, 'db'):
            self.db.close()

def main_menu():
    """
    Menú principal de la aplicación.
    Interfaz de línea de comandos para interactuar con el sistema.
    """
    platform = AuctionPlatform()
    
    while True:
        # Mostrar el menú
        print("\n" + "=" * 50)
        print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS")
        print("=" * 50)
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
        
        # Opción 1: Registrar usuario
        if choice == '1':
            username = input("Nombre de usuario: ").strip()
            password = getpass.getpass("Contraseña: ")
            password2 = getpass.getpass("Confirmar contraseña: ")
            
            if password != password2:
                print("Las contraseñas no coinciden")
                continue
            
            if len(password) < 8:
                print("La contraseña debe tener al menos 8 caracteres")
                continue
            
            platform.register_user(username, password)
        
        # Opción 2: Login
        elif choice == '2':
            username = input("Nombre de usuario: ").strip()
            password = getpass.getpass("Contraseña: ")
            
            if platform.authenticate_user(username, password):
                print(f"Bienvenido, {username}!")
            else:
                print("Credenciales incorrectas")
        
        # Opción 3: Crear subasta
        elif choice == '3':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            
            title = input("Título de la subasta: ")
            description = input("Descripción: ")
            start_price = float(input("Precio inicial (€): "))
            days = int(input("Duración (días): "))
            encrypt = input("¿Cifrar descripción? (s/n): ").lower() == 's'
            
            end_date = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
            auction_id = platform.create_auction(title, description, start_price, end_date, encrypt)
            
            if auction_id > 0:
                print(f"Subasta #{auction_id} creada correctamente")
        
        # Opción 4: Hacer puja
        elif choice == '4':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            
            auction_id = int(input("ID de la subasta: "))
            amount = float(input("Monto de la puja (€): "))
            
            if platform.place_bid(auction_id, amount):
                print("Puja realizada correctamente")
        
        # Opción 5: Listar subastas
        elif choice == '5':
            platform.list_auctions()
        
        # Opción 6: Cerrar subasta
        elif choice == '6':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            
            auction_id = int(input("ID de la subasta a cerrar: "))
            
            if platform.close_auction(auction_id):
                print("Subasta cerrada correctamente")
        
        # Opción 7: Cerrar sesión
        elif choice == '7':
            platform.logout()
            print("Sesión cerrada")
        
        # Opción 8: Salir
        elif choice == '8':
            print("¡Hasta luego!")
            break
        
        # Opción inválida
        else:
            print("Opción no válida")


# Punto de entrada del programa
if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS CON CRIPTOGRAFÍA")
    print("Práctica de Criptografía y Seguridad Informática")
    print("=" * 70)
    logger.info("=== Iniciando Plataforma de Subastas ===")
    main_menu()


if __name__ == "__main__":
    print("\n" + "="*70)
    print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS CON CRIPTOGRAFÍA")
    print("Práctica de Criptografía y Seguridad Informática")
    print("="*70)
    logger.info("=== Iniciando Plataforma de Subastas ===")
    main_menu()
