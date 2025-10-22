"""Punto de entrada de la plataforma de subastas electrónica.
Proporciona un menú de texto sencillo para interactuar con la clase
AuctionPlatform. Mantiene la lógica de UI separada de la lógica de negocio.
"""

import datetime
import getpass

from auction_platform import AuctionPlatform
from config import logger


def main_menu() -> None:
    """Bucle principal del menú por consola.

    No valida exhaustivamente entradas (por sencillez), pero maneja casos
    comunes como números inválidos al introducir ID o importes.
    """
    platform = AuctionPlatform()
    while True:
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
        if choice == '1':
            # Registro: pedimos dos veces la contraseña por si hay typo
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
        elif choice == '2':
            # Login básico
            username = input("Nombre de usuario: ").strip()
            password = getpass.getpass("Contraseña: ")
            if platform.authenticate_user(username, password):
                print(f"Bienvenido, {username}!")
            else:
                print("Credenciales incorrectas")
        elif choice == '3':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            # Recolectamos datos mínimos para crear la subasta
            title = input("Título de la subasta: ")
            description = input("Descripción: ")
            start_price = float(input("Precio inicial (€): "))
            days = int(input("Duración (días): "))
            encrypt = input("¿Cifrar descripción? (s/n): ").lower() == 's'
            end_date = (datetime.datetime.now() + datetime.timedelta(days=days)).isoformat()
            auction_id = platform.create_auction(title, description, start_price, end_date, encrypt)
            if auction_id > 0:
                print(f"Subasta #{auction_id} creada")
        elif choice == '4':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            try:
                auction_id = int(input("ID de la subasta: "))
            except ValueError:
                print("El identificador de la subasta debe ser un número entero válido")
                continue
            try:
                amount = float(input("Monto de la puja (€): "))
            except ValueError:
                print("El monto de la puja debe ser un número")
                continue
            if platform.place_bid(auction_id, amount):
                print("Puja realizada")
        elif choice == '5':
            # Simplemente imprimimos la tabla de subastas
            platform.list_auctions()
        elif choice == '6':
            if not platform.current_user:
                print("Debe iniciar sesión primero")
                continue
            auction_id = int(input("ID de la subasta a cerrar: "))
            if platform.close_auction(auction_id):
                print("Subasta cerrada")
        elif choice == '7':
            # Logout de la sesión actual
            platform.current_user = None
            print("Sesión cerrada")
        elif choice == '8':
            print("¡Hasta luego!")
            break
        else:
            print("Opción no válida")


def run() -> None:
    """Inicializa la app y lanza el menú principal."""
    print("\n" + "=" * 70)
    print("PLATAFORMA DE SUBASTAS ELECTRÓNICAS")
    print("=" * 70)
    logger.info("=== Iniciando Plataforma de Subastas ===")
    main_menu()


if __name__ == "__main__":
    run()
