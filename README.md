# Sistema de Subastas Electrónicas con Criptografía

Sistema de subastas electrónicas que implementa diversos mecanismos criptográficos para garantizar la seguridad y autenticidad de las operaciones.

## 📁 Estructura del Proyecto

El código ha sido refactorizado y organizado en módulos separados para mejor mantenibilidad:

```
Practica/
├── sistema_subastas.py      # Punto de entrada principal y menú
├── database.py               # Gestión de base de datos SQLite
├── pki_manager.py            # Infraestructura de clave pública (PKI)
├── crypto_utils.py           # Utilidades criptográficas
├── auth_manager.py           # Gestión de autenticación y usuarios
├── auction_manager.py        # Gestión de subastas
├── bid_manager.py            # Gestión de pujas
├── test_sistema.py           # Tests automatizados
└── .gitignore                # Archivos ignorados por git
```

## 🔧 Módulos

### `database.py`
- Maneja la conexión a SQLite
- Crea y gestiona las tablas: `users`, `auctions`, `bids`
- Proporciona métodos para operaciones CRUD básicas

### `pki_manager.py`
- Implementa la infraestructura PKI (Root CA + Sub-CA)
- Genera certificados X.509 para usuarios
- Verifica cadenas de certificación

### `crypto_utils.py`
- **Hash de contraseñas**: PBKDF2-HMAC-SHA256 con 100k iteraciones
- **Cifrado simétrico**: AES-256-CBC con padding PKCS#7
- **Integridad**: HMAC-SHA256
- **Firmas digitales**: RSA-PSS con SHA-256

### `auth_manager.py`
- Registro de usuarios con claves RSA-2048
- Autenticación con verificación de contraseñas hasheadas
- Gestión de sesiones

### `auction_manager.py`
- Creación de subastas con cifrado opcional de descripción
- Cierre de subastas con documento firmado
- Listado de subastas activas y cerradas

### `bid_manager.py`
- Registro de pujas con HMAC para integridad
- Firma digital RSA-PSS de cada puja
- Verificación inmediata de integridad y firma

## 🚀 Instalación

1. Clonar el repositorio:
```bash
git clone https://github.com/alvarogg05/Practica.git
cd Practica
```

2. Instalar dependencias:
```bash
pip install cryptography
```

## 🎮 Uso

### Ejecutar el sistema
```bash
python3 sistema_subastas.py
```

### Ejecutar tests
```bash
python3 test_sistema.py
```

## 🔐 Características Criptográficas

1. **Registro y Autenticación**
   - PBKDF2-HMAC-SHA256 con 100,000 iteraciones
   - Salt aleatorio único por usuario
   - Claves privadas cifradas con la contraseña del usuario

2. **Cifrado Simétrico**
   - AES-256-CBC para descripciones de subastas
   - IV aleatorio de 128 bits
   - Padding PKCS#7

3. **Integridad de Pujas**
   - HMAC-SHA256 con clave de 256 bits
   - Verificación antes de aceptar pujas

4. **Firma Digital**
   - RSA-PSS con RSA-2048
   - Firma de cada puja y documento de cierre
   - Verificación con certificados X.509

5. **PKI**
   - Root CA autofirmada
   - Sub-CA firmada por Root CA
   - Certificados X.509 para cada usuario
   - Cadena de confianza verificable

## 📝 Ejemplo de Uso

```python
# Importar los módulos
from database import Database
from pki_manager import PKIManager
from auth_manager import AuthManager
from auction_manager import AuctionManager

# Inicializar componentes
db = Database()
pki = PKIManager()
auth = AuthManager(db, pki)
auction_mgr = AuctionManager(db, auth)

# Registrar usuario
auth.register_user("juan", "password123")

# Autenticar
auth.authenticate_user("juan", "password123")

# Crear subasta
auction_id = auction_mgr.create_auction(
    title="Laptop",
    description="Laptop gaming",
    start_price=500.0,
    end_date="2025-12-31T23:59:59",
    encrypt=True
)
```

## 🗂️ Archivos Generados

El sistema genera automáticamente los siguientes directorios y archivos:

- `keys/` - Claves públicas y privadas de usuarios y CAs
- `certs/` - Certificados X.509
- `data/` - Claves de cifrado, HMACs y documentos firmados
- `auction_platform.db` - Base de datos SQLite
- `auction_platform.log` - Log de eventos

## 🧪 Tests

El archivo `test_sistema.py` incluye tests para:
- Utilidades criptográficas (hash, AES, HMAC)
- Operaciones de base de datos
- Sistema PKI
- Autenticación de usuarios
- Gestión de subastas
- Flujo completo integrado

## 📚 Requisitos

- Python 3.8+
- cryptography >= 41.0.0

## 👨‍💻 Autor

Proyecto realizado como práctica de Criptografía y Seguridad Informática.

## 📄 Licencia

Este es un proyecto académico.
