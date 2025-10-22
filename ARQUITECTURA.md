# Arquitectura del Sistema de Subastas

## Diagrama de Componentes

```
┌─────────────────────────────────────────────────────────────────┐
│                    sistema_subastas.py                          │
│                   (Punto de Entrada)                            │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │         Clase AuctionPlatform (Coordinador)              │  │
│  │  - Inicializa todos los componentes                      │  │
│  │  - Delega operaciones a gestores específicos             │  │
│  └──────────────────────────────────────────────────────────┘  │
└──────┬──────────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │          │
       ▼          ▼          ▼          ▼          ▼
  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
  │database│ │  pki   │ │ crypto │ │  auth  │ │auction │
  │        │ │manager │ │ utils  │ │manager │ │manager │
  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘
                                         │          │
                                         │          │
                                         ▼          ▼
                                    ┌────────┐ ┌────────┐
                                    │  bid   │ │ (usa)  │
                                    │manager │ │ otros  │
                                    └────────┘ └────────┘
```

## Capas de la Aplicación

```
┌─────────────────────────────────────────────────────┐
│            CAPA DE PRESENTACIÓN                     │
│  - Menú interactivo (main_menu)                     │
│  - Entrada/salida de usuario                        │
└──────────────────┬──────────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────────┐
│         CAPA DE COORDINACIÓN                        │
│  - AuctionPlatform (orquesta las operaciones)       │
└──────┬──────────┬──────────┬──────────┬─────────────┘
       │          │          │          │
┌──────▼──────┐ ┌▼──────┐ ┌─▼────┐ ┌───▼─────┐
│   Auth      │ │Auction│ │ Bid  │ │  PKI    │
│  Manager    │ │Manager│ │Mgr   │ │ Manager │
└──────┬──────┘ └┬──────┘ └─┬────┘ └───┬─────┘
       │         │          │          │
┌──────▼─────────▼──────────▼──────────▼─────────┐
│          CAPA DE SERVICIOS                      │
│  - CryptoUtils (hash, cifrado, HMAC, firmas)    │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│         CAPA DE PERSISTENCIA                    │
│  - Database (SQLite)                            │
│  - Almacenamiento de archivos (keys, certs)     │
└─────────────────────────────────────────────────┘
```

## Flujo de Datos: Registro de Usuario

```
Usuario ingresa datos
        │
        ▼
┌───────────────────┐
│  main_menu()      │
└────────┬──────────┘
         │ register_user(username, password)
         ▼
┌────────────────────┐
│ AuctionPlatform    │
└────────┬───────────┘
         │ register_user(username, password)
         ▼
┌────────────────────┐      hash_password()
│  AuthManager       │──────────────────────────┐
└────────┬───────────┘                          │
         │                                       ▼
         │                              ┌───────────────┐
         │                              │ CryptoUtils   │
         │                              └───────────────┘
         │ issue_certificate()
         ├──────────────────────────────────────┐
         │                                      │
         ▼                                      ▼
┌────────────────┐                    ┌────────────────┐
│  PKIManager    │                    │   Database     │
│  - Sub-CA      │                    │  INSERT user   │
└────────────────┘                    └────────────────┘
```

## Flujo de Datos: Realizar Puja

```
Usuario ingresa puja
        │
        ▼
┌───────────────────┐
│  main_menu()      │
└────────┬──────────┘
         │ place_bid(auction_id, amount)
         ▼
┌────────────────────┐
│ AuctionPlatform    │
└────────┬───────────┘
         │ place_bid(auction_id, amount)
         ▼
┌────────────────────┐
│   BidManager       │
└────────┬───────────┘
         │
         ├─── Verificar subasta activa ──▶ Database
         │
         ├─── Generar HMAC ──────────────▶ CryptoUtils.generate_hmac()
         │
         ├─── Firmar datos ──────────────▶ CryptoUtils.sign_data()
         │
         ├─── Guardar puja ──────────────▶ Database.INSERT bid
         │
         ├─── Verificar HMAC ────────────▶ CryptoUtils.verify_hmac()
         │
         └─── Verificar firma ───────────▶ CryptoUtils.verify_signature()
                                           PKIManager.verify_chain()
```

## Responsabilidades de Cada Módulo

### 🗄️ database.py
- Conexión a SQLite
- Creación de tablas (users, auctions, bids)
- Operaciones CRUD básicas

### 🔐 crypto_utils.py
- Hash PBKDF2-HMAC-SHA256
- Cifrado/descifrado AES-256-CBC
- HMAC-SHA256
- Firma/verificación RSA-PSS

### 📜 pki_manager.py
- Gestión de CAs (Root y Sub-CA)
- Generación de certificados X.509
- Verificación de cadenas de certificación

### 👤 auth_manager.py
- Registro de usuarios
- Autenticación
- Gestión de sesiones
- Generación de claves RSA para usuarios

### 🏷️ auction_manager.py
- Creación de subastas
- Cifrado opcional de descripciones
- Cierre de subastas
- Listado de subastas

### 💰 bid_manager.py
- Registro de pujas
- Integridad con HMAC
- Autenticidad con firmas digitales
- Verificación de pujas

## Patrones de Diseño Utilizados

### 1. **Separación de Responsabilidades (SoC)**
Cada módulo tiene una única responsabilidad bien definida.

### 2. **Facade Pattern**
`AuctionPlatform` actúa como fachada, proporcionando una interfaz simple a un sistema complejo.

### 3. **Dependency Injection**
Los gestores reciben sus dependencias en el constructor:
```python
auth_manager = AuthManager(db, pki)
auction_manager = AuctionManager(db, auth)
bid_manager = BidManager(db, auth, pki)
```

### 4. **Static Utility Class**
`CryptoUtils` es una clase con métodos estáticos para funciones crypto reutilizables.

## Ventajas del Diseño

✅ **Modularidad**: Cada módulo puede desarrollarse y probarse independientemente

✅ **Mantenibilidad**: Los cambios en un módulo no afectan a otros

✅ **Reutilización**: Los módulos pueden usarse en otros proyectos

✅ **Testabilidad**: Fácil crear tests unitarios para cada módulo

✅ **Escalabilidad**: Fácil añadir nuevas funcionalidades

✅ **Legibilidad**: El código es más fácil de entender y navegar
