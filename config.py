"""Configuración y constantes compartidas para la plataforma de subastas."""

import logging
from pathlib import Path

# Constantes de configuración
DB_FILE = "auction_platform.db"
KEYS_DIR = Path("keys")
CERTS_DIR = Path("certs")
DATA_DIR = Path("data")

# Crear directorios requeridos al importar el módulo
for directory in (KEYS_DIR, CERTS_DIR, DATA_DIR):
    directory.mkdir(exist_ok=True)

# Configuración de logging común
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    handlers=[logging.FileHandler('auction_platform.log'), logging.StreamHandler()]
)

logger = logging.getLogger("auction_platform")
