"""
Configuración y constantes compartidas para la plataforma de subastas.

Este módulo centraliza paths, creación de carpetas y la configuración del
logger para que el resto de módulos sólo importen y usen.
"""

import logging
from pathlib import Path

# Constantes de configuración (ficheros y carpetas base del proyecto)
DB_FILE = "auction_platform.db"
DATA_DIR = Path("data")

# Flag de persistencia 
SAVE_ACTA_JSON = True  # Si True, guarda actas de cierre en data/

# Creamos directorios al importar el módulo para evitar comprobaciones repetidas
DATA_DIR.mkdir(exist_ok=True)

# Configuración de logging común: fichero + consola con formato simple
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    handlers=[logging.FileHandler('auction_platform.log'), logging.StreamHandler()]
)

logger = logging.getLogger("auction_platform")
