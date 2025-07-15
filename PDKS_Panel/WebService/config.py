"""
Uygulama yapılandırma ayarları
"""

import os
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Veritabanı yapılandırması
DATABASE = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'dbname': os.getenv('DB_NAME', 'pdks'),
    'user': os.getenv('DB_USER', 'postgres'),
    'password': os.getenv('DB_PASSWORD', '')
}

# Cihaz dinleyici ayarları
LISTENER_CONFIG = {
    'retry_interval': 5,  # Bağlantı hatası durumunda yeniden deneme aralığı (saniye)
    'heartbeat_interval': 30,  # Cihaz durum kontrolü aralığı (saniye)
    'connection_timeout': 10,  # Cihaz bağlantı zaman aşımı (saniye)
}

# Loglama ayarları
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'pdks.log'
} 