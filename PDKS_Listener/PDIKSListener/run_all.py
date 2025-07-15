#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import threading
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
import logging

from PDIKSListener.models import Base, Device
from cihaz_listener import DeviceListener

# Logging yapılandırması
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.info("Uygulama başlatılıyor...")

class PDKSManager:
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        self.listeners: List[DeviceListener] = []
        self.stop_flag = False
        self.engine = None
        self.SessionLocal = None
        self.init_db()
        
    def init_db(self):
        """SQLAlchemy engine ve session factory oluştur"""
        try:
            db_url = f"postgresql://{self.db_config['user']}:{self.db_config.get('password', '')}@{self.db_config['host']}:{self.db_config.get('port', 5432)}/{self.db_config['dbname']}"
            self.engine = create_engine(db_url)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            Base.metadata.bind = self.engine
        except Exception as e:
            print(f"Veritabanı bağlantı hatası: {e}")
            sys.exit(1)
            
    def get_db(self):
        """Veritabanı oturumu oluştur"""
        if not self.SessionLocal:
            return None
            
        db = self.SessionLocal()
        try:
            return db
        except Exception as e:
            print(f"Oturum oluşturma hatası: {e}")
            if db:
                db.close()
            return None

    def get_active_devices(self) -> List[Dict]:
        """Aktif cihazları getir"""
        db = self.get_db()
        if not db:
            return []
            
        try:
            devices = db.query(Device).filter(
                Device.is_active == True,
                Device.deleted_at.is_(None)
            ).order_by(Device.name).all()
            
            return [
                {
                    'id': device.device_id,
                    'name': device.name,
                    'ip': device.ip,
                    'port': device.port,
                    'timeout': device.timeout,
                    'is_active': device.is_active,
                    'created_at': device.created_at,
                    'last_connection': device.last_connection,
                    'last_status': device.last_status
                }
                for device in devices
            ]
        except Exception as e:
            print(f"Aktif cihazları getirme hatası: {e}")
            return []
        finally:
            db.close()

    def start_listeners(self):
        """Tüm aktif cihazlar için dinleyicileri başlat"""
        devices = self.get_active_devices()
        if not devices:
            print("Aktif cihaz bulunamadı!")
            return
            
        print(f"\n{len(devices)} aktif cihaz bulundu. Dinleyiciler başlatılıyor...")
        
        for device in devices:
            try:
                # Cihaz konfigürasyonu
                device_config = {
                    'ip': device['ip'],
                    'port': device['port'],
                    'timeout': device['timeout'],
                    'name': device['name']
                }
                
                # Dinleyici oluştur ve başlat
                listener = DeviceListener(device_config, self.db_config)
                listener_thread = threading.Thread(
                    target=listener.run,
                    name=f"Listener-{device['name']}"
                )
                listener_thread.daemon = True
                listener_thread.start()
                
                self.listeners.append(listener)
                print(f"Dinleyici başlatıldı: {device['name']} ({device['ip']})")
                
            except Exception as e:
                print(f"Dinleyici başlatma hatası ({device['name']}): {e}")

    def stop_listeners(self):
        """Tüm dinleyicileri durdur"""
        print("\nDinleyiciler durduruluyor...")
        for listener in self.listeners:
            try:
                listener.stop()
            except:
                pass
        self.listeners.clear()

def signal_handler(signum, frame):
    """Sinyal yakalayıcı"""
    print("\nProgram durduruluyor...")
    if hasattr(signal_handler, 'manager'):
        signal_handler.manager.stop_listeners()
    sys.exit(0)

def main():
    # .env dosyasını yükle
    load_dotenv()

    # Veritabanı konfigürasyonu
    db_config = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'user': os.getenv('DB_USER', 'postgres'),
        'password': os.getenv('DB_PASSWORD', ''),
        'dbname': os.getenv('DB_NAME', 'pdks'),
        'port': int(os.getenv('DB_PORT', 5432))
    }

    # PDKS yöneticisini oluştur
    manager = PDKSManager(db_config)
    print("Veritabanı bağlantısı kuruldu:", manager.engine.url)

    # Sinyal işleyicisine manager'ı ekle
    signal_handler.manager = manager

    # Sinyalleri yakala
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Dinleyicileri başlat
        manager.start_listeners()

        # Ana thread'i canlı tut
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nKullanıcı tarafından durduruldu.")
    finally:
        manager.stop_listeners()

    return 0

if __name__ == "__main__":
    sys.exit(main())
