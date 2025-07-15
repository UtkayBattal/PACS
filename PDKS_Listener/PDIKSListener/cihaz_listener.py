#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse
import threading
import logging
from datetime import datetime, timedelta
from zk import ZK, const
from sqlalchemy import create_engine, func, text
from sqlalchemy.orm import sessionmaker
from PDIKSListener.models import Base, Device, User, Record, Department
from typing import Optional, Dict, List
import traceback
import shutil

# Loglama yapılandırması
class CustomFormatter(logging.Formatter):
    """Özel log formatı"""
    
    # Log renkleri
    grey = "\x1b[38;21m"
    blue = "\x1b[38;5;39m"
    yellow = "\x1b[38;5;226m"
    red = "\x1b[38;5;196m"
    green = "\x1b[38;5;40m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        # Özel log seviyesi renkleri
        if hasattr(record, 'success'):
            format_str = self.green + self.fmt + self.reset
        else:
            format_str = self.FORMATS.get(record.levelno)
        
        # Zaman formatını düzenle
        record.asctime = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        
        formatter = logging.Formatter(format_str)
        return formatter.format(record)

# Log formatını ayarla
log_format = "%(asctime)s | %(levelname)-8s | [%(name)s] %(message)s"

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(CustomFormatter(log_format))

# File handler
file_handler = logging.FileHandler('/app/pdks_listener.log')
file_handler.setFormatter(logging.Formatter(log_format))

# Logger'ı yapılandır
logger = logging.getLogger('PDKSListener')
logger.setLevel(logging.INFO)
logger.handlers = []  # Mevcut handler'ları temizle
logger.addHandler(console_handler)
logger.addHandler(file_handler)
logger.propagate = False

def safe_log(level, message, device_name=""):
    """Gelişmiş loglama"""
    try:
        # Mesajı formatla
        formatted_message = f"[{device_name}] {message}"
        
        # Log seviyesine göre kaydet
        if level.upper() == 'SUCCESS':
            # Başarı mesajları için özel yeşil renk
            log_record = logging.LogRecord(
                'PDKSListener', logging.INFO, '', 0, 
                formatted_message, (), None
            )
            setattr(log_record, 'success', True)
            console_handler.emit(log_record)
            # Dosyaya normal INFO olarak kaydet
            logger.info(formatted_message)
        elif level.upper() == 'INFO':
            logger.info(formatted_message)
        elif level.upper() == 'WARNING':
            logger.warning(formatted_message)
        elif level.upper() == 'ERROR':
            logger.error(formatted_message)
        elif level.upper() == 'CRITICAL':
            logger.critical(formatted_message)
        elif level.upper() == 'DEBUG':
            logger.debug(formatted_message)
    except Exception as e:
        print(f"Loglama hatası: {e}")

# ANSI renk kodları
class Colors:
    HEADER = '\033[95m'
    INFO = '\033[94m'
    SUCCESS = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    CRITICAL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def to_ascii(text):
    """Unicode metni ASCII'ye dönüştür"""
    if not text:
        return text
    return text.encode('ascii', 'ignore').decode('ascii')

def safe_string(value, default=None, max_length=None):
    """Güvenli string dönüşümü"""
    if value is None:
        return default
    
    try:
        value = str(value).strip()
        if max_length and len(value) > max_length:
            value = value[:max_length]
        return value
    except:
        return default
    
def status_to_text(status_code):
    """Durum kodunu metne dönüştür"""
    status_map = {
        0: "Normal",
        1: "Geç Giriş",
        2: "Erken Çıkış",
        3: "Eksik Hareket",
        4: "Fazla Mesai",
        5: "Manuel Giriş",
        6: "Manuel Çıkış"
    }
    return status_map.get(status_code, str(status_code))

def punch_to_direction(punch_code):
    """Yön kodunu metne dönüştür"""
    return "GİRİŞ" if punch_code == 0 else "ÇIKIŞ"

class DeviceListener:
    def __init__(self, device_config, db_config=None):
        self.device_config = device_config
        self.db_config = db_config or {}
        self.zk = None
        self.conn = None
        self.stop_flag = False
        self.engine = None
        self.SessionLocal = None
        self.last_connection_attempt = 0
        self.connection_attempt_count = 0
        self.max_connection_attempts = int(os.getenv('RECONNECT_ATTEMPT_LIMIT', '5'))
        self.reconnect_interval = int(os.getenv('RECONNECT_INTERVAL', '300'))
        self.check_interval = int(os.getenv('CHECK_INTERVAL', '30'))
        self.sync_interval = 600  # 10 dakika (saniye cinsinden)
        self.last_sync_time = 0
        self.device_connections = {}  # Cihaz bağlantılarını saklayacak sözlük
        self.last_attendance_time = {}  # Son yoklama zamanını saklamak için
        self.batch_size = 50  # Toplu işlem boyutu
        self.init_db()
        
        # Başlangıç mesajı
        self.log("info", f"Device Listener başlatıldı - {self.device_config.get('name', 'Terminal')}")
        self.log("info", f"Bağlantı ayarları: {self.device_config.get('ip')}:{self.device_config.get('port')}")
        self.log("info", f"Kontrol aralığı: {self.check_interval}s, Senkronizasyon aralığı: {self.sync_interval}s")
        
    def init_db(self):
        """SQLAlchemy engine ve session factory oluştur"""
        try:
            # Veritabanı bağlantı URL'sini oluştur
            db_url = f"postgresql://{self.db_config.get('user', 'postgres')}:{self.db_config.get('password', '')}@{self.db_config.get('host', 'host.docker.internal')}:{self.db_config.get('port', 5432)}/{self.db_config.get('dbname', 'pdks')}"
            
            # Engine oluşturma seçenekleri
            engine_options = {
                'pool_size': 5,  # Bağlantı havuzu boyutu
                'max_overflow': 10,  # Maksimum ek bağlantı sayısı
                'pool_timeout': 30,  # Havuzdan bağlantı alma zaman aşımı
                'pool_recycle': 1800,  # Bağlantıları 30 dakikada bir yenile
                'pool_pre_ping': True,  # Bağlantı kontrolü için ping
                'connect_args': {
                    'connect_timeout': 10  # Bağlantı zaman aşımı
                }
            }
            
            self.engine = create_engine(db_url, **engine_options)
            
            # Veritabanı bağlantısını test et
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
                self.log("success", "Veritabanı bağlantısı başarıyla test edildi")
            
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            Base.metadata.bind = self.engine
            
            self.log("info", f"Veritabanı bağlantısı başlatıldı: {self.db_config.get('host', 'host.docker.internal')}:{self.db_config.get('port', 5432)}/{self.db_config.get('dbname', 'pdks')}")
            
        except Exception as e:
            self.log("error", f"Veritabanı bağlantı hatası: {e}")
            # Kritik hata durumunda yeniden deneme
            time.sleep(5)
            self.retry_db_connection()

    def retry_db_connection(self, max_retries=5, delay=5):
        """Veritabanı bağlantısını yeniden deneme"""
        for attempt in range(max_retries):
            try:
                self.log("info", f"Veritabanı bağlantısı yeniden deneniyor (deneme {attempt + 1}/{max_retries})")
                
                # Mevcut engine'i kapat
                if self.engine:
                    self.engine.dispose()
                
                # Yeni bağlantı oluştur
                self.init_db()
                return True
                
            except Exception as e:
                self.log("error", f"Yeniden bağlanma denemesi başarısız ({attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(delay)
                    delay *= 2  # Her denemede bekleme süresini artır
                    
        self.log("critical", "Veritabanına bağlanılamıyor, uygulama durduruluyor")
        self.stop_flag = True
        return False

    def get_db(self):
        """Veritabanı oturumu oluştur ve bağlantı kontrolü yap"""
        if not self.SessionLocal:
            if not self.retry_db_connection():
                return None
                
        try:
            db = self.SessionLocal()
            # Bağlantıyı test et
            db.execute(text("SELECT 1"))
            return db
        except Exception as e:
            self.log("error", f"Veritabanı oturumu oluşturma hatası: {e}")
            if 'db' in locals():
                db.close()
            # Bağlantıyı yeniden deneme
            if self.retry_db_connection():
                return self.get_db()
            return None

    def log(self, level, message):
        """Log mesajı oluştur"""
        safe_log(level, message, self.device_config.get('name', ''))

    def connect(self):
        """Cihaza bağlanmayı dener."""
        try:
            current_time = time.time()
            if current_time - self.last_connection_attempt < 3:  # Minimum bağlantı deneme aralığı
                return False

            self.last_connection_attempt = current_time

            # Mevcut bağlantıyı temizle
            if self.zk is not None:
                try:
                    self.zk.disconnect()
                except:
                    pass
                self.zk = None
                time.sleep(1)

            # Yeni bağlantı oluştur
            self.zk = ZK(
                self.device_config['ip'],
                port=self.device_config['port'],
                timeout=int(os.getenv('DEVICE_TIMEOUT', 5)),
                password=0,
                force_udp=True,  # UDP kullan
                ommit_ping=False  # Ping kontrolünü etkinleştir
            )

            max_attempts = 3
            retry_delay = int(os.getenv('DEVICE_RETRY_DELAY', 2))

            for attempt in range(max_attempts):
                try:
                    if attempt > 0:
                        self.log("info", f"Bağlantı yeniden deneniyor (deneme {attempt+1}/{max_attempts})")
                        time.sleep(retry_delay)

                    # Bağlantıyı dene
                    conn = self.zk.connect()
                    if conn:
                        self.conn = conn
                        self.connected = True
                        self.log("success", f"Bağlantı başarılı - {self.device_config['ip']}")
                        return True

                except Exception as e:
                    error_msg = str(e).lower()
                    if "timeout" in error_msg:
                        self.log("error", f"Bağlantı zaman aşımı (deneme {attempt+1}/{max_attempts})")
                    elif "broken pipe" in error_msg:
                        self.log("error", f"Bağlantı koptu (deneme {attempt+1}/{max_attempts})")
                    else:
                        self.log("error", f"Bağlantı hatası (deneme {attempt+1}/{max_attempts}): {str(e)}")

                    if attempt < max_attempts - 1:
                        continue

            self.log("error", f"{max_attempts} deneme sonrasında bağlantı kurulamadı")
            self.connected = False
            return False

        except Exception as e:
            self.log("error", f"Bağlantı hatası: {str(e)}")
            self.connected = False
            return False

    def get_device(self, device_id=None, device_ip=None):
        """Cihaz bağlantısını getir."""
        try:
            if not device_id:
                device_id = self.device_config['ip']
            if not device_ip:
                device_ip = self.device_config['ip']

            if not hasattr(self, 'device_connections'):
                self.device_connections = {}

            # Mevcut bağlantıyı kontrol et ve temizle
            if device_id in self.device_connections:
                try:
                    conn = self.device_connections[device_id]
                    conn.disconnect()
                except:
                    pass
                del self.device_connections[device_id]
                time.sleep(1)

            # Yeni bağlantı oluştur
            try:
                zk = ZK(
                    device_ip,
                    port=self.device_config['port'],
                    timeout=int(os.getenv('DEVICE_TIMEOUT', 5)),
                    password=0,
                    force_udp=True,  # UDP kullan
                    ommit_ping=False  # Ping kontrolünü etkinleştir
                )

                conn = zk.connect()
                if conn:
                    self.device_connections[device_id] = conn
                    self.log("info", f"Yeni cihaz bağlantısı kuruldu: {device_ip}")
                    return conn
                else:
                    self.log("error", f"Cihaz bağlantısı kurulamadı: {device_ip}")
                    return None

            except Exception as e:
                error_msg = str(e).lower()
                if "broken pipe" in error_msg:
                    self.log("error", f"Cihaz bağlantısı hatası: Bağlantı koptu")
                else:
                    self.log("error", f"Cihaz bağlantısı hatası: {str(e)}")
                return None

        except Exception as e:
            self.log("error", f"get_device hatası: {str(e)}")
            return None

    def get_attendance(self):
        """Cihazdan yoklama verilerini alır."""
        if not self.connected or not self.zk:
            return None
            
        try:
            attendances = self.zk.get_attendance()
            if attendances:
                self.log("success", f"{len(attendances)} adet yoklama verisi alındı")
                return attendances
            return []
            
        except Exception as e:
            self.log("error", f"Yoklama verisi alma hatası: {str(e)}")
            self.connected = False
            return None

    def clear_attendance(self):
        """Cihazdan alınan yoklama verilerini temizler."""
        if not self.connected or not self.zk:
            return False
            
        try:
            # Temizleme işlemini yap ama loglama yapma
            self.zk.clear_attendance()
            return True
        except Exception as e:
            self.log("error", f"Yoklama verisi temizleme hatası: {str(e)}")
            self.connected = False
            return False

    def check_device_availability(self):
        """Cihazın erişilebilir olup olmadığını kontrol et"""
        import platform
        import subprocess
        import shutil
        
        try:
            # Ping komutunun tam yolunu bul
            ping_cmd = shutil.which('ping')
            if not ping_cmd:
                self.log("warning", "Ping komutu bulunamadı, bağlantı kontrolü atlanıyor")
                return True  # Ping komutu yoksa kontrolü atla
            
            timeout = int(os.getenv('PING_TIMEOUT', '3'))
            
            # Windows için ping komutu
            if platform.system().lower() == "windows":
                cmd = [ping_cmd, '-n', '1', '-w', str(timeout * 1000), self.device_config['ip']]
            # Linux/Unix için ping komutu
            else:
                cmd = [ping_cmd, '-c', '1', '-W', str(timeout), self.device_config['ip']]
            
            # Ping komutunu çalıştır
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Ping başarılı ise True döndür
            return result.returncode == 0
            
        except Exception as e:
            self.log("warning", f"Ping kontrolü yapılamadı: {e}, bağlantı kontrolü atlanıyor")
            return True  # Hata durumunda kontrolü atla

    def get_attendances(self):
        """Gelişmiş yoklama veri alma"""
        if not self.conn or not self.zk.is_connect:
            self.log("warning", "Yoklama verisi için bağlantı kurulamadı, yeniden bağlanmaya çalışılıyor")
            if not self.connect():
                return []

        try:
            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    # Son yoklama zamanından sonraki verileri al
                    device_id = self.device_config.get('ip')
                    last_time = self.last_attendance_time.get(device_id)
                    
                    attendances = self.conn.get_attendance()
                    if attendances:
                        # Verileri tarihe göre sırala
                        attendances = sorted(attendances, key=lambda x: x.timestamp)
                        
                        # Son yoklama zamanını güncelle
                        if attendances:
                            self.last_attendance_time[device_id] = attendances[-1].timestamp
                            
                        # Performans log mesajı
                        self.log("success", f"{len(attendances)} yeni yoklama verisi alındı")
                        
                        # Detaylı log
                        if attendances:
                            first_record = attendances[0]
                            last_record = attendances[-1]
                            self.log("info", f"Veri aralığı: {first_record.timestamp} - {last_record.timestamp}")
                            
                    return attendances
                    
                except Exception as e:
                    error_msg = str(e).lower()
                    if "broken pipe" in error_msg:
                        self.log("error", f"Yoklama verisi alınamadı (deneme {attempt+1}/{max_attempts}): Bağlantı koptu")
                    else:
                        self.log("error", f"Yoklama verisi alınamadı (deneme {attempt+1}/{max_attempts}): {e}")
                    
                    if "TCP packet invalid" in str(e) or "not connected" in str(e).lower():
                        self.log("info", "Bağlantı yenileniyor...")
                        if self.connect():
                            time.sleep(1)
                            continue
                    time.sleep(2)  # Hata durumunda daha uzun bekle
                    
            self.log("error", "Yoklama verisi alınamadı - tüm denemeler başarısız")
            return []
            
        except Exception as e:
            self.log("error", f"Yoklama verisi işleme hatası: {e}")
            return []

    def get_device_info(self):
        """Cihaz bilgilerini alır."""
        if not self.conn or not self.zk.is_connect:
            if not self.connect():
                return None

        try:
            # Bazı ZK kütüphaneleri get_device_info metoduna sahip değil
            if hasattr(self.conn, 'get_device_info'):
                info = self.conn.get_device_info()
                return info
            else:
                # Alternatif bilgileri toplama
                info = {
                    'firmware_version': getattr(self.conn, 'firmware_version', 'Bilinmiyor'),
                    'serialnumber': getattr(self.conn, 'serialnumber', 'Bilinmiyor'),
                    'platform': getattr(self.conn, 'platform', 'Bilinmiyor'),
                    'device_name': getattr(self.conn, 'device_name', self.device_config.get('name', 'Terminal')),
                    'work_code': getattr(self.conn, 'workcode', 0)
                }
                return info
        except Exception as e:
            safe_log("ERROR", f"Cihaz bilgileri alınamadı: {e}", self.device_config.get('name', 'Terminal'))
            return None
    
    def update_device_status(self, is_connected: bool):
        """Cihaz durumunu güncelle"""
        db = self.get_db()
        if not db:
            return
            
        try:
            device = db.query(Device).filter(
                Device.ip == self.device_config['ip'],
                Device.deleted_at.is_(None)
            ).first()
            
            if device:
                device.last_connection = datetime.now()
                device.last_status = "Bağlı" if is_connected else "Bağlantı Kesildi"
                db.commit()
                
        except Exception as e:
            self.log("error", f"Cihaz durumu güncellenirken hata: {e}")
            db.rollback()
        finally:
            db.close()

    def validate_attendance_data(self, att):
        """Yoklama verisini doğrula"""
        if not att:
            return False
            
        required_fields = ['user_id', 'timestamp', 'punch']
        return all(hasattr(att, field) for field in required_fields)

    def process_device_specific_data(self, att):
        """Cihaza özel veri işleme"""
        try:
            # Kullanıcı ID'sini düzelt
            user_id = int(att.user_id)
            if user_id > 100000000:
                user_id = user_id - 100000000
                
            # Timestamp'i düzelt
            timestamp = att.timestamp
            if isinstance(timestamp, str):
                timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                
            return {
                'user_id': user_id,
                'timestamp': timestamp,
                'punch': att.punch,
                'status': att.status if hasattr(att, 'status') else None
            }
        except Exception as e:
            self.log("error", f"Veri işleme hatası: {e}")
            return None
            
    def process_attendance_data(self):
        """Geliştirilmiş yoklama verisi işleme"""
        if not self.conn:
            if not self.connect():
                return
                
        try:
            # Yoklama verilerini al
            attendances = self.get_attendances()
            if not attendances:
                return
                
            # Toplu işlem için verileri grupla
            total_records = len(attendances)
            processed_count = 0
            error_count = 0
            should_clear = False  # Temizleme yapılacak mı?
            
            # Verileri daha küçük gruplar halinde işle
            batch_size = 10  # Batch boyutu küçültüldü
            
            for i in range(0, total_records, batch_size):
                batch = attendances[i:i + batch_size]
                batch_success = 0
                batch_errors = 0
                
                for att in batch:
                    try:
                        if not self.validate_attendance_data(att):
                            continue
                            
                        processed_data = self.process_device_specific_data(att)
                        if not processed_data:
                            batch_errors += 1
                            continue
                            
                        if self.record_exists(processed_data):
                            continue
                            
                        if self.insert_attendance_record(processed_data):
                            batch_success += 1
                            should_clear = True  # Kayıt başarılı olduğunda temizleme işaretini aç
                        else:
                            batch_errors += 1
                            
                    except Exception as e:
                        self.log("error", f"Kayıt işleme hatası: {str(e)}")
                        batch_errors += 1
                        
                processed_count += batch_success
                error_count += batch_errors
                
            # Final durumu logla
            if processed_count > 0:
                self.log("success", f"Toplam {processed_count} yeni kayıt başarıyla eklendi")
                
                # Sadece yeni kayıt eklendiğinde ve CLEAR_ATTENDANCE true ise temizleme yap
                if should_clear and os.getenv('CLEAR_ATTENDANCE', 'true').lower() == 'true':
                    if self.clear_attendance():
                        self.log("info", f"{processed_count} kayıt sonrası yoklama verileri cihazdan temizlendi")
                
            if error_count > 0:
                self.log("warning", f"Toplam {error_count} kayıt eklenemedi")
                
        except Exception as e:
            self.log("error", f"Yoklama verisi işleme hatası: {str(e)}")
            self.log("error", traceback.format_exc())

    def record_exists(self, att_data: Dict) -> bool:
        """Kayıt var mı kontrol et"""
        db = self.get_db()
        if not db:
            return False
            
        try:
            # Aynı kullanıcı için aynı zamanda kayıt var mı kontrol et
            exists = db.query(Record).filter(
                Record.user_id == att_data['user_id'],
                Record.timestamp == att_data['timestamp'],
                Record.deleted_at.is_(None)
            ).first() is not None
            
            return exists
            
        except Exception as e:
            self.log("error", f"Kayıt kontrolü hatası: {e}")
            return False
        finally:
            db.close()

    def insert_attendance_record(self, att_data: Dict) -> bool:
        """Yoklama kaydı ekle"""
        db = self.get_db()
        if not db:
            return False
            
        try:
            # Kullanıcıyı kontrol et/oluştur
            user_id = att_data['user_id']
            
            # Cihaz bilgilerini al
            device_ip = self.device_config['ip']
            device_id = self.device_config.get('id', device_ip)  # id yoksa ip kullan
            
            # Kullanıcıyı kontrol et/oluştur
            self.ensure_user_exists(user_id, device_id, device_ip)
            
            # Son kaydı kontrol et
            last_record = self.get_last_record_of_user_today(user_id, att_data['timestamp'])
            
            # Akıllı giriş/çıkış kontrolü
            if last_record:
                # Son kayıt varsa, yeni kayıt farklı yönde olmalı
                new_punch = 1 if last_record.punch == 0 else 0
            else:
                # İlk kayıt her zaman giriş olmalı
                new_punch = 0
                
            # Cihazı bul
            device = db.query(Device).filter(
                Device.ip == device_ip,
                Device.deleted_at.is_(None)
            ).first()
            
            # Yeni kaydı oluştur
            new_record = Record(
                user_id=user_id,
                timestamp=att_data['timestamp'],
                punch=new_punch,
                device_id=device.device_id if device else None,
                created_at=datetime.now()
            )
            
            # Departman kontrolü ve geç giriş/erken çıkış durumu
            user = db.query(User).filter(
                User.user_id == user_id,
                User.deleted_at.is_(None)
            ).first()
            
            if user and user.department_id:
                dept = db.query(Department).filter(
                    Department.department_id == user.department_id,
                    Department.deleted_at.is_(None)
                ).first()
                
                if dept:
                    current_time = att_data['timestamp'].time()
                    
                    if new_punch == 0:  # Giriş
                        if dept.work_start_time:
                            tolerance = timedelta(minutes=dept.late_tolerance_minutes or 0)
                            max_time = (datetime.combine(datetime.min, dept.work_start_time) + tolerance).time()
                            
                            if current_time > max_time:
                                new_record.status = "Geç Giriş"
                                
                    else:  # Çıkış
                        if dept.work_end_time and current_time < dept.work_end_time:
                            new_record.status = "Erken Çıkış"
            
            db.add(new_record)
            db.commit()
            
            punch_direction = "GİRİŞ" if new_punch == 0 else "ÇIKIŞ"
            self.log("info", f"Yeni {punch_direction} kaydı eklendi: {user_id} - {att_data['timestamp']}")
            
            return True
            
        except Exception as e:
            self.log("error", f"Kayıt ekleme hatası: {e}")
            db.rollback()
            return False
        finally:
            db.close()

    def ensure_user_exists(self, user_id, device_id, device_ip):
        """Ensure a user exists in the database, creating them if needed."""
        try:
            session = self.get_db()
            user = session.query(User).filter_by(user_id=user_id).first()
            
            if not user:
                # Get user info from device
                dev = self.get_device(device_id, device_ip)
                if dev:
                    try:
                        self.log("info", f"ID: {user_id} için kullanıcı bilgisi cihazdan alınıyor: {device_ip}")
                        user_info = dev.get_user(user_id)
                        if user_info:
                            self.log("info", f"Cihaz verilerinden kullanıcı oluşturuluyor: {user_info}")
                            name = getattr(user_info, 'name', f"Kullanıcı {user_id}")
                            if name:
                                name = to_ascii(name)
                            else:
                                name = f"Kullanıcı {user_id}"
                                
                            # Önemli: role_id boş string ise None atanacak
                            role_id = getattr(user_info, 'role_id', None)
                            device_role = None if role_id == "" else role_id
                            self.log("info", f"Rol bilgisi: Orjinal={role_id}, Düzenlenmiş={device_role}")
                            
                            user = User(
                                user_id=user_id,
                                name=name,
                                card_no=getattr(user_info, 'card', None),
                                device_role=device_role,
                                created_at=datetime.now()
                            )
                            session.add(user)
                            session.commit()
                            self.log("info", f"Kullanıcı oluşturuldu: {user_id}")
                        else:
                            self.log("warning", f"Cihazdan kullanıcı bilgisi alınamadı: {device_ip}")
                    except Exception as e:
                        self.log("error", f"Cihazdan kullanıcı oluşturma hatası: {str(e)}")
                        session.rollback()
            
            if user:
                return user.user_id
            return None
        except Exception as e:
            self.log("error", f"ensure_user_exists içinde hata: {str(e)}")
            if 'session' in locals():
                session.rollback()
            return None
        finally:
            if 'session' in locals():
                session.close()

    def get_last_record_of_user_today(self, user_id: int, timestamp: datetime) -> Optional[Record]:
        """Kullanıcının bugün en son kaydını al"""
        db = self.get_db()
        if not db:
            return None
            
        try:
            today_start = timestamp.replace(hour=0, minute=0, second=0, microsecond=0)
            today_end = today_start + timedelta(days=1)
            
            last_record = db.query(Record).filter(
                Record.user_id == user_id,
                Record.timestamp >= today_start,
                Record.timestamp < today_end,
                Record.timestamp < timestamp,  # Şu anki kayıttan önceki kayıtlar
                Record.deleted_at.is_(None)
            ).order_by(Record.timestamp.desc()).first()
            
            return last_record
            
        except Exception as e:
            self.log("error", f"Son kayıt kontrolü hatası: {e}")
            return None
        finally:
            db.close()

    def sync_all_users(self, force=True):
        """
        Cihazdaki tüm kullanıcıları veritabanına senkronize eder.
        
        Args:
            force (bool): True ise, varolan kullanıcılar da güncellenir.
        """
        try:
            self.log("info", "Cihazdan tüm kullanıcılar çekiliyor...")
            dev = self.get_device()
            
            if not dev:
                self.log("error", "Cihaz bağlantısı kurulamadı. Kullanıcı senkronizasyonu yapılamıyor.")
                return False
                
            # Cihazdan tüm kullanıcıları al
            users = dev.get_users()
            if not users:
                self.log("warning", "Cihazda kullanıcı bulunamadı.")
                return False
                
            self.log("info", f"Cihazda {len(users)} kullanıcı bulundu.")
            
            # Session aç
            session = self.SessionLocal()
            
            try:
                # Her kullanıcı için veritabanında kayıt oluştur veya güncelle
                for user in users:
                    user_id = getattr(user, 'user_id', None)
                    
                    if not user_id:
                        self.log("warning", f"Geçersiz kullanıcı ID: {user}")
                        continue
                    
                    # Kullanıcıyı veritabanında ara
                    db_user = session.query(User).filter_by(user_id=user_id).first()
                    
                    # role_id'nin None olarak ayarlanması
                    role_id = getattr(user, 'role_id', None)
                    # Boş string kontrolü yap ve None olarak ayarla
                    device_role = None if role_id == "" else role_id
                    
                    # Kullanıcı adını işle
                    name = getattr(user, 'name', f"Kullanıcı {user_id}")
                    if name:
                        name = to_ascii(name)
                    else:
                        name = f"Kullanıcı {user_id}"
                    
                    if db_user:
                        # Kullanıcı varsa ve force=True ise güncelle
                        if force:
                            self.log("info", f"Kullanıcı güncelleniyor: {user_id} - {name}")
                            db_user.name = name
                            db_user.card_no = getattr(user, 'card', None)
                            db_user.device_role = device_role
                            db_user.updated_at = datetime.now()
                    else:
                        # Kullanıcı yoksa oluştur
                        self.log("info", f"Yeni kullanıcı oluşturuluyor: {user_id} - {name}")
                        new_user = User(
                            user_id=user_id,
                            name=name,
                            card_no=getattr(user, 'card', None),
                            device_role=device_role,
                            created_at=datetime.now()
                        )
                        session.add(new_user)
                
                # Değişiklikleri kaydet
                session.commit()
                self.log("info", "Kullanıcı senkronizasyonu tamamlandı.")
                return True
                
            except Exception as e:
                self.log("error", f"Kullanıcı senkronizasyonu sırasında hata oluştu: {str(e)}")
                session.rollback()
                return False
            finally:
                session.close()
                
        except Exception as e:
            self.log("error", f"sync_all_users içinde hata: {str(e)}")
            return False

    def sync_missing_users(self):
        """Sadece eksik kullanıcıları senkronize eder"""
        try:
            dev = self.get_device()
            if not dev:
                self.log("error", "Cihaz bağlantısı kurulamadı. Eksik kullanıcı senkronizasyonu yapılamıyor.")
                return False

            # Cihazdan tüm kullanıcıları al
            users = dev.get_users()
            if not users:
                return False

            session = self.SessionLocal()
            try:
                added_count = 0
                for user in users:
                    user_id = getattr(user, 'user_id', None)
                    if not user_id:
                        continue

                    # Kullanıcı veritabanında var mı kontrol et
                    db_user = session.query(User).filter_by(user_id=user_id).first()
                    if not db_user:
                        # Kullanıcı yoksa ekle
                        name = getattr(user, 'name', f"Kullanıcı {user_id}")
                        if name:
                            name = to_ascii(name)
                        else:
                            name = f"Kullanıcı {user_id}"

                        role_id = getattr(user, 'role_id', None)
                        device_role = None if role_id == "" else role_id

                        new_user = User(
                            user_id=user_id,
                            name=name,
                            card_no=getattr(user, 'card', None),
                            device_role=device_role,
                            created_at=datetime.now()
                        )
                        session.add(new_user)
                        added_count += 1

                if added_count > 0:
                    session.commit()
                    self.log("info", f"{added_count} yeni kullanıcı eklendi")
                return True

            finally:
                session.close()

        except Exception as e:
            self.log("error", f"Eksik kullanıcı senkronizasyonu hatası: {str(e)}")
            return False

    def run(self):
        """Ana dinleyici döngüsü."""
        last_check_time = 0
        reconnect_attempt = 0
        max_reconnect_attempts = int(os.getenv('RECONNECT_ATTEMPT_LIMIT', 5))
        check_interval = int(os.getenv('CHECK_INTERVAL', 60))
        reconnect_interval = int(os.getenv('RECONNECT_INTERVAL', 300))
 
        safe_log("INFO", f"Dinleyici başlatıldı - kontrol aralığı: {check_interval}s, yeniden bağlanma aralığı: {reconnect_interval}s", self.device_config.get('name', 'Terminal'))

        # İlk başlatmada tam senkronizasyon yap
        if self.connect():
            self.log("info", "İlk senkronizasyon yapılıyor...")
            self.sync_all_users(force=True)
            self.last_sync_time = time.time()
        
        while not self.stop_flag:
            try:
                current_time = time.time()

                # Düzenli kontrol
                if current_time - last_check_time >= check_interval:
                    last_check_time = current_time

                    # Bağlantı kontrolü
                    if not self.conn or not getattr(self.zk, 'is_connect', False):
                        if not self.connect():
                            reconnect_attempt += 1
                            if max_reconnect_attempts > 0 and reconnect_attempt >= max_reconnect_attempts:
                                self.log("critical", f"Maksimum yeniden bağlanma denemesi aşıldı ({max_reconnect_attempts}), dinleyici durduruluyor")
                                self.stop_flag = True
                                break
                            time.sleep(10)
                            continue
                        else:
                            reconnect_attempt = 0

                    # Yoklama verilerini al ve işle
                    self.process_attendance_data()

                    # 10 dakikada bir eksik kullanıcıları kontrol et
                    if current_time - self.last_sync_time >= self.sync_interval:
                        self.log("info", "Periyodik kullanıcı kontrolü yapılıyor...")
                        self.sync_missing_users()
                        self.last_sync_time = current_time
                
                # Performans optimizasyonu için kısa uyku
                time.sleep(1)
                
            except KeyboardInterrupt:
                self.log("info", "Kullanıcı tarafından durduruldu")
                break
            except Exception as e:
                self.log("error", f"Ana döngü hatası: {e}")
                try:
                    if self.conn and hasattr(self.zk, 'disconnect'):
                        self.zk.disconnect()
                    time.sleep(5)
                except:
                    pass
                
                reconnect_attempt += 1
                if max_reconnect_attempts > 0 and reconnect_attempt >= max_reconnect_attempts:
                    self.log("critical", f"Maksimum hata sayısına ulaşıldı ({max_reconnect_attempts}), dinleyici durduruluyor")
                    self.stop_flag = True
                    break
                
                time.sleep(5)
                
        self.log("info", "Dinleyici durduruldu")

    def stop(self):
        """Dinleyiciyi durdur"""
        self.stop_flag = True
        if self.conn:
            try:
                self.conn.disconnect()
            except:
                pass
        self.conn = None

    def create_user_from_device(self, user_id, device_id, device_ip):
        """Create a user from device data."""
        try:
            session = self.SessionLocal()
            # Check if user exists
            user = session.query(User).filter_by(user_id=user_id).first()
            if not user:
                # Get user info from device
                dev = self.get_device(device_id, device_ip)
                if dev:
                    try:
                        self.log("info", f"ID: {user_id} için kullanıcı bilgisi cihazdan alınıyor: {device_ip}")
                        user_info = dev.get_user(user_id)
                        if user_info:
                            self.log("info", f"Cihaz verilerinden kullanıcı oluşturuluyor: {user_info}")
                            
                            # role_id'nin None olarak ayarlanması
                            role_id = getattr(user_info, 'role_id', None)
                            # Boş string kontrolü yap ve None olarak ayarla
                            device_role = None if role_id == "" else role_id
                            self.log("info", f"Rol bilgisi: Orjinal={role_id}, Düzenlenmiş={device_role}")
                            
                            name = getattr(user_info, 'name', f"Kullanıcı {user_id}")
                            if name:
                                name = to_ascii(name)
                            else:
                                name = f"Kullanıcı {user_id}"
                            
                            user = User(
                                user_id=user_id,
                                name=name,
                                card_no=getattr(user_info, 'card', None),
                                device_role=device_role,  # Güncellenmiş role_id değeri kullanılıyor
                                created_at=datetime.now()
                            )
                            
                            session.add(user)
                            session.commit()
                            self.log("info", f"Kullanıcı oluşturuldu: {user_id}")
                            return user
                        else:
                            self.log("warning", f"Cihazdan kullanıcı bilgisi alınamadı: {device_ip}")
                    except Exception as e:
                        self.log("error", f"Cihazdan kullanıcı oluşturma hatası: {str(e)}")
                        session.rollback()
            return user
        except Exception as e:
            self.log("error", f"create_user_from_device hatası: {str(e)}")
            if 'session' in locals():
                session.rollback()
            return None
        finally:
            if 'session' in locals():
                session.close()

def main():
    parser = argparse.ArgumentParser(description='ZKTeco Terminal Dinleyici')
    
    # Cihaz parametreleri
    parser.add_argument('--ip', required=True, help='Terminal IP adresi')
    parser.add_argument('--port', type=int, default=4370, help='Terminal port numarası')
    parser.add_argument('--timeout', type=int, default=15, help='Bağlantı zaman aşımı (saniye)')
    parser.add_argument('--name', help='Terminal adı')
    
    # Veritabanı parametreleri
    parser.add_argument('--db-host', dest='db_host', default='localhost',
                      help='PostgreSQL sunucu adresi')
    parser.add_argument('--db-user', dest='db_user', default='postgres',
                      help='PostgreSQL kullanıcı adı')
    parser.add_argument('--db-pass', dest='db_pass', default='',
                      help='PostgreSQL şifresi')
    parser.add_argument('--db-name', dest='db_name', default='pdks',
                      help='PostgreSQL veritabanı adı')
    parser.add_argument('--db-port', dest='db_port', type=int, default=5432,
                      help='PostgreSQL port numarası')
    
    args = parser.parse_args()
    
    # Cihaz konfigürasyonu
    device_config = {
        'ip': args.ip,
        'port': args.port,
        'timeout': args.timeout,
        'name': args.name or f"Terminal ({args.ip})"
    }
    
    # Veritabanı konfigürasyonu
    db_config = {
        'host': args.db_host,
        'user': args.db_user,
        'password': args.db_pass,
        'dbname': args.db_name,
        'port': args.db_port
    }
    
    # Dinleyiciyi başlat
    listener = DeviceListener(device_config, db_config)
    
    try:
        listener.run()
    except KeyboardInterrupt:
        print("\nDinleyici durduruluyor...")
    finally:
        listener.stop()
        
    return 0

if __name__ == "__main__":
    sys.exit(main())