#!/usr/bin/env python
# -*- coding: utf-8 -*-

from zk import ZK
import sys
import time

# Cihaz bağlantı bilgileri
DEVICE_CONFIG = {
    'ip': '192.168.1.101',  # Cihazın IP adresi
    'port': 4370,           # Port numarası (genelde 4370'tir)
    'timeout': 5            # Bağlantı zaman aşımı (saniye)
}

# Kullanıcı bilgileri
USER_INFO = {
    'user_id': 9999,          # Kullanıcı ID (integer)
    'name': 'Test User',      # Kullanıcı adı
    'card_no': '123456789',   # Kart numarası
    'privilege': 14           # Yetki seviyesi (0: Normal kullanıcı, 14: Admin)
}

def connect_to_device():
    """Cihaza bağlanır ve bağlantı nesnesini döndürür"""
    try:
        # ZK nesnesini oluştur
        zk = ZK(DEVICE_CONFIG['ip'],
                port=DEVICE_CONFIG['port'],
                timeout=DEVICE_CONFIG['timeout'])
        
        # Bağlantıyı kur
        conn = zk.connect()
        print("Cihaza bağlantı başarılı!")
        return conn
    
    except Exception as e:
        print(f"Bağlantı hatası: {str(e)}")
        sys.exit(1)

def add_user_to_device(conn):
    """Kullanıcıyı cihaza ekler"""
    try:
        # Cihazı devre dışı bırak
        conn.disable_device()
        
        # İsmi ASCII'ye dönüştür
        ascii_name = USER_INFO['name'].encode('ascii', 'ignore').decode('ascii')
        
        # Kart numarasını string'e çevir
        card_no = str(USER_INFO['card_no'])
        
        # Kullanıcıyı ekle
        conn.set_user(
            uid=USER_INFO['user_id'],  # Integer olarak kullan
            name=ascii_name,
            privilege=int(USER_INFO['privilege']),
            card=card_no,
            user_id=str(USER_INFO['user_id'])  # ZK kütüphanesi için string'e çevir
        )
        
        # Cihazı tekrar aktifleştir
        conn.enable_device()
        
        print("Kullanıcı başarıyla eklendi!")
        return True
    
    except Exception as e:
        print(f"Kullanıcı ekleme hatası: {str(e)}")
        # Hata durumunda cihazı tekrar aktifleştirmeyi dene
        try:
            conn.enable_device()
        except:
            pass
        return False

def main():
    """Ana fonksiyon"""
    try:
        # Cihaza bağlan
        conn = connect_to_device()
        if not conn:
            return
        
        # Kullanıcıyı ekle
        add_user_to_device(conn)
        
        # Bağlantıyı kapat
        conn.disconnect()
        print("Bağlantı kapatıldı.")
        
    except Exception as e:
        print(f"Beklenmeyen hata: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 