from panel.app_orm import app, cleanup_connections
from dotenv import load_dotenv
import signal
import sys
import os

def signal_handler(sig, frame):
    print('\nUygulama kapatılıyor...')
    cleanup_connections()
    os._exit(0)

if __name__ == '__main__':
    # Signal handler'ı ekle
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # .env dosyasını yükle
    load_dotenv()
    
    # Uygulamayı başlat
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False) 