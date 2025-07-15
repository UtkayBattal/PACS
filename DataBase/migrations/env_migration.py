import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from alembic import command as alembic_command
from alembic.config import Config
from models import Base
import psycopg2

# .env dosyasını yükle
load_dotenv()

def get_db_url():
    """
    Get database URL from environment variables
    """
    return "postgresql://dbuser:dbpass123@localhost:5433/myapp_db"

def create_database():
    """Veritabanını oluştur"""
    params = {
        'dbname': 'postgres',  # Önce postgres veritabanına bağlan
        'user': os.getenv("DB_USER", "postgres"),
        'password': os.getenv("DB_PASSWORD", "postgres"),
        'host': os.getenv("DB_HOST", "localhost"),
        'port': os.getenv("DB_PORT", "5432")
    }
    
    target_db = os.getenv("DB_NAME", "pdks")
    
    try:
        # Postgres veritabanına bağlan
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        cur = conn.cursor()
        
        # Veritabanı var mı kontrol et
        cur.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{target_db}'")
        exists = cur.fetchone()
        
        if not exists:
            # Veritabanı yoksa oluştur
            cur.execute(f'CREATE DATABASE {target_db}')
            print(f"Veritabanı '{target_db}' oluşturuldu.")
        
        cur.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Veritabanı oluşturma hatası: {str(e)}")
        return False

# SQLAlchemy engine ve session oluştur
engine = create_engine(get_db_url())
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Veritabanı oturumu oluştur"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_alembic():
    """Alembic yapılandırmasını başlat"""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    config = Config(os.path.join(current_dir, "alembic.ini"))
    config.set_main_option("script_location", current_dir)
    config.set_main_option("sqlalchemy.url", get_db_url())
    return config

def create_tables():
    """Tüm tabloları oluştur"""
    if create_database():
        Base.metadata.create_all(bind=engine)
        print("Tablolar başarıyla oluşturuldu.")
    else:
        print("Veritabanı oluşturulamadığı için tablolar oluşturulamadı.")

def drop_tables():
    """Tüm tabloları sil"""
    Base.metadata.drop_all(bind=engine)
    print("Tablolar başarıyla silindi.")

def run_migrations():
    """Migration'ları çalıştır"""
    config = init_alembic()
    
    try:
        # Alembic'i başlat
        alembic_command.stamp(config, "head")
        
        # Yeni migration oluştur
        alembic_command.revision(config, autogenerate=True, message="Otomatik migration")
        
        # Migration'ları uygula
        alembic_command.upgrade(config, "head")
        print("Migration'lar başarıyla uygulandı.")
    except Exception as e:
        print(f"Migration hatası: {str(e)}")
        raise

def rollback_migrations():
    """Migration'ları geri al"""
    config = init_alembic()
    alembic_command.downgrade(config, "-1")
    print("Son migration geri alındı.")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Kullanım: python env_migration.py [create|drop|migrate|rollback]")
        sys.exit(1)
    
    cmd = sys.argv[1].lower()
    
    if cmd == "create":
        create_tables()
    elif cmd == "drop":
        drop_tables()
    elif cmd == "migrate":
        run_migrations()
    elif cmd == "rollback":
        rollback_migrations()
    else:
        print("Geçersiz komut. Kullanılabilir komutlar: create, drop, migrate, rollback") 