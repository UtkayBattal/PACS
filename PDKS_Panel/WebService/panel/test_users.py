#!/usr/bin/env python3

import os
import sys
from sqlalchemy import create_engine, text

# Database bağlantısı
db_user = os.environ.get('DB_USER', 'dbuser')
db_password = os.environ.get('DB_PASSWORD', 'dbpass123')
db_host = os.environ.get('DB_HOST', 'pdks_database')
db_port = os.environ.get('DB_PORT', '5432')
db_name = os.environ.get('DB_NAME', 'myapp_db')

DATABASE_URL = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

try:
    engine = create_engine(DATABASE_URL)
    
    # Database'e bağlan
    with engine.connect() as connection:
        print("=== DATABASE BAĞLANTISI BAŞARILI ===")
        
        # Users tablosundaki tüm kolonları kontrol et
        result = connection.execute(text("SELECT user_id, name, email, role_id, device_role, password FROM users LIMIT 20;"))
        users = result.fetchall()
        
        print(f"\nToplam {len(users)} kullanıcı bulundu:")
        for user in users:
            user_id, name, email, role_id, device_role, password = user
            print(f"- ID: {user_id}, Name: {name}, Email: {email}, Role: {role_id}, Device_Role: {device_role}, Has_Password: {'Yes' if password else 'No'}")
            
        # NULL user_id olan kayıtları kontrol et
        result = connection.execute(text("SELECT COUNT(*) FROM users WHERE user_id IS NULL;"))
        null_count = result.scalar()
        print(f"\nNULL user_id olan kayıt sayısı: {null_count}")
        
        # Admin veya yönetici kullanıcısını ara
        result = connection.execute(text("SELECT user_id, name, email, role_id FROM users WHERE LOWER(name) LIKE '%admin%' OR LOWER(name) LIKE '%yönetici%' OR LOWER(name) LIKE '%yonetici%' LIMIT 5;"))
        admins = result.fetchall()
        if admins:
            print(f"\nYönetici benzeri kullanıcılar bulundu:")
            for admin in admins:
                print(f"  - ID: {admin[0]}, Name: {admin[1]}, Email: {admin[2]}, Role: {admin[3]}")
        else:
            print("\nYönetici benzeri kullanıcı bulunamadı!")
            
        # Roles tablosu var mı kontrol et
        try:
            result = connection.execute(text("SELECT * FROM roles;"))
            roles = result.fetchall()
            print(f"\nRoles tablosu mevcut, {len(roles)} rol bulundu:")
            for role in roles:
                print(f"  - ID: {role[0]}, Name: {role[1]}")
        except Exception as e:
            print(f"\nRoles tablosu bulunamadı: {str(e)}")

except Exception as e:
    print(f"HATA: {str(e)}")
    sys.exit(1) 