# PACS - Personel Devam Kontrol Sistemi

## 📋 Proje Hakkında

PACS (Personel Devam Kontrol Sistemi), ZKTeco parmak izi terminalleri ile entegre çalışan, Docker tabanlı bir personel devam kontrol ve izin takip sistemidir. Sistem, modern web teknolojileri kullanarak geliştirilmiş olup, mikroservis mimarisi ile tasarlanmıştır.

## 🏗️ Sistem Mimarisi

Proje 3 ana bileşenden oluşmaktadır:

### 1. **DataBase** - Veritabanı Servisi
- **Teknoloji**: PostgreSQL 14 + Python 3.9
- **Görev**: Merkezi veritabanı yönetimi
- **Özellikler**:
  - SQLAlchemy ORM ile veri modelleme
  - Alembic ile veritabanı migration yönetimi
  - Otomatik tablo oluşturma ve varsayılan veri ekleme

### 2. **PDKS_Listener** - Terminal Dinleyici Servisi
- **Teknoloji**: Python 3.9 + pyzk kütüphanesi
- **Görev**: ZKTeco terminallerinden veri toplama
- **Özellikler**:
  - Gerçek zamanlı terminal bağlantısı
  - Otomatik yoklama verisi senkronizasyonu
  - Kullanıcı bilgileri otomatik aktarımı
  - Bağlantı kopması durumunda otomatik yeniden bağlanma
  - Gelişmiş hata yönetimi ve loglama

### 3. **PDKS_Panel** - Web Yönetim Paneli
- **Teknoloji**: Flask + SQLAlchemy + Bootstrap
- **Görev**: Web tabanlı yönetim arayüzü
- **Özellikler**:
  - Kullanıcı yönetimi ve kimlik doğrulama
  - Terminal yönetimi ve konfigürasyonu
  - Detaylı raporlama sistemi (PDF/Excel export)
  - İzin talepleri yönetimi
  - Gerçek zamanlı dashboard

## 🚀 Kurulum ve Çalıştırma

### Gereksinimler
- Docker ve Docker Compose
- En az 4GB RAM
- Ağ erişimi (terminaller için)

### Hızlı Başlangıç

1. **Projeyi klonlayın:**
```bash
git clone <repository-url>
cd PACS
```

2. **Veritabanı servisini başlatın:**
```bash
cd DataBase
docker-compose up -d
```

3. **Web panelini başlatın:**
```bash
cd ../PDKS_Panel
docker-compose up -d
```

4. **Terminal dinleyicisini başlatın:**
```bash
cd ../PDKS_Listener
# .env dosyasını düzenleyin (terminal IP adreslerini ekleyin)
docker-compose up -d
```

### Detaylı Kurulum

#### 1. Veritabanı Kurulumu

```bash
cd DataBase
# Docker Compose ile PostgreSQL başlat
docker-compose up -d

# Veritabanı durumunu kontrol et
docker logs pdks_database
```

**Varsayılan Veritabanı Bilgileri:**
- Host: localhost:5433
- Database: myapp_db
- Username: dbuser
- Password: dbpass123

#### 2. Web Panel Kurulumu

```bash
cd PDKS_Panel
# Environment dosyasını oluştur
cp WebService/panel/.env.example WebService/panel/.env

# Docker ile başlat
docker-compose up -d
```

**Varsayılan Panel Erişimi:**
- URL: http://localhost:5000
- Admin Email: admin@admin.com
- Admin Password: admin

#### 3. Terminal Dinleyici Kurulumu

```bash
cd PDKS_Listener
# Environment dosyasını oluştur
cp .env.example .env

# Terminal IP adreslerini .env dosyasına ekle
echo "DEVICE_IP=192.168.1.100" >> .env
echo "DEVICE_PORT=4370" >> .env

# Docker ile başlat
docker-compose up -d
```

## 📊 Veritabanı Şeması

### Ana Tablolar

#### Users (Kullanıcılar)
- `user_id`: Birincil anahtar
- `name`: Ad soyad
- `email`: E-posta adresi
- `password`: Şifrelenmiş şifre
- `role_id`: Rol referansı
- `department_id`: Departman referansı
- `card_no`: Kart numarası
- `device_role`: Terminal yetki seviyesi
- `status`: Aktif/Pasif durumu

#### Devices (Terminaller)
- `device_id`: Birincil anahtar
- `name`: Terminal adı
- `ip`: IP adresi
- `port`: Port numarası
- `location_id`: Konum referansı
- `is_active`: Aktif durumu
- `last_connection`: Son bağlantı zamanı

#### Records (Kayıtlar)
- `id`: Birincil anahtar
- `user_id`: Kullanıcı referansı
- `device_id`: Terminal referansı
- `timestamp`: Kayıt zamanı
- `punch`: Giriş/Çıkış (0/1)
- `status`: Durum bilgisi

#### LeaveRequests (İzin Talepleri)
- `id`: Birincil anahtar
- `user_id`: Talep eden kullanıcı
- `start_date`: İzin başlangıç tarihi
- `end_date`: İzin bitiş tarihi
- `reason`: İzin sebebi
- `status`: Talep durumu (bekleniyor/onaylandı/reddedildi)
- `approved_by`: Onaylayan admin

## 🔧 Konfigürasyon

### Environment Variables

#### DataBase (.env)
```env
POSTGRES_USER=dbuser
POSTGRES_PASSWORD=dbpass123
POSTGRES_DB=myapp_db
POSTGRES_PORT=5433
```

#### PDKS_Panel (.env)
```env
DB_USER=dbuser
DB_PASSWORD=dbpass123
DB_HOST=pdks_database
DB_PORT=5433
DB_NAME=myapp_db
FLASK_ENV=production
SECRET_KEY=your-secret-key
```

#### PDKS_Listener (.env)
```env
DEVICE_IP=192.168.1.100
DEVICE_PORT=4370
DEVICE_TIMEOUT=5
DB_HOST=pdks_database
DB_USER=dbuser
DB_PASSWORD=dbpass123
DB_NAME=myapp_db
DB_PORT=5433
CHECK_INTERVAL=30
RECONNECT_INTERVAL=300
CLEAR_ATTENDANCE=true
```

## 📈 Özellikler

### 🎯 Temel Özellikler
- **Gerçek Zamanlı Veri Toplama**: Terminal verilerinin anlık senkronizasyonu
- **Çoklu Terminal Desteği**: Birden fazla terminali aynı anda yönetme
- **Otomatik Kullanıcı Senkronizasyonu**: Terminal kullanıcılarının otomatik aktarımı
- **Gelişmiş Hata Yönetimi**: Bağlantı kopması durumunda otomatik yeniden bağlanma

### 📊 Raporlama Sistemi
- **Personel Listesi**: Tüm personelin detaylı bilgileri
- **Detaylı Giriş-Çıkış**: Zaman bazlı detaylı kayıtlar
- **Puantaj Raporları**: Günlük, haftalık ve dönemsel puantaj
- **Excel/PDF Export**: Raporları farklı formatlarda indirme
- **Filtreleme**: Departman, tarih, kullanıcı bazlı filtreleme

### 👥 Kullanıcı Yönetimi
- **Rol Tabanlı Yetkilendirme**: Admin, Supervisor, User rolleri
- **Güvenli Kimlik Doğrulama**: PBKDF2 ile şifre hashleme
- **Profil Yönetimi**: Kullanıcı bilgilerini güncelleme
- **Departman Yönetimi**: Departman bazlı organizasyon

### 📅 İzin Yönetimi
- **İzin Talepleri**: Personel izin talebi oluşturma
- **Onay Süreci**: Admin onayı ile izin yönetimi
- **İzin Takibi**: Kullanılan ve kalan izin günleri
- **Otomatik Hesaplama**: İzin gün sayısı otomatik hesaplama

### 🔧 Terminal Yönetimi
- **Terminal Konfigürasyonu**: IP, port ve ayar yönetimi
- **Bağlantı Durumu**: Gerçek zamanlı terminal durumu
- **Kullanıcı Aktarımı**: Terminal kullanıcılarını sisteme aktarma
- **Parmak İzi Yönetimi**: Parmak izi kayıt ve silme işlemleri

## 🛠️ API Endpoints

### Kimlik Doğrulama
- `POST /login` - Kullanıcı girişi
- `POST /logout` - Kullanıcı çıkışı
- `GET /profile` - Kullanıcı profili

### Terminal Yönetimi
- `GET /devices` - Terminal listesi
- `POST /devices` - Yeni terminal ekleme
- `PUT /devices/<id>` - Terminal güncelleme
- `DELETE /devices/<id>` - Terminal silme

### Raporlama
- `POST /reports/generate` - Rapor oluşturma
- `POST /reports/download` - Rapor indirme
- `GET /reports/api/active-users-count` - Aktif kullanıcı sayısı

### İzin Yönetimi
- `GET /leave-requests/employee` - Personel izin paneli
- `POST /leave-requests/employee/create` - İzin talebi oluşturma
- `GET /leave-requests/admin` - Admin izin paneli
- `POST /leave-requests/admin/approve/<id>` - İzin onaylama
- `POST /leave-requests/admin/reject/<id>` - İzin reddetme

## 🔒 Güvenlik

### Kimlik Doğrulama
- PBKDF2 ile şifre hashleme
- Session tabanlı kimlik doğrulama
- Rol bazlı erişim kontrolü

### Veri Güvenliği
- SQL Injection koruması (SQLAlchemy ORM)
- XSS koruması (Flask-WTF)
- CSRF koruması
- Güvenli veritabanı bağlantıları

### Ağ Güvenliği
- Docker network izolasyonu
- Port yönetimi
- Environment variable ile hassas bilgi koruması

## 📝 Loglama

### Log Seviyeleri
- **INFO**: Genel bilgi mesajları
- **WARNING**: Uyarı mesajları
- **ERROR**: Hata mesajları
- **CRITICAL**: Kritik hata mesajları
- **SUCCESS**: Başarılı işlem mesajları

### Log Dosyaları
- `pdks_listener.log`: Terminal dinleyici logları
- `pdks_web.log`: Web panel logları
- `pdks_database.log`: Veritabanı logları

## 🐛 Sorun Giderme

### Yaygın Sorunlar

#### Terminal Bağlantı Sorunları
```bash
# Terminal IP'sini kontrol et
ping 192.168.1.100

# Port erişilebilirliğini kontrol et
telnet 192.168.1.100 4370

# Docker loglarını kontrol et
docker logs pdks-listener
```

#### Veritabanı Bağlantı Sorunları
```bash
# Veritabanı container durumunu kontrol et
docker ps | grep pdks_database

# Veritabanı loglarını kontrol et
docker logs pdks_database

# Bağlantıyı test et
docker exec -it pdks_database psql -U dbuser -d myapp_db
```

#### Web Panel Erişim Sorunları
```bash
# Container durumunu kontrol et
docker ps | grep pdks-web

# Port erişilebilirliğini kontrol et
curl http://localhost:5000

# Logları kontrol et
docker logs pdks-web
```

### Performans Optimizasyonu

#### Veritabanı Optimizasyonu
- İndekslerin doğru tanımlandığından emin olun
- Büyük veri setleri için sayfalama kullanın
- Gereksiz sorguları optimize edin

#### Terminal Bağlantı Optimizasyonu
- `CHECK_INTERVAL` değerini ayarlayın
- `RECONNECT_INTERVAL` değerini optimize edin
- Batch işlemler için `batch_size` ayarlayın

## 🔄 Güncelleme ve Bakım

### Veritabanı Migration
```bash
cd DataBase
# Yeni migration oluştur
alembic revision --autogenerate -m "migration_description"

# Migration'ı uygula
alembic upgrade head
```

### Container Güncelleme
```bash
# Tüm servisleri güncelle
docker-compose pull
docker-compose up -d

# Eski image'ları temizle
docker image prune -f
```

### Yedekleme
```bash
# Veritabanı yedeği
docker exec pdks_database pg_dump -U dbuser myapp_db > backup.sql

# Container yedeği
docker save pdks_database > pdks_database.tar
```

## 📞 Destek ve Katkıda Bulunma

### Geliştirici Bilgileri
- **Proje**: PACS - Personel Devam Kontrol Sistemi
- **Teknoloji**: Python, Flask, PostgreSQL, Docker
- **Mimari**: Mikroservis

### Katkıda Bulunma
1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Commit yapın (`git commit -m 'Add some AmazingFeature'`)
4. Push yapın (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

### Lisans
Bu proje MIT lisansı altında lisanslanmıştır.

## 📚 Ek Kaynaklar

### Dokümantasyon
- [Flask Dokümantasyonu](https://flask.palletsprojects.com/)
- [SQLAlchemy Dokümantasyonu](https://docs.sqlalchemy.org/)
- [Docker Dokümantasyonu](https://docs.docker.com/)
- [ZKTeco Terminal Dokümantasyonu](https://www.zkteco.com/)

### Faydalı Komutlar
```bash
# Tüm servisleri başlat
docker-compose -f DataBase/docker-compose.yml up -d
docker-compose -f PDKS_Panel/docker-compose.yml up -d
docker-compose -f PDKS_Listener/docker-compose.yml up -d

# Servisleri durdur
docker-compose -f DataBase/docker-compose.yml down
docker-compose -f PDKS_Panel/docker-compose.yml down
docker-compose -f PDKS_Listener/docker-compose.yml down

# Logları takip et
docker logs -f pdks-listener
docker logs -f pdks-web
docker logs -f pdks_database
```

---

**Not**: Bu sistem ZKTeco parmak izi terminalleri ile test edilmiştir. Farklı terminal markaları için ek konfigürasyon gerekebilir.
