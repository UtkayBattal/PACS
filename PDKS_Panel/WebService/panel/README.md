# PDKS Yönetim Paneli

PDKS (Personel Devam Kontrol Sistemi) için web tabanlı bir yönetim panelidir. Bu panel, MySQL veritabanındaki kullanıcıları ve kayıtları yönetmek için kullanılır.

## Özellikler

- Kullanıcı yönetimi (ekleme, düzenleme, silme)
- Giriş/çıkış kayıtlarını görüntüleme ve filtreleme
- Parmak izi yönetimi (yakında)
- Cihaz durum bilgileri
- Admin profil yönetimi
- Güvenli oturum yönetimi

## Kurulum

1. Gerekli Python paketlerini yükleyin:

```bash
pip install -r requirements.txt
```

2. Uygulamayı başlatın:

```bash
python app.py
```

## Varsayılan Giriş Bilgileri

- Kullanıcı Adı: `admin`
- Şifre: `admin`

İlk girişten sonra şifrenizi değiştirmeniz önerilir.

## Sistem Gereksinimleri

- Python 3.8 veya daha yüksek
- MySQL 5.7 veya daha yüksek
- İnternet bağlantısı (Bootstrap ve Font Awesome CDN için)

## Bağlantı Bilgileri

Panel, ana PDKS Python programıyla aynı MySQL veritabanını kullanır. Veritabanı bağlantı ayarları otomatik olarak `pdks_config.json` dosyasından alınır.

## Güvenlik Notları

- Bu panel yerel ağda çalıştırılmak üzere tasarlanmıştır.
- Genel internet üzerinden erişim sağlamak için ek güvenlik önlemleri alınmalıdır.
- Üretim ortamında kullanmadan önce güvenlik testlerini gerçekleştirin.

## Lisans

Bu proje özel kullanım için geliştirilmiştir.
