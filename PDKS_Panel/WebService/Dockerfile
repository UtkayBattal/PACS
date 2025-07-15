FROM python:3.11-slim

WORKDIR /app

# Gerekli sistem paketlerini kur ve güvenlik güncellemelerini uygula
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    wkhtmltopdf \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Python paketlerini kopyala ve kur
COPY WebService/requirements.txt .

# Önce pyzk paketini kur
RUN pip install --no-cache-dir pyzk==0.9

# Sonra diğer paketleri kur
RUN pip install --no-cache-dir -r requirements.txt

# Paket kontrolü için script oluştur
COPY WebService/check_packages.py /app/check_packages.py

# Uygulama kodlarını kopyala
COPY WebService /app/WebService/

# Gereksiz dosyaları ve yönetici izinlerini kaldır
RUN rm -rf /tmp/* && \
    find . -type d -exec chmod 755 {} \; && \
    find . -type f -exec chmod 644 {} \;

# Güvenlik için root olmayan kullanıcı ekle ve kullan
RUN useradd -m appuser
USER appuser

# PYTHONPATH'i ayarla
ENV PYTHONPATH=/app

# Çalışma dizinini ayarla
WORKDIR /app/WebService

# Paket kontrolü yap ve Flask uygulamasını çalıştır
CMD ["bash", "-c", "python /app/check_packages.py && python run.py"] 