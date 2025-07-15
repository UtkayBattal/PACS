FROM postgres:14

# Python ve gerekli paketleri yükle
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Çalışma dizinini ayarla
WORKDIR /docker-entrypoint-initdb.d

# Virtual environment oluştur ve aktive et
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Gerekli Python paketlerini yükle
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Migration dosyalarını kopyala
COPY migrations/ .

# Veritabanı başlatıldıktan sonra migration'ları çalıştır
COPY init-db.sh /docker-entrypoint-initdb.d/
RUN chmod +x /docker-entrypoint-initdb.d/init-db.sh 