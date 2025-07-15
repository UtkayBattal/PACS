#!/bin/bash
set -e

# Veritabanının hazır olmasını bekle
until PGPASSWORD=$POSTGRES_PASSWORD psql -h "localhost" -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c '\q'; do
  echo "Postgres is unavailable - sleeping"
  sleep 1
done

echo "PostgreSQL is up - executing migrations"
cd /docker-entrypoint-initdb.d
python3 env_migration.py migrate 