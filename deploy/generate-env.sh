#!/bin/sh
# Создаёт .env из шаблона со случайными секретами. Существующий файл не трогает.
set -eu

[ ! -e .env ] || { echo ".env уже существует" >&2; exit 1; }

umask 077
cp .env.example .env
for name in POSTGRES_PASSWORD REDIS_PASSWORD S3_ACCESS_KEY S3_SECRET_KEY GRAFANA_PASSWORD; do
    sed -i "s/^$name=\$/$name=$(openssl rand -hex 32)/" .env
done
