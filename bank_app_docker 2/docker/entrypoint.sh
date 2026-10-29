#!/bin/bash
# Point d'entrée du conteneur applicatif : attend la base, crée les comptes
# de connexion (Argon2id) si besoin, puis démarre Flask.
set -e
cd /opt/bank

echo "[app] attente de PostgreSQL ($PGHOST)..."
until pg_isready -h "$PGHOST" -U "$PGUSER" -d bank_db >/dev/null 2>&1; do sleep 1; done

echo "[app] comptes applicatifs (idempotent)"
python app/seed_users.py || true

echo "[app] démarrage de Flask sur 0.0.0.0:5000"
cd app
exec flask --app app.py run --host 0.0.0.0 --port 5000
