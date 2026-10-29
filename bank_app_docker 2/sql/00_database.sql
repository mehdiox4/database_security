-- [[create_db]]
-- Exécuter en tant que superutilisateur : psql -U postgres -f 00_database.sql
CREATE ROLE bank_owner NOLOGIN;                 -- propriétaire des objets (non connectable)

CREATE DATABASE bank_db
    OWNER bank_owner
    ENCODING 'UTF8'
    TEMPLATE template0;

REVOKE ALL ON DATABASE bank_db FROM PUBLIC;     -- personne ne se connecte par défaut

\connect bank_db

CREATE EXTENSION IF NOT EXISTS pgcrypto;        -- chiffrement, HMAC
CREATE SCHEMA bank AUTHORIZATION bank_owner;    -- schéma applicatif dédié
-- [[/create_db]]
