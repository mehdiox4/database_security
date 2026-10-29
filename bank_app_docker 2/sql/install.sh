#!/bin/sh
# Installation complète (superutilisateur postgres)
set -e
for f in 00_database 01_schema 02_roles; do psql -v ON_ERROR_STOP=1 -U postgres -d ${DB:-postgres} -f $f.sql; done
