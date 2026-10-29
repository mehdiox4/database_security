# seed_users.py - crée les comptes applicatifs de démonstration (mots de passe hachés Argon2id)
# Idempotent : peut être rejoué sans erreur (ON CONFLICT DO NOTHING), ce qui permet de
# l'appeler à chaque démarrage du conteneur applicatif sans dupliquer les comptes.
import os
import psycopg2
from argon2 import PasswordHasher
ph = PasswordHasher()
DEMO_PASSWORD = "Bank@Demo2026!"          # mot de passe de démonstration (données fictives)
USERS = [  # (username, role_name, customer_id, employee_id)
    ("client_amine", "ROLE_CLIENT", 1, None), ("client_sara", "ROLE_CLIENT", 2, None),
    ("client_hamza", "ROLE_CLIENT", 3, None), ("client_imane", "ROLE_CLIENT", 4, None),
    ("client_reda", "ROLE_CLIENT", 5, None),  ("employee01", "ROLE_EMPLOYEE", None, 1),
    ("manager01", "ROLE_MANAGER", None, 2),   ("admin01", "ROLE_ADMIN", None, 3),
    ("auditor01", "ROLE_AUDITOR", None, 4),   ("employee02", "ROLE_EMPLOYEE", None, 5)]
# psycopg2/libpq complète automatiquement host, user et mot de passe à partir des
# variables d'environnement standard PGHOST / PGUSER / PGPASSWORD / PGSSLMODE si elles
# sont définies (cas du conteneur Docker, où PGHOST=db) ; sans elles, connexion locale
# par socket Unix (cas d'une installation directe sur Ubuntu, exécutée en tant que
# l'utilisateur système "postgres").
conn = psycopg2.connect(dbname="bank_db")
created = 0
with conn, conn.cursor() as cur:
    for username, role, cust, emp in USERS:
        cur.execute("""INSERT INTO bank.app_user
                       (username, password_hash, role_id, customer_id, employee_id)
                       SELECT %s, %s, role_id, %s, %s FROM bank.role WHERE role_name = %s
                       ON CONFLICT (username) DO NOTHING""",
                    (username, ph.hash(DEMO_PASSWORD), cust, emp, role))
        created += cur.rowcount
print(f"{created} nouveau(x) utilisateur(s) créé(s) ({len(USERS)} attendus au total)")
