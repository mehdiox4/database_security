# Mesure l'état de durcissement (appelé avant puis après le durcissement)
import json, os, stat, subprocess, sys, psycopg2
label = sys.argv[1]
c = psycopg2.connect(dbname="postgres"); c.autocommit = True
def q(s, p=None):
    with c.cursor() as cur:
        cur.execute(s, p); return cur.fetchall()
def setting(n): return q("SELECT setting FROM pg_settings WHERE name=%s", (n,))[0][0]
R = {}
R["Journalisation des connexions (log_connections)"] = setting("log_connections")
R["Journalisation des déconnexions"] = setting("log_disconnections")
R["Préfixe des journaux (utilisateur/IP/application)"] = setting("log_line_prefix")
R["Journalisation des instructions (log_statement)"] = setting("log_statement")
R["Attentes de verrous journalisées"] = setting("log_lock_waits")
R["Version TLS minimale"] = setting("ssl_min_protocol_version")
R["Chiffrement des mots de passe (password_encryption)"] = setting("password_encryption")
R["Exposition réseau (listen_addresses)"] = setting("listen_addresses")
hba = q("SELECT type, count(*) FROM pg_hba_file_rules WHERE type LIKE 'host%' GROUP BY 1 ORDER BY 1")
R["Règles pg_hba réseau (type : nombre)"] = ", ".join(f"{t}:{n}" for t, n in hba) or "aucune"
R["Règles pg_hba en méthode 'trust'"] = str(q("SELECT count(*) FROM pg_hba_file_rules WHERE auth_method='trust'")[0][0])
R["Comptes superutilisateurs"] = ", ".join(r[0] for r in q("SELECT rolname FROM pg_roles WHERE rolsuper ORDER BY 1"))
R["Comptes applicatifs/labo non nécessaires"] = ", ".join(r[0] for r in q(
    "SELECT rolname FROM pg_roles WHERE rolname LIKE '%lab%' OR rolname LIKE 'temp\\_%'")) or "aucun"
R["Compte applicatif app_backend : superuser/createrole"] = str(q(
    "SELECT rolsuper OR rolcreaterole OR rolcreatedb FROM pg_roles WHERE rolname='app_backend'")[0][0])
cfg = q("SELECT rolconfig FROM pg_roles WHERE rolname='app_backend'")[0][0]
R["Délais (statement/idle) du compte app_backend"] = ", ".join(cfg) if cfg else "aucun"
R["PUBLIC peut créer dans le schéma public"] = str(q("SELECT has_schema_privilege('public','public','CREATE')")[0][0])
bank = psycopg2.connect(dbname="bank_db"); 
with bank.cursor() as cur:
    cur.execute("SELECT has_database_privilege('public','bank_db','CONNECT')"); R["PUBLIC peut se connecter à bank_db"] = str(cur.fetchone()[0])
    cur.execute("SELECT count(*) FROM pg_class WHERE relnamespace='bank'::regnamespace AND relkind='r' AND NOT relrowsecurity AND relname IN ('customer','account','bank_transaction','transfer','loan','beneficiary')"); R["Tables sensibles sans RLS"] = str(cur.fetchone()[0])
    cur.execute("SELECT count(*) FROM bank.app_user WHERE password_hash NOT LIKE '$argon2id$%'"); R["Mots de passe non hachés Argon2id"] = str(cur.fetchone()[0])
d = q("SHOW data_directory")[0][0]
R["Permissions du répertoire de données"] = oct(stat.S_IMODE(os.stat(d).st_mode))
R["Permissions de pg_hba.conf"] = oct(stat.S_IMODE(os.stat("/etc/postgresql/16/main/pg_hba.conf").st_mode))
R["Version du serveur"] = q("SHOW server_version")[0][0]
json.dump(R, open(f"/home/claude/bank/build/evidence/hard_{label}.json", "w"), ensure_ascii=False, indent=1)
for k, v in R.items(): print(f"{k:<55} {v}")
