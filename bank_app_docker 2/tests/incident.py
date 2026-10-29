# incident.py - simulation d'incident INC-2026-001 (laboratoire isolé, données fictives)
import json, os, sys, time
sys.path.insert(0, "/home/claude/bank/app")
os.environ.setdefault("FLASK_SECRET", "x" * 32); os.environ.setdefault("COOKIE_SECURE", "0")
import psycopg2, db
ATT = "185.220.101.45"                        # adresse externe fictive de l'attaquant
adm = psycopg2.connect(dbname="bank_db"); adm.autocommit = True
cur = adm.cursor()
cur.execute("SELECT now()"); t0 = cur.fetchone()[0]
conn = db.connect()
log = []
# Phase 1 : reconnaissance / force brute
for u, n in (("admin01", 6), ("client_imane", 2), ("manager01", 3)):
    for i in range(n): db.authenticate(conn, u, f"Essai{i}!", ATT)
st, mgr = db.authenticate(conn, "manager01", "Bank@Demo2026!", ATT)   # mot de passe faible deviné
log.append(f"connexion manager01 depuis {ATT} : {st}")
# Phase 2 : abus du compte privilégié
for cid in (1, 2, 3, 4, 5):
    with db.db_session(conn, mgr, ATT) as c:
        c.execute("SELECT bank.reveal_national_id(%s, %s)", (cid, "verification dossier client"))
for amt in (49000, 20000, 3000):
    r = db.make_transfer(conn, mgr, 1001, "MA6400010000000000001004", amt, "Régularisation", ATT)
    log.append(f"transfert {amt} MAD 1001->1004 : {r['result_status']}")
for st_ in ("FROZEN", "ACTIVE", "FROZEN"):
    with db.db_session(conn, mgr, ATT) as c:
        c.execute("UPDATE bank.account SET status=%s WHERE account_id=1005", (st_,))
# Phase 3 : tentatives d'effacement des traces (refusées)
for q in ("SELECT * FROM bank.audit_log", "DELETE FROM bank.audit_log",
          "UPDATE bank.account SET balance = 0 WHERE account_id = 1005"):
    try:
        with db.db_session(conn, mgr, ATT) as c: c.execute(q)
    except psycopg2.Error as e:
        log.append(f"refusé : {q} -> {e.pgerror.strip().splitlines()[0]}")
# Confinement par l'administrateur
admin = {"user_id": 8, "username": "admin01", "role_name": "ROLE_ADMIN", "customer_id": None}
cur.execute("SELECT user_id FROM bank.app_user WHERE username='admin01'"); admin["user_id"] = cur.fetchone()[0]
with db.db_session(conn, admin, "10.10.1.2") as c:
    c.execute("UPDATE bank.app_user SET is_active = FALSE WHERE username = 'manager01'")
st2, _ = db.authenticate(conn, "manager01", "Bank@Demo2026!", ATT)
log.append(f"après confinement, connexion manager01 : {st2}")
cur.execute("SELECT to_char(%s, 'YYYY-MM-DD HH24:MI:SS TZ')", (t0,)); T0 = cur.fetchone()[0]
json.dump(dict(t0=T0, log=log), open("/home/claude/bank/build/evidence/incident_run.json", "w"), ensure_ascii=False, indent=1)
print("\n".join(log))
