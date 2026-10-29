# run_tests.py - scénarios de sécurité exécutés pour de vrai contre PostgreSQL 16
import json, os, sys, threading, time
sys.path.insert(0, "/home/claude/bank/app")
os.environ.setdefault("FLASK_SECRET", "test-secret-" + "x" * 20)
os.environ.setdefault("COOKIE_SECURE", "0")
import psycopg2
from psycopg2 import errors
from decimal import Decimal
import db
from app import app

PWD = "Bank@Demo2026!"
R, EV = [], {}                      # R = tableau des tests ; EV = preuves (sorties)
adm = psycopg2.connect(dbname="bank_db")            # DBA local (superutilisateur)
adm.autocommit = True
def su(q, p=None):
    with adm.cursor() as c:
        c.execute(q, p)
        return c.fetchall() if c.description else None

def user(name):
    return su("SELECT u.user_id, u.username, r.role_name, u.customer_id FROM bank.app_user u "
              "JOIN bank.role r USING(role_id) WHERE username=%s", (name,))[0]
U = {n: dict(zip(("user_id", "username", "role_name", "customer_id"), user(n)))
     for n in ("client_amine", "client_sara", "client_hamza", "client_imane", "client_reda",
               "employee01", "manager01", "admin01", "auditor01")}
IP = {"client_amine": "197.230.12.34", "employee01": "10.10.1.21", "manager01": "10.10.1.5",
      "admin01": "10.10.1.2", "client_reda": "41.248.7.9", "client_imane": "105.157.3.77",
      "auditor01": "10.10.1.9", "client_hamza": "196.200.44.8"}
conn = db.connect()
def sess(name): return db.db_session(conn, U[name], IP.get(name, "127.0.0.1"))
def acct(i): return su("SELECT account_number FROM bank.account WHERE account_id=%s", (i,))[0][0]
def bal(i): return su("SELECT balance FROM bank.account WHERE account_id=%s", (i,))[0][0]
def add(tid, name, method, expected, obtained, ok, ev):
    R.append(dict(id=tid, name=name, method=method, expected=expected, obtained=obtained,
                  status="PASS" if ok else "FAIL")); EV[tid] = ev
    print(f"[{'PASS' if ok else 'FAIL'}] T{tid} {name} -> {obtained}")
def attempt(name, q, p=None):
    """Exécute q avec les droits de `name` ; renvoie ('OK', lignes) ou ('ERR', message)."""
    try:
        with sess(name) as cur:
            cur.execute(q, p)
            return "OK", (cur.fetchall() if cur.description else cur.rowcount)
    except psycopg2.Error as e:
        return "ERR", e.pgerror.strip().splitlines()[0] if e.pgerror else str(e)

# ---------------------------------------------------------------- T1 : SQL injection
su("DROP SCHEMA IF EXISTS sqli_lab CASCADE")
su("DROP ROLE IF EXISTS sqli_lab_user")
su("CREATE SCHEMA sqli_lab")
su("CREATE TABLE sqli_lab.users (username text, password text)")
su("INSERT INTO sqli_lab.users VALUES ('admin','Lab-S3cret'), ('bob','bob-pass')")
su("CREATE ROLE sqli_lab_user LOGIN PASSWORD 'lab'")
su("GRANT CONNECT ON DATABASE bank_db TO sqli_lab_user")
su("GRANT USAGE ON SCHEMA sqli_lab TO sqli_lab_user")
su("GRANT SELECT ON sqli_lab.users TO sqli_lab_user")
lab = psycopg2.connect(host="localhost", dbname="bank_db", user="sqli_lab_user", password="lab")
def vulnerable(u, p):
    q = "SELECT username FROM sqli_lab.users WHERE username = '" + u + "' AND password = '" + p + "'"
    with lab.cursor() as c:
        c.execute(q); return q, [r[0] for r in c.fetchall()]
def secure(u, p):
    with lab.cursor() as c:
        c.execute("SELECT username FROM sqli_lab.users WHERE username = %s AND password = %s", (u, p))
        return [r[0] for r in c.fetchall()]
payloads = [("admin' --", "x"), ("' OR '1'='1", "' OR '1'='1"),
            ("' UNION SELECT username || ':' || password FROM sqli_lab.users --", "x")]
ev, vuln_ok, sec_ok = [], 0, 0
for u, p in payloads:
    q, rows = vulnerable(u, p); lab.rollback()
    vuln_ok += bool(rows)
    ev += ["[VULNÉRABLE] SQL exécuté : " + q, "              lignes retournées : " + str(rows)]
    srows = secure(u, p); lab.rollback(); sec_ok += (srows == [])
    ev += ["[PARAMÉTRÉ ] même entrée    : lignes retournées : " + str(srows)]
st, usr = db.authenticate(conn, "admin' --", "x", "203.0.113.50")
ev.append(f"[APPLICATION] authenticate(\"admin' --\") -> {st}")
st2, _ = db.authenticate(conn, "client_amine' OR '1'='1", "x", "203.0.113.50")
ev.append(f"[APPLICATION] authenticate(\"client_amine' OR '1'='1\") -> {st2}")
q = attempt("client_amine", "SELECT username, password_hash FROM bank.app_user")
ev.append("[DÉFENSE EN PROFONDEUR] role_client lit app_user -> " + q[1])
add(1, "Injection SQL", "Payloads classiques (contournement, OR 1=1, UNION) sur login naïf puis paramétré",
    "Blocked", f"Naïf : {vuln_ok}/3 réussissent ; paramétré : {sec_ok}/3 bloquées ; application : {st}/{st2}",
    vuln_ok == 3 and sec_ok == 3 and st == st2 == "INVALID" and q[0] == "ERR", ev)

# ---------------------------------------------------------------- T2 : isolation entre clients
ev = []
ok1, mine = attempt("client_amine", "SELECT account_id FROM bank.account ORDER BY 1")
ev.append("Amine : SELECT account_id FROM bank.account -> " + str([r['account_id'] for r in mine]))
ok2, other = attempt("client_amine", "SELECT * FROM bank.account WHERE customer_id = 3")
ev.append("Amine : SELECT * FROM account WHERE customer_id = 3 (Hamza) -> " + f"{len(other)} ligne(s)")
ok3, tx = attempt("client_amine", "SELECT * FROM bank.bank_transaction WHERE account_id = 1004")
ev.append("Amine : transactions du compte 1004 (Hamza) -> " + f"{len(tx)} ligne(s)")
e4 = attempt("client_amine", "SELECT national_id FROM bank.customer")
ev.append("Amine : SELECT national_id FROM customer -> " + e4[1])
e5 = attempt("client_amine", "SELECT * FROM bank.audit_log")
ev.append("Amine : SELECT * FROM audit_log -> " + e5[1])
e6 = attempt("client_amine", "INSERT INTO bank.beneficiary (customer_id, name, bank_name, account_number)"
             " VALUES (3, 'Pirate', 'X', 'MA00')")
ev.append("Amine : INSERT beneficiary pour Hamza -> " + e6[1])
add(2, "Accès aux données d'un autre client", "Client Amine tente de lire/écrire les données de Hamza",
    "Permission Denied", "0 ligne via RLS ; permission denied (audit_log, national_id) ; violation RLS à l'écriture",
    [r['account_id'] for r in mine] == [1001, 1002] and other == [] and tx == []
    and e4[0] == e5[0] == e6[0] == "ERR", ev)

# ---------------------------------------------------------------- T3 : modification de solde
ev = []
s_cl = attempt("client_amine", "UPDATE bank.account SET balance = 1000000 WHERE account_id = 1001")
ev.append("client_amine  : UPDATE account SET balance = 1000000 -> " + s_cl[1])
s_em = attempt("employee01", "UPDATE bank.account SET balance = 1000000 WHERE account_id = 1001")
ev.append("employee01    : UPDATE account SET balance = 1000000 -> " + s_em[1])
s_mg = attempt("manager01", "UPDATE bank.account SET balance = 1000000 WHERE account_id = 1001")
ev.append("manager01     : UPDATE account SET balance = 1000000 -> " + s_mg[1])
try:
    su("UPDATE bank.account SET balance = 1000000 WHERE account_id = 1001"); s_su = "OK"
except psycopg2.Error as e:
    s_su = e.pgerror.strip().splitlines()[0]
ev.append("postgres (DBA): UPDATE account SET balance = 1000000 -> " + s_su)
add(3, "Modification directe d'un solde", "UPDATE balance par client, employé, manager et même DBA",
    "Unauthorized", "permission denied (client/employé/manager) ; trigger BK002 (DBA)",
    s_cl[0] == s_em[0] == s_mg[0] == "ERR" and "interdite" in s_su and bal(1001) == Decimal("12500.00"), ev)

# ---------------------------------------------------------------- T4 : solde insuffisant et refus métier
ev = []
b_before = (bal(1006), bal(1005))
with sess("client_reda") as cur:
    cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s)", (1006, acct(1005), 2000, "Test solde"))
    r4 = cur.fetchone()
ev.append(f"Reda (500 MAD) -> Imane 2000 MAD : {dict(r4)}")
cases = [("Amine débite le compte de Sara", "client_amine", (1003, acct(1001), 100, "x")),
         ("Amine -> compte non bénéficiaire (Imane)", "client_amine", (1001, acct(1005), 100, "x")),
         ("Montant négatif", "client_amine", (1001, acct(1003), -50, "x")),
         ("Compte destinataire inexistant", "client_amine", (1001, "MA0000000000000000000000", 10, "x"))]
rej = 0
for label, who, args in cases:
    with sess(who) as cur:
        cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s)", args); r = cur.fetchone()
    rej += r["result_status"] == "REJECTED"
    ev.append(f"{label} : {r['result_status']} - {r['result_message']}")
n_rej = su("SELECT count(*) FROM bank.audit_log WHERE action='TRANSFER_REJECTED'")[0][0]
ev.append(f"Entrées d'audit TRANSFER_REJECTED : {n_rej}")
add(4, "Virement avec solde insuffisant", "Reda (500 MAD) envoie 2000 MAD ; 4 autres refus métier",
    "Transaction rejected", f"{r4['result_status']} : {r4['result_message']} ; {rej}/4 autres rejets",
    r4["result_status"] == "REJECTED" and rej == 4 and (bal(1006), bal(1005)) == b_before and n_rej == 5, ev)

# ---------------------------------------------------------------- T5 : erreur pendant un virement
ev = []
a0, b0 = bal(1001), bal(1003)
ev.append(f"Avant   : compte 1001 = {a0} MAD ; compte 1003 = {b0} MAD")
with sess("client_amine") as cur:
    cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s,%s)", (1001, acct(1003), 300, "Loyer", True))
    r5 = cur.fetchone()
a1, b1 = bal(1001), bal(1003)
n_tr = su("SELECT count(*) FROM bank.transfer")[0][0]
ev.append(f"Résultat: {dict(r5)}")
ev.append(f"Après   : compte 1001 = {a1} MAD ; compte 1003 = {b1} MAD ; virements enregistrés = {n_tr}")
ev.append("Audit   : " + str(su("SELECT action, result, new_value FROM bank.audit_log "
                              "WHERE action='TRANSFER_ROLLBACK'")[0]))
with sess("client_amine") as cur:
    cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s)", (1001, acct(1003), 300, "Loyer"))
    r5b = cur.fetchone()
ev.append(f"Rejeu sans panne : {dict(r5b)} ; soldes {bal(1001)} / {bal(1003)}")
add(5, "Erreur pendant un virement", "Panne simulée après le débit de 300 MAD (1001 -> 1003)",
    "ROLLBACK", f"{r5['result_status']} : soldes inchangés ({a1} / {b1}) ; rejeu : {r5b['result_status']}",
    r5["result_status"] == "ROLLED_BACK" and (a1, b1) == (a0, b0) and n_tr == 0
    and r5b["result_status"] == "COMPLETED" and (bal(1001), bal(1003)) == (Decimal("12200.00"), Decimal("8500.00")), ev)

# ---------------------------------------------------------------- T6 : audit d'une modification sensible
ev = []
with sess("employee01") as cur:
    cur.execute("SELECT bank.update_customer_contact(%s, NULL, %s, NULL)", (3, "+212600000999"))
rows = su("SELECT audit_id, user_id, action, table_name, record_id, host(ip_address), old_value, new_value, result "
          "FROM bank.audit_log WHERE table_name='customer' AND action='UPDATE' ORDER BY audit_id DESC LIMIT 1")
ev.append("Dernière ligne d'audit (table customer) : " + str(rows[0]))
with sess("employee01") as cur:
    cur.execute("SELECT bank.create_customer(%s,%s,%s,%s,%s,%s,%s)",
                ("Test", "Fictif", "1990-01-01", "test.fictif@mail.test", "+212600000106", "1 Rue Test", "FAKE00999999"))
    new_id = cur.fetchone()["create_customer"]
ins = su("SELECT new_value FROM bank.audit_log WHERE table_name='customer' AND action='INSERT' "
         "ORDER BY audit_id DESC LIMIT 1")[0][0]
ev.append(f"Création du client {new_id} : national_id présent dans le journal ? " + str("national_id" in ins))
eb = attempt("employee01", "SELECT * FROM bank.customer")
ev.append("employee01 : SELECT * FROM bank.customer -> " + eb[1])
add(6, "Modification d'une donnée sensible", "employee01 modifie le téléphone du client 3",
    "Audit Log generated", f"audit_id {rows[0][0]} : {rows[0][6]} -> {rows[0][7]} (user_id {rows[0][1]}, IP {rows[0][5]})",
    rows[0][6] == {"phone": "+212600000103"} and rows[0][7] == {"phone": "+212600000999"}
    and "national_id" not in ins and eb[0] == "ERR", ev)

# ---------------------------------------------------------------- T7 : force brute (via Flask)
ev = []
cli = app.test_client()
def post_login(u, p):
    cli.get("/login")
    with cli.session_transaction() as s: s["csrf"] = "tok"
    return cli.post("/login", data={"username": u, "password": p, "csrf": "tok"},
                    environ_overrides={"REMOTE_ADDR": "196.200.44.8"})
codes = [post_login("client_hamza", "mauvais-%d" % i).status_code for i in range(1, 6)]
ev.append("5 mots de passe erronés (HTTP) : " + str(codes))
late = post_login("client_hamza", PWD)
ev.append(f"6e tentative avec le BON mot de passe : HTTP {late.status_code} (compte verrouillé)")
al = su("SELECT alert_id, rule_code, severity, username, description FROM bank.security_alert "
        "WHERE rule_code='BRUTE_FORCE'")
ev.append("security_alert : " + str(al))
au = su("SELECT action, table_name, result FROM bank.audit_log WHERE table_name='security_alert'")
ev.append("audit_log      : " + str(au))
ev.append("login_attempt  : " + str(su("SELECT username, success, host(ip_address) FROM bank.login_attempt "
                                       "WHERE username='client_hamza' ORDER BY attempt_id")))
add(7, "Tentatives de connexion répétées", "5 échecs puis connexion correcte sur client_hamza",
    "Security alert", f"Alerte {al[0][2]} + verrouillage 15 min ; 6e tentative : HTTP {late.status_code}",
    codes == [401] * 5 and late.status_code == 423 and len(al) == 1 and len(au) == 1, ev)
with sess("admin01") as cur:       # déverrouillage par l'administrateur (traçable)
    cur.execute("UPDATE bank.app_user SET locked_until = NULL, failed_attempts = 0 "
                "WHERE username = 'client_hamza'")

# ---------------------------------------------------------------- T8 : mots de passe
ev = []
hs = su("SELECT username, substr(password_hash, 1, 31) || '…' FROM bank.app_user ORDER BY user_id LIMIT 3")
for h in hs: ev.append(f"{h[0]:<14} {h[1]}")
bad = su("SELECT count(*) FROM bank.app_user WHERE password_hash NOT LIKE '$argon2id$%'")[0][0]
ev.append(f"Lignes dont le hachage n'est pas Argon2id : {bad}")
try:
    su("INSERT INTO bank.app_user (username, password_hash, role_id, customer_id) "
       "SELECT 'pirate01', 'MonMotDePasse123', role_id, 6 FROM bank.role WHERE role_name='ROLE_CLIENT'")
    ins_p = "accepté"
except psycopg2.Error as e:
    ins_p = e.pgerror.strip().splitlines()[0]
ev.append("INSERT d'un mot de passe en clair -> " + ins_p)
h1, h2 = db.ph.hash(PWD), db.ph.hash(PWD)
ev.append("Même mot de passe, deux hachages : " + str(h1 != h2) + " (sel aléatoire)")
ev.append("Vérification Argon2 du bon mot de passe : " + str(db.ph.verify(h1, PWD)))
ap = attempt("admin01", "SELECT password_hash FROM bank.app_user")
ev.append("admin01 : SELECT password_hash FROM app_user -> " + ap[1])
add(8, "Stockage des mots de passe", "Inspection de app_user, tentative d'INSERT en clair, droits de l'admin",
    "Passwords never stored in plaintext", f"{bad} hachage non Argon2id ; INSERT clair refusé (CHECK) ; colonne masquée à l'admin",
    bad == 0 and "ck" in ins_p.lower() or "check" in ins_p.lower() and ap[0] == "ERR", ev)

# ---------------------------------------------------------------- T9 : règles de détection
ev = []
with sess("client_imane") as cur:
    cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s)", (1005, acct(1001), 60000, "Achat véhicule"))
    big = cur.fetchone()
ev.append(f"Imane -> Amine 60 000 MAD : {big['result_status']}")
rr = []
for i in range(2):
    with sess("client_imane") as cur:
        cur.execute("SELECT * FROM bank.transfer_money(%s,%s,%s,%s)", (1005, acct(1001), 100, f"Test {i+1}"))
        rr.append(cur.fetchone()["result_status"])
ev.append("Imane -> Amine 2 virements de 100 MAD : " + str(rr))
for st in ("FROZEN", "ACTIVE", "FROZEN"):
    with sess("manager01") as cur:
        cur.execute("UPDATE bank.account SET status = %s WHERE account_id = 1002", (st,))
with sess("manager01") as cur:
    cur.execute("UPDATE bank.account SET status = 'ACTIVE' WHERE account_id = 1002")
alerts = su("SELECT rule_code, severity, account_id, description FROM bank.security_alert "
            "WHERE rule_code <> 'BRUTE_FORCE' ORDER BY alert_id")
for a in alerts: ev.append("ALERTE " + str(a))
codes_ = sorted(a[0] for a in alerts)
add(9, "Règles de détection (virements, modifications)", "60 000 MAD, 3 virements rapides, 3 changements de statut",
    "Security alerts", ", ".join(codes_), codes_ == ["ACCOUNT_CHANGES", "LARGE_TRANSFER", "RAPID_TRANSFERS"], ev)

# ---------------------------------------------------------------- T10 : intégrité du journal
ev = []
d1 = attempt("admin01", "DELETE FROM bank.audit_log")
ev.append("admin01 : DELETE FROM audit_log -> " + d1[1])
def su_err(q):
    try: su(q); return "accepté"
    except psycopg2.Error as e: return e.pgerror.strip().splitlines()[0]
d2 = su_err("DELETE FROM bank.audit_log WHERE audit_id = 1")
ev.append("postgres : DELETE FROM audit_log -> " + d2)
d3 = su_err("UPDATE bank.bank_transaction SET amount = 1 WHERE transaction_id = 1")
ev.append("postgres : UPDATE bank_transaction -> " + d3)
d4 = su_err("TRUNCATE bank.audit_log")
ev.append("postgres : TRUNCATE audit_log -> " + d4)
add(10, "Suppression/modification des traces", "DELETE/UPDATE/TRUNCATE sur audit_log et bank_transaction",
    "Rejected", "permission denied (admin) ; trigger BK003 (DBA)",
    d1[0] == "ERR" and "ajout seul" in d2 and "ajout seul" in d3 and "ajout seul" in d4, ev)

# ---------------------------------------------------------------- T11 : vues masquées & RBAC lecture
ev = []
vm = attempt("employee01", "SELECT customer_id, first_name, email_masked, phone_masked, national_id_masked "
                           "FROM bank.v_customer_masked ORDER BY 1 LIMIT 3")
for r in vm[1]: ev.append("employee01 v_customer_masked : " + str(dict(r)))
va = attempt("employee01", "SELECT account_id, account_number_masked, balance FROM bank.v_account_masked ORDER BY 1 LIMIT 2")
for r in va[1]: ev.append("employee01 v_account_masked  : " + str(dict(r)))
ca = attempt("client_amine", "SELECT * FROM bank.v_customer_masked")
ev.append("client_amine  v_customer_masked : " + ca[1])
al_ = attempt("auditor01", "SELECT count(*) AS n FROM bank.audit_log")
ev.append("auditor01 : SELECT count(*) FROM audit_log -> " + str(al_[1][0]["n"]))
am = attempt("auditor01", "UPDATE bank.security_alert SET status='CLOSED'")
ev.append("auditor01 : UPDATE security_alert -> " + am[1])
ml = attempt("manager01", "SELECT audit_id, action, table_name, result FROM bank.v_audit_log_limited ORDER BY 1 DESC LIMIT 2")
ev.append("manager01 v_audit_log_limited (sans old/new/IP) : " + str([dict(r) for r in ml[1]]))
add(11, "Vues masquées et rôles de lecture", "employee01, client, auditor01, manager01 sur les vues",
    "Masked / Denied", "données masquées pour l'employé ; client refusé ; auditeur lecture seule",
    vm[0] == "OK" and ca[0] == "ERR" and am[0] == "ERR" and al_[0] == "OK" and ml[0] == "OK", ev)

# ---------------------------------------------------------------- T12 : concurrence (Isolation)
ev = []
res = []
bar = threading.Barrier(2)
def worker(i):
    c = db.connect()
    bar.wait()
    res.append(db.make_transfer(c, U["client_reda"], 1006, acct(1005), 400, f"Concurrent {i}", "41.248.7.9"))
ths = [threading.Thread(target=worker, args=(i,)) for i in (1, 2)]
[t.start() for t in ths]; [t.join() for t in ths]
stt = sorted(r["result_status"] for r in res)
ev.append("Deux virements simultanés de 400 MAD depuis un compte de 500 MAD : " + str(stt))
ev.append("Messages : " + str([r["result_message"] for r in res]))
ev.append(f"Solde final du compte 1006 : {bal(1006)} MAD")
add(12, "Virements simultanés (Isolation)", "2 threads, 2 × 400 MAD sur un solde de 500 MAD",
    "1 COMPLETED + 1 REJECTED", " + ".join(stt) + f" ; solde final {bal(1006)}",
    stt == ["COMPLETED", "REJECTED"] and bal(1006) == Decimal("100.00"), ev)

# ---------------------------------------------------------------- T13 : réconciliation et TLS
ev = []
rec = su("SELECT account_id, balance_account, balance_ledger, gap FROM bank.v_balance_reconciliation ORDER BY 1")
for r in rec: ev.append(str(r))
ssl_ = su("SELECT 1")  # placeholder
with conn.cursor() as c:
    c.execute("SELECT ssl, version, cipher, bits FROM pg_stat_ssl WHERE pid = pg_backend_pid()")
    tls = c.fetchone()
ev.append("TLS (connexion app_backend) : " + str(dict(tls)))
add(13, "Intégrité comptable et TLS", "Réconciliation solde/journal ; pg_stat_ssl",
    "Gap = 0 ; TLS actif", f"écarts : {[str(r[3]) for r in rec]} ; TLS {tls['version']}",
    all(r[3] == 0 for r in rec) and tls["ssl"], ev)


# ---------------------------------------------------------------- T14 : session, rôle, logout, CSRF (Flask)
ev = []
c2 = app.test_client()
def login2(u, p, tok="tok2"):
    c2.get("/login")
    with c2.session_transaction() as s: s["csrf"] = tok
    return c2.post("/login", data={"username": u, "password": p, "csrf": tok})
r_login = login2("client_sara", PWD)
ev.append(f"POST /login (client_sara) -> HTTP {r_login.status_code}, cookie : " + r_login.headers.get("Set-Cookie", "")[:110])
page = c2.get("/")
mine_ok = b"MA6400010000000000001003" in page.data and b"MA6400010000000000001001" not in page.data
ev.append(f"GET / -> HTTP {page.status_code} ; compte de Sara visible : {b'MA6400010000000000001003' in page.data} ; compte d'Amine visible : {b'MA6400010000000000001001' in page.data}")
adm_try = c2.get("/admin"); sec_try = c2.get("/security")
ev.append(f"GET /admin -> HTTP {adm_try.status_code} ; GET /security -> HTTP {sec_try.status_code} (RBAC applicatif)")
nocsrf = c2.post("/transfer", data={"sender": "1003", "receiver": "x", "amount": "1"})
ev.append(f"POST /transfer sans jeton CSRF -> HTTP {nocsrf.status_code}")
with c2.session_transaction() as s: tok = s["csrf"]
out = c2.post("/logout", data={"csrf": tok})
after = c2.get("/")
ev.append(f"POST /logout -> HTTP {out.status_code} ; GET / ensuite -> HTTP {after.status_code} vers {after.headers.get('Location')}")
ck = r_login.headers.get("Set-Cookie", "")
add(14, "Session, rôle et déconnexion", "Connexion de client_sara, accès /admin, CSRF, logout",
    "Session isolée, 403, 400, redirection login",
    f"HTTP {adm_try.status_code}/{sec_try.status_code} sur pages réservées ; CSRF {nocsrf.status_code} ; après logout {after.status_code}",
    r_login.status_code == 302 and mine_ok and adm_try.status_code == 403 and sec_try.status_code == 403
    and nocsrf.status_code == 400 and after.status_code == 302 and "HttpOnly" in ck and "SameSite=Strict" in ck, ev)

# ---------------------------------------------------------------- T15 : audit (lecture sensible, suppression, administration)
ev = []
with sess("client_amine") as cur:
    cur.execute("DELETE FROM bank.beneficiary WHERE customer_id = 1 AND name = 'Hamza Lahlou'")
with sess("admin01") as cur:
    cur.execute("UPDATE bank.app_user SET is_active = FALSE WHERE username = 'employee02'")
with sess("admin01") as cur:
    cur.execute("UPDATE bank.app_user SET is_active = TRUE WHERE username = 'employee02'")
with sess("manager01") as cur:
    cur.execute("SELECT bank.reveal_national_id(%s, %s)", (1, "Vérification KYC dossier 1042"))
    shown = cur.fetchone()["reveal_national_id"]
emp = attempt("employee01", "SELECT bank.reveal_national_id(1, 'Curiosité personnelle test')")
short = attempt("manager01", "SELECT bank.reveal_national_id(1, 'ok')")
ev.append("manager01 reveal_national_id(1, motif valide) -> " + shown)
ev.append("employee01 reveal_national_id(...) -> " + emp[1])
ev.append("manager01 reveal_national_id(1, 'ok') -> " + short[1])
rows = su("SELECT a.audit_id, u.username, a.action, a.table_name, a.record_id, host(a.ip_address), "
          "a.old_value, a.new_value FROM bank.audit_log a LEFT JOIN bank.app_user u USING(user_id) "
          "WHERE (a.action = 'READ_SENSITIVE') OR (a.action='DELETE' AND a.table_name='beneficiary') "
          "OR (a.table_name='app_user' AND a.action='UPDATE') ORDER BY a.audit_id")
for r in rows: ev.append("AUDIT " + str(r))
acts = [r[2] + ":" + r[3] for r in rows]
add(15, "Traçabilité : lecture sensible, suppression, administration",
    "Suppression d'un bénéficiaire, désactivation/réactivation d'un utilisateur, lecture du numéro d'identité",
    "Audit Log generated", f"{len(rows)} entrées : " + ", ".join(acts),
    shown == "FAKE00123456" and emp[0] == "ERR" and short[0] == "ERR"
    and acts.count("READ_SENSITIVE:customer") == 1 and acts.count("DELETE:beneficiary") == 1
    and acts.count("UPDATE:app_user") == 2, ev)
lab.close()

json.dump(dict(results=R, evidence=EV), open("/home/claude/bank/build/results.json", "w"),
          ensure_ascii=False, indent=1, default=str)
print("\nRÉSUMÉ :", sum(r["status"] == "PASS" for r in R), "/", len(R), "PASS")
