# db.py - couche d'accès PostgreSQL du backend (requêtes TOUJOURS paramétrées)
import os, re
from contextlib import contextmanager
from decimal import Decimal
import psycopg2
from psycopg2 import sql
from psycopg2.extras import RealDictCursor
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

DSN = dict(host=os.environ.get("DB_HOST", "localhost"), dbname="bank_db",
           user="app_backend", password=os.environ["DB_PASSWORD"],
           sslmode=os.environ.get("DB_SSLMODE", "require"))
ENC_KEY = os.environ["ENC_KEY"]                 # clé de chiffrement des données (KMS)
ph = PasswordHasher()                           # Argon2id (t=3, m=64 MiB, p=4)
DUMMY_HASH = ph.hash("dummy-password")          # égalise le temps de réponse (anti-énumération)
USERNAME_RE = re.compile(r"[a-z][a-z0-9_]{2,39}")
DB_ROLES = {"ROLE_CLIENT": "role_client", "ROLE_EMPLOYEE": "role_employee",
            "ROLE_MANAGER": "role_manager", "ROLE_ADMIN": "role_admin",
            "ROLE_AUDITOR": "role_auditor"}

def connect():
    return psycopg2.connect(cursor_factory=RealDictCursor, **DSN)

@contextmanager
def db_session(conn, user, ip="127.0.0.1"):
    """Transaction exécutée avec les droits du rôle PostgreSQL de l'utilisateur connecté.
    COMMIT à la sortie normale, ROLLBACK si une exception se produit."""
    with conn:                                   # BEGIN ... COMMIT / ROLLBACK
        with conn.cursor() as cur:
            cur.execute(sql.SQL("SET LOCAL ROLE {}").format(
                sql.Identifier(DB_ROLES[user["role_name"]])))
            cur.execute("""SELECT set_config('app.user_id',     %s, true),
                                  set_config('app.role',        %s, true),
                                  set_config('app.customer_id', %s, true),
                                  set_config('app.ip',          %s, true),
                                  set_config('app.enc_key',     %s, true),
                                  set_config('application_name', %s, true)""",
                        (str(user["user_id"]), user["role_name"],
                         str(user["customer_id"] or ""), ip, ENC_KEY, user["username"]))
            yield cur

def authenticate(conn, username, password, ip):
    """Retourne (statut, utilisateur). Message public unique : pas d'énumération."""
    username = (username or "")[:60]
    user = None
    if USERNAME_RE.fullmatch(username):          # liste blanche AVANT toute requête
        with conn, conn.cursor() as cur:
            cur.execute("""SELECT u.user_id, u.username, u.password_hash, u.is_active,
                                  u.customer_id, r.role_name,
                                  COALESCE(u.locked_until > now(), false) AS locked
                             FROM bank.app_user u JOIN bank.role r USING (role_id)
                            WHERE u.username = %s""", (username,))
            user = cur.fetchone()
            if user:
                # customer/employee sont protégées par Row-Level Security ; ce nom
                # d'affichage passe donc par une fonction dédiée (SECURITY DEFINER,
                # deux colonnes non sensibles) plutôt que par un accès direct.
                cur.execute("SELECT * FROM bank.get_display_name(%s)", (username,))
                name = cur.fetchone() or {}
                user["first_name"] = name.get("first_name")
                user["last_name"] = name.get("last_name")
    ok = False
    if user and user["is_active"] and not user["locked"]:
        try:
            ok = ph.verify(user["password_hash"], password)
        except (VerifyMismatchError, InvalidHashError):
            ok = False
    else:
        try: ph.verify(DUMMY_HASH, password or "")
        except VerifyMismatchError: pass
    with conn, conn.cursor() as cur:             # traçabilité de chaque tentative
        cur.execute("SELECT bank.record_login_attempt(%s, %s, %s)", (username, ok, ip))
    if ok:
        return "OK", user
    if user and user["locked"]:
        return "LOCKED", None
    return "INVALID", None

def make_transfer(conn, user, sender_id, receiver_number, amount, description, ip):
    with db_session(conn, user, ip) as cur:
        cur.execute("SELECT * FROM bank.transfer_money(%s, %s, %s, %s)",
                    (sender_id, receiver_number, Decimal(str(amount)), description))
        return cur.fetchone()
