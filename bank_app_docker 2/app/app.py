# app.py - backend Flask (authentification, RBAC applicatif, protection CSRF, anti-rejeu)
import os, secrets
from datetime import timedelta
from functools import wraps
from flask import (Flask, abort, flash, redirect, render_template, request, session, url_for)
import db

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET"],
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10))

ROLE_LABELS = {"ROLE_CLIENT": "Client", "ROLE_EMPLOYEE": "Employé", "ROLE_MANAGER": "Manager",
               "ROLE_ADMIN": "Administrateur", "ROLE_AUDITOR": "Auditeur sécurité"}

@app.after_request
def security_headers(resp):
    # Plus de dépendance externe (ancien CDN Bootstrap) : tout est servi en local
    # (app/static/style.css, app/static/uir_logo.png), donc 'self' suffit.
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    # no-store : les données bancaires ne doivent jamais être mises en cache par le
    # navigateur. Cela peut faire réafficher une page "périmée" en cas de clic sur
    # Précédent ; le jeton anti-rejeu (op_token) garantit que cela ne rejoue jamais
    # réellement une opération déjà traitée (voir /transfer).
    resp.headers["Cache-Control"] = "no-store"
    return resp

def csrf_token():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    return session["csrf"]
app.jinja_env.globals["csrf_token"] = csrf_token

@app.before_request
def check_csrf():
    if request.method == "POST" and not secrets.compare_digest(
            request.form.get("csrf", ""), session.get("csrf", "")):
        abort(400, "CSRF token invalide")

@app.context_processor
def inject_nav():
    """Rend le nom affiché, le libellé de rôle et les initiales disponibles dans
    tous les gabarits (barre de navigation commune, bouton de déconnexion)."""
    u = session.get("user")
    if not u:
        return {}
    name = (u.get("first_name") or "") + " " + (u.get("last_name") or "")
    name = name.strip() or u["username"]
    initials = "".join(p[0] for p in name.split()[:2]).upper() or u["username"][:2].upper()
    return {"nav_user": u, "nav_name": name, "nav_initials": initials,
            "nav_role_label": ROLE_LABELS.get(u["role_name"], u["role_name"])}

def login_required(*roles):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if "user" not in session:
                return redirect(url_for("login"))
            if roles and session["user"]["role_name"] not in roles:
                abort(403)                         # RBAC applicatif (en plus de RBAC SQL)
            return f(*a, **kw)
        return wrapper
    return deco

def new_op_token():
    """Jeton à usage unique pour une opération sensible (ex. virement). Généré à
    chaque affichage du formulaire et consommé à la soumission : si la même page
    est renvoyée une seconde fois (bouton Précédent du navigateur, double clic,
    rechargement d'un formulaire), le jeton a déjà été consommé et l'opération
    n'est PAS rejouée — l'utilisateur voit un message clair au lieu d'un virement
    dupliqué ou d'une impression d'annulation."""
    tok = secrets.token_urlsafe(24)
    pending = session.get("op_tokens", [])
    pending = (pending + [tok])[-20:]              # on garde au plus 20 jetons en attente
    session["op_tokens"] = pending
    return tok

def consume_op_token(tok):
    pending = session.get("op_tokens", [])
    if not tok or tok not in pending:
        return False
    session["op_tokens"] = [t for t in pending if t != tok]
    return True

@app.errorhandler(Exception)
def generic_error(e):                       # aucune trace SQL ni pile d'appel côté client
    code = getattr(e, "code", 500)
    if code == 500:
        app.logger.exception("erreur interne")
    return render_template("error.html", code=code), code

def client_ip():
    return request.remote_addr or "0.0.0.0"

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        status, user = db.authenticate(db.connect(), request.form.get("username", ""),
                                       request.form.get("password", ""), client_ip())
        if status == "OK":
            session.clear(); session.permanent = True
            session["user"] = {k: user[k] for k in
                ("user_id", "username", "role_name", "customer_id", "first_name", "last_name")}
            return redirect(url_for("dashboard"))
        flash("Compte temporairement verrouillé. Réessayez dans quelques minutes." if status == "LOCKED"
              else "Identifiants invalides.", "danger")
        return render_template("login.html"), (423 if status == "LOCKED" else 401)
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("Vous avez été déconnecté en toute sécurité.", "success")
    return redirect(url_for("login"))

@app.route("/")
@login_required()
def dashboard():
    u = session["user"]
    if u["role_name"] != "ROLE_CLIENT":
        return redirect(url_for("admin" if u["role_name"] in ("ROLE_ADMIN", "ROLE_MANAGER")
                                else "security"))
    with db.db_session(db.connect(), u, client_ip()) as cur:     # RLS filtre automatiquement
        cur.execute("SELECT account_id, account_number, account_type, balance, currency "
                    "FROM bank.account ORDER BY account_id"); accounts = cur.fetchall()
        cur.execute("SELECT * FROM bank.bank_transaction ORDER BY transaction_date DESC "
                    "LIMIT 10"); txns = cur.fetchall()
        cur.execute("SELECT * FROM bank.beneficiary WHERE status = 'ACTIVE'"); benefs = cur.fetchall()
        cur.execute("SELECT * FROM bank.loan"); loans = cur.fetchall()
    total = sum(a["balance"] for a in accounts)
    return render_template("dashboard.html", accounts=accounts, txns=txns, benefs=benefs,
                           loans=loans, total=total, op_token=new_op_token())

@app.route("/transfer", methods=["POST"])
@login_required("ROLE_CLIENT", "ROLE_MANAGER", "ROLE_ADMIN")
def transfer():
    if not consume_op_token(request.form.get("op_token", "")):
        # Jeton absent, inconnu ou déjà utilisé : on ne relance PAS transfer_money().
        # Cas typique : page de formulaire resservie par le navigateur (bouton
        # Précédent de Safari) après un premier envoi déjà traité avec succès.
        flash("Cette page de virement n'est plus valide (déjà envoyée ou expirée). "
              "Le dernier virement envoyé reste celui affiché ci-dessous ; "
              "pour en faire un nouveau, utilisez le formulaire actuel.", "warning")
        return redirect(url_for("dashboard"))
    try:
        sender = int(request.form["sender"]); amount = request.form["amount"]
        receiver = request.form["receiver"].strip()
    except (KeyError, ValueError):
        abort(400)
    res = db.make_transfer(db.connect(), session["user"], sender, receiver, amount,
                           request.form.get("description", "Virement")[:200], client_ip())
    flash(f'{res["result_status"]} : {res["result_message"]}',
          "success" if res["result_status"] == "COMPLETED" else "danger")
    return redirect(url_for("dashboard"))

@app.route("/admin")
@login_required("ROLE_ADMIN", "ROLE_MANAGER")
def admin():
    u = session["user"]
    audit_view = "bank.audit_log" if u["role_name"] == "ROLE_ADMIN" else "bank.v_audit_log_limited"
    with db.db_session(db.connect(), u, client_ip()) as cur:
        cur.execute("SELECT count(*) AS n FROM bank.account"); n_accounts = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM bank.app_user WHERE is_active"); n_users = cur.fetchone()["n"]
        cur.execute("SELECT count(*) AS n FROM bank.security_alert WHERE status = 'OPEN'")
        n_alerts = cur.fetchone()["n"]
        cur.execute("SELECT * FROM bank.security_alert ORDER BY created_at DESC LIMIT 5")
        alerts = cur.fetchall()
        cur.execute(f"SELECT * FROM {audit_view} ORDER BY timestamp DESC LIMIT 10")  # nom fixe (liste blanche)
        audit = cur.fetchall()
    return render_template("admin.html", n_accounts=n_accounts, n_users=n_users,
                           n_alerts=n_alerts, alerts=alerts, audit=audit)

@app.route("/security")
@login_required("ROLE_ADMIN", "ROLE_AUDITOR")
def security():
    with db.db_session(db.connect(), session["user"], client_ip()) as cur:
        cur.execute("SELECT * FROM bank.login_attempt ORDER BY attempted_at DESC LIMIT 10")
        attempts = cur.fetchall()
        cur.execute("SELECT * FROM bank.security_alert ORDER BY created_at DESC LIMIT 10")
        alerts = cur.fetchall()
        cur.execute("SELECT count(*) FILTER (WHERE NOT success) AS failed, "
                    "count(*) FILTER (WHERE success) AS ok FROM bank.login_attempt")
        stats = cur.fetchone()
    return render_template("security.html", attempts=attempts, alerts=alerts, stats=stats)
