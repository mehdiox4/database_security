Banking and Account Management System — application à exécuter

Démarrage rapide (Ubuntu 24.04, avec sudo)

unzip bank_app.zip && cd bank_app
sudo bash INSTALL.sh      # installe PostgreSQL, crée la base, les rôles, les données
bash RUN.sh                # démarre l'application sur http://127.0.0.1:5000
Comptes de démonstration (mot de passe commun : Bank@Demo2026!) :

Compte	Rôle
client_amine, client_sara, client_hamza, client_imane, client_reda	ROLE_CLIENT
employee01, employee02	ROLE_EMPLOYEE
manager01	ROLE_MANAGER
admin01	ROLE_ADMIN
auditor01	ROLE_AUDITOR
Rejouer les tests de sécurité automatisés (preuves du rapport)

sudo -u postgres app/venv/bin/python3 -c "import sys; sys.path.insert(0,'app')" 2>/dev/null
sudo -u postgres env DB_PASSWORD='Backend#Demo2026' ENC_KEY='DEMO-ONLY-KEY-2026-CHANGE-ME' \
     app/venv/bin/python3 tests/run_tests.py
Les autres scripts (tests/incident.py, tests/investigate.sh, tests/recovery.sh, tests/privs.sh, tests/hardening_audit.py) peuvent être rejoués de la même manière ; voir le chapitre G du rapport pour le détail de chacun.

Arborescence

sql/      scripts de base de données, dans l'ordre d'exécution (00 à 06) + hardening.sh
app/      application Flask (app.py, db.py, templates/) + seed_users.py
tests/    scripts de tests de sécurité, d'incident, de sauvegarde (preuves du rapport)
INSTALL.sh   installation complète (une seule fois)
RUN.sh       démarrage de l'application
Important

Toutes les données sont fictives. Les mots de passe et la clé de chiffrement de démonstration (ENC_KEY) ne doivent jamais être réutilisés tels quels hors du laboratoire.
Tester uniquement contre cette instance locale : voir PENTEST_GUIDE.md.
