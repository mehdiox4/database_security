-- [[roles]]
-- Rôles de groupe (non connectables) : ils portent les permissions
CREATE ROLE role_client   NOLOGIN;
CREATE ROLE role_employee NOLOGIN;
CREATE ROLE role_manager  NOLOGIN;
CREATE ROLE role_admin    NOLOGIN;
CREATE ROLE role_auditor  NOLOGIN;

-- Hiérarchie : le manager hérite de l'employé ; l'admin hérite du manager
GRANT role_employee TO role_manager;
GRANT role_manager  TO role_admin;

-- Compte technique du backend Flask : seul à pouvoir se connecter.
-- NOINHERIT : sans SET ROLE explicite, il n'a presque aucun droit.
CREATE ROLE app_backend LOGIN NOINHERIT CONNECTION LIMIT 20
       PASSWORD 'Backend#Demo2026';
GRANT role_client, role_employee, role_manager, role_admin, role_auditor TO app_backend;

-- Compte de sauvegarde : lecture seule de toutes les données.
-- pg_read_all_data ne contourne PAS la RLS : BYPASSRLS est indispensable pour pg_dump.
CREATE ROLE backup_svc LOGIN BYPASSRLS PASSWORD 'Backup#Demo2026';
GRANT pg_read_all_data TO backup_svc;

GRANT CONNECT ON DATABASE bank_db TO app_backend, backup_svc;

-- Par défaut, toute fonction créée par bank_owner n'est PAS exécutable par PUBLIC
ALTER DEFAULT PRIVILEGES FOR ROLE bank_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
-- [[/roles]]
