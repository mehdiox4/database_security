-- [[seed]]
-- Données 100 % fictives. Exécuter en superutilisateur (démo) : psql -d bank_db -f 06_seed.sql
SET search_path = bank, public;
SET app.enc_key = 'DEMO-ONLY-KEY-2026-CHANGE-ME';   -- en production : KMS / HSM, jamais en dur

INSERT INTO bank.role (role_name) VALUES
  ('ROLE_CLIENT'), ('ROLE_EMPLOYEE'), ('ROLE_MANAGER'), ('ROLE_ADMIN'), ('ROLE_AUDITOR');

INSERT INTO bank.branch (branch_name, city, address) VALUES
  ('Agence Rabat Agdal',      'Rabat',      '12 Avenue Fal Ould Oumeir'),
  ('Agence Casablanca Maarif','Casablanca', '45 Boulevard Zerktouni'),
  ('Agence Témara Centre',    'Témara',     '8 Avenue Hassan II');

INSERT INTO bank.employee (first_name, last_name, email, role_id, branch_id) VALUES
  ('Salma',  'Idrissi',  'salma.idrissi@demobank.test',  2, 1),   -- employee01
  ('Karim',  'Alaoui',   'karim.alaoui@demobank.test',   3, 1),   -- manager01
  ('Nadia',  'Tazi',     'nadia.tazi@demobank.test',     4, 2),   -- admin01
  ('Youssef','Bennani',  'youssef.bennani@demobank.test',5, 2),   -- auditor01
  ('Omar',   'Chraibi',  'omar.chraibi@demobank.test',   2, 3);   -- employee02

-- Clients créés via la fonction (chiffrement du numéro d'identité)
SELECT bank.create_customer('Amine',  'El Fassi',   DATE '1998-03-14', 'amine.elfassi@mail.test',
                            '+212600000101', '10 Rue Oqba, Rabat',        'FAKE00123456');
SELECT bank.create_customer('Sara',   'Benjelloun', DATE '2000-07-22', 'sara.benjelloun@mail.test',
                            '+212600000102', '27 Rue Moulay Ali, Casablanca', 'FAKE00234567');
SELECT bank.create_customer('Hamza',  'Lahlou',     DATE '1995-11-02', 'hamza.lahlou@mail.test',
                            '+212600000103', '3 Lotissement Najah, Témara', 'FAKE00345678');
SELECT bank.create_customer('Imane',  'Cherkaoui',  DATE '1989-05-30', 'imane.cherkaoui@mail.test',
                            '+212600000104', '55 Avenue Atlas, Rabat',    'FAKE00456789');
SELECT bank.create_customer('Reda',   'Mansouri',   DATE '2001-01-19', 'reda.mansouri@mail.test',
                            '+212600000105', '14 Rue Ibn Sina, Salé',     'FAKE00567890');

-- Comptes (account_id 1001..1006) et historique cohérent avec les soldes
INSERT INTO bank.account (customer_id, account_type, balance, created_at) VALUES
  (1, 'CHECKING', 12500.00, now() - interval '60 days'),   -- 1001 Amine
  (1, 'SAVINGS',  40000.00, now() - interval '60 days'),   -- 1002 Amine
  (2, 'CHECKING',  8200.00, now() - interval '50 days'),   -- 1003 Sara
  (3, 'CHECKING',  3000.00, now() - interval '45 days'),   -- 1004 Hamza
  (4, 'CHECKING', 95000.00, now() - interval '90 days'),   -- 1005 Imane
  (5, 'CHECKING',   500.00, now() - interval '20 days');   -- 1006 Reda

INSERT INTO bank.bank_transaction
  (account_id, transaction_type, amount, balance_after, transaction_date, description) VALUES
  (1001, 'DEPOSIT',    15000.00, 15000.00, now() - interval '20 days', 'Versement salaire'),
  (1001, 'WITHDRAWAL',  1500.00, 13500.00, now() - interval '15 days', 'Retrait DAB'),
  (1001, 'WITHDRAWAL',  1000.00, 12500.00, now() - interval '8 days',  'Paiement loyer'),
  (1002, 'DEPOSIT',    40000.00, 40000.00, now() - interval '60 days', 'Ouverture épargne'),
  (1003, 'DEPOSIT',     9000.00,  9000.00, now() - interval '30 days', 'Versement salaire'),
  (1003, 'WITHDRAWAL',   800.00,  8200.00, now() - interval '10 days', 'Paiement carte'),
  (1004, 'DEPOSIT',     5000.00,  5000.00, now() - interval '25 days', 'Versement salaire'),
  (1004, 'WITHDRAWAL',  2000.00,  3000.00, now() - interval '12 days', 'Retrait DAB'),
  (1005, 'DEPOSIT',   100000.00,100000.00, now() - interval '80 days', 'Cession de parts'),
  (1005, 'WITHDRAWAL',  5000.00, 95000.00, now() - interval '40 days', 'Frais de scolarité'),
  (1006, 'DEPOSIT',      500.00,   500.00, now() - interval '19 days', 'Dépôt initial');

-- Bénéficiaires : numéros de compte internes (récupérés par sous-requête)
INSERT INTO bank.beneficiary (customer_id, name, bank_name, account_number)
SELECT 1, 'Sara Benjelloun', 'Demo Bank', account_number FROM bank.account WHERE account_id = 1003
UNION ALL SELECT 1, 'Hamza Lahlou', 'Demo Bank', account_number FROM bank.account WHERE account_id = 1004
UNION ALL SELECT 4, 'Amine El Fassi', 'Demo Bank', account_number FROM bank.account WHERE account_id = 1001
UNION ALL SELECT 5, 'Imane Cherkaoui', 'Demo Bank', account_number FROM bank.account WHERE account_id = 1005;

INSERT INTO bank.loan (customer_id, amount, interest_rate, start_date, end_date, status) VALUES
  (1, 120000.00, 5.25, DATE '2025-01-15', DATE '2030-01-15', 'ACTIVE'),
  (3,  50000.00, 4.90, DATE '2025-06-01', DATE '2028-06-01', 'ACTIVE'),
  (4, 200000.00, 4.50, DATE '2026-11-01', DATE '2036-11-01', 'PENDING');

-- Règles de détection (paramétrables par l'administrateur)
INSERT INTO bank.security_rule (rule_code, description, threshold, window_minutes) VALUES
  ('RAPID_TRANSFERS', 'Nombre de virements depuis un même compte dans la fenêtre', 3,  5),
  ('LARGE_TRANSFER',  'Montant unitaire de virement à partir duquel alerter (MAD)', 50000, 0),
  ('BRUTE_FORCE',     'Échecs de connexion consécutifs pour un même utilisateur',   5, 10),
  ('ACCOUNT_CHANGES', 'Modifications (hors solde) d''un même compte dans la fenêtre', 3, 10);
-- [[/seed]]
