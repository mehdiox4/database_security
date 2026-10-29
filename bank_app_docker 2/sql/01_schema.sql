-- [[tables]]
SET ROLE bank_owner;
SET search_path = bank, public;

---------------------------------------------------------------- ROLE / BRANCH
CREATE TABLE bank.role (
    role_id     SMALLINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name   VARCHAR(30) NOT NULL UNIQUE CHECK (role_name ~ '^ROLE_[A-Z]+$')
);

CREATE TABLE bank.branch (
    branch_id   INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    branch_name VARCHAR(80)  NOT NULL UNIQUE,
    city        VARCHAR(60)  NOT NULL,
    address     VARCHAR(150) NOT NULL
);

---------------------------------------------------------------- EMPLOYEE
CREATE TABLE bank.employee (
    employee_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name  VARCHAR(60)  NOT NULL,
    last_name   VARCHAR(60)  NOT NULL,
    email       VARCHAR(120) NOT NULL UNIQUE
                CHECK (email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
    role_id     SMALLINT NOT NULL REFERENCES bank.role(role_id),
    branch_id   INTEGER  NOT NULL REFERENCES bank.branch(branch_id),
    status      VARCHAR(10) NOT NULL DEFAULT 'ACTIVE'
                CHECK (status IN ('ACTIVE','SUSPENDED','LEFT'))
);

---------------------------------------------------------------- CUSTOMER
CREATE TABLE bank.customer (
    customer_id       INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    first_name        VARCHAR(60)  NOT NULL,
    last_name         VARCHAR(60)  NOT NULL,
    date_of_birth     DATE NOT NULL CHECK (date_of_birth > DATE '1900-01-01'),
    email             VARCHAR(120) NOT NULL UNIQUE
                      CHECK (email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$'),
    phone             VARCHAR(20)  NOT NULL CHECK (phone ~ '^\+[0-9]{8,15}$'),
    address           VARCHAR(200) NOT NULL,
    national_id       BYTEA    NOT NULL,          -- chiffré : pgp_sym_encrypt()
    national_id_last4 CHAR(4)  NOT NULL,          -- sert uniquement au masquage
    national_id_hash  BYTEA    NOT NULL UNIQUE,   -- HMAC-SHA256 : unicité sans clair
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    status            VARCHAR(10) NOT NULL DEFAULT 'ACTIVE'
                      CHECK (status IN ('ACTIVE','BLOCKED','CLOSED'))
);

---------------------------------------------------------------- ACCOUNT
CREATE SEQUENCE bank.account_number_seq START 1001;

CREATE TABLE bank.account (
    account_id     INTEGER GENERATED ALWAYS AS IDENTITY (START WITH 1001) PRIMARY KEY,
    customer_id    INTEGER NOT NULL REFERENCES bank.customer(customer_id)
                   ON DELETE RESTRICT,
    account_number VARCHAR(24) NOT NULL UNIQUE
                   DEFAULT ('MA640001' || lpad(nextval('bank.account_number_seq')::text, 16, '0')),
    account_type   VARCHAR(10) NOT NULL CHECK (account_type IN ('CHECKING','SAVINGS')),
    balance        NUMERIC(15,2) NOT NULL DEFAULT 0 CHECK (balance >= 0),
    currency       CHAR(3) NOT NULL DEFAULT 'MAD' CHECK (currency IN ('MAD','EUR','USD')),
    status         VARCHAR(10) NOT NULL DEFAULT 'ACTIVE'
                   CHECK (status IN ('ACTIVE','FROZEN','CLOSED')),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_account_number CHECK (account_number ~ '^MA[0-9]{22}$')
);

---------------------------------------------------------------- TRANSFER
CREATE TABLE bank.transfer (
    transfer_id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    sender_account_id   INTEGER NOT NULL REFERENCES bank.account(account_id),
    receiver_account_id INTEGER NOT NULL REFERENCES bank.account(account_id),
    amount              NUMERIC(15,2) NOT NULL CHECK (amount > 0),
    transfer_date       TIMESTAMPTZ NOT NULL DEFAULT now(),
    status              VARCHAR(10) NOT NULL DEFAULT 'PENDING'
                        CHECK (status IN ('PENDING','COMPLETED','REVERSED')),
    CONSTRAINT ck_transfer_distinct CHECK (sender_account_id <> receiver_account_id)
);

---------------------------------------------------------------- TRANSACTION
-- "transaction" est un mot-clé SQL : la table est nommée bank_transaction.
CREATE TABLE bank.bank_transaction (
    transaction_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    account_id       INTEGER NOT NULL REFERENCES bank.account(account_id),
    transfer_id      INTEGER REFERENCES bank.transfer(transfer_id),
    transaction_type VARCHAR(15) NOT NULL
        CHECK (transaction_type IN ('DEPOSIT','WITHDRAWAL','TRANSFER_OUT','TRANSFER_IN','FEE')),
    amount           NUMERIC(15,2) NOT NULL CHECK (amount > 0),
    balance_after    NUMERIC(15,2) NOT NULL CHECK (balance_after >= 0),
    transaction_date TIMESTAMPTZ NOT NULL DEFAULT now(),
    description      VARCHAR(200),
    status           VARCHAR(10) NOT NULL DEFAULT 'COMPLETED'
                     CHECK (status IN ('PENDING','COMPLETED','FAILED'))
);

---------------------------------------------------------------- BENEFICIARY / LOAN
CREATE TABLE bank.beneficiary (
    beneficiary_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id    INTEGER NOT NULL REFERENCES bank.customer(customer_id) ON DELETE CASCADE,
    name           VARCHAR(100) NOT NULL,
    bank_name      VARCHAR(80)  NOT NULL,
    account_number VARCHAR(34)  NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    status         VARCHAR(10) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
    CONSTRAINT uq_beneficiary UNIQUE (customer_id, account_number)
);

CREATE TABLE bank.loan (
    loan_id       INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    customer_id   INTEGER NOT NULL REFERENCES bank.customer(customer_id),
    amount        NUMERIC(15,2) NOT NULL CHECK (amount > 0),
    interest_rate NUMERIC(5,2)  NOT NULL CHECK (interest_rate BETWEEN 0 AND 30),
    start_date    DATE NOT NULL,
    end_date      DATE NOT NULL,
    status        VARCHAR(10) NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING','ACTIVE','REPAID','REJECTED')),
    CONSTRAINT ck_loan_dates CHECK (end_date > start_date)
);
-- [[/tables]]

-- [[tables_security]]
---------------------------------------------------------------- APP_USER (authentification)
CREATE TABLE bank.app_user (
    user_id         INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username        VARCHAR(40) NOT NULL UNIQUE CHECK (username ~ '^[a-z][a-z0-9_]{2,39}$'),
    password_hash   TEXT NOT NULL CHECK (password_hash LIKE '$argon2id$%'),  -- jamais de clair
    role_id         SMALLINT NOT NULL REFERENCES bank.role(role_id),
    customer_id     INTEGER UNIQUE REFERENCES bank.customer(customer_id),
    employee_id     INTEGER UNIQUE REFERENCES bank.employee(employee_id),
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    failed_attempts SMALLINT NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_user_owner
        CHECK ((customer_id IS NOT NULL)::int + (employee_id IS NOT NULL)::int = 1)
);

CREATE TABLE bank.login_attempt (
    attempt_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username     VARCHAR(60) NOT NULL,
    success      BOOLEAN NOT NULL,
    ip_address   INET,
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE bank.audit_log (
    audit_id   BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    INTEGER REFERENCES bank.app_user(user_id),
    db_user    TEXT NOT NULL DEFAULT session_user,
    action     VARCHAR(30) NOT NULL,
    table_name VARCHAR(40) NOT NULL,
    record_id  BIGINT,
    timestamp  TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip_address INET,
    old_value  JSONB,
    new_value  JSONB,
    result     VARCHAR(10) NOT NULL DEFAULT 'SUCCESS'
               CHECK (result IN ('SUCCESS','REJECTED','FAILED','ALERT'))
);

CREATE TABLE bank.security_rule (
    rule_code      VARCHAR(30) PRIMARY KEY,
    description    VARCHAR(200) NOT NULL,
    threshold      NUMERIC(15,2) NOT NULL CHECK (threshold > 0),
    window_minutes INTEGER NOT NULL DEFAULT 0,
    enabled        BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE bank.security_alert (
    alert_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_code   VARCHAR(30) NOT NULL REFERENCES bank.security_rule(rule_code),
    severity    VARCHAR(10) NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
    account_id  INTEGER,
    username    VARCHAR(60),
    description VARCHAR(300) NOT NULL,
    status      VARCHAR(15) NOT NULL DEFAULT 'OPEN'
                CHECK (status IN ('OPEN','ACKNOWLEDGED','CLOSED')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Index de performance (et de détection rapide)
CREATE INDEX ix_txn_account_date ON bank.bank_transaction (account_id, transaction_date DESC);
CREATE INDEX ix_transfer_sender  ON bank.transfer (sender_account_id, transfer_date DESC);
CREATE INDEX ix_account_customer ON bank.account (customer_id);
CREATE INDEX ix_audit_record     ON bank.audit_log (table_name, record_id);
CREATE INDEX ix_audit_time       ON bank.audit_log (timestamp DESC);
CREATE INDEX ix_login_user_time  ON bank.login_attempt (username, attempted_at DESC);

RESET ROLE;
-- [[/tables_security]]
