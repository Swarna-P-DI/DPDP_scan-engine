-- Synthetic Scan + RAID test data.
-- All values are fake, deterministic, and safe for local validation only.

DROP SCHEMA IF EXISTS synthetic_raid CASCADE;
CREATE SCHEMA synthetic_raid;

CREATE TABLE synthetic_raid.users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    aadhaar TEXT,
    pan TEXT,
    created_at TIMESTAMP NOT NULL
);

CREATE TABLE synthetic_raid.bank_accounts (
    account_id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES synthetic_raid.users(id),
    ifsc_code TEXT NOT NULL,
    account_number TEXT NOT NULL,
    balance NUMERIC(12, 2) NOT NULL
);

CREATE TABLE synthetic_raid.employees (
    emp_id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    aadhaar TEXT NOT NULL,
    salary NUMERIC(12, 2) NOT NULL
);

INSERT INTO synthetic_raid.users
    (id, name, email, phone, aadhaar, pan, created_at)
VALUES
    (1, 'Ravi Kumar', 'ravi.kumar.synthetic@example.test', '9876543210', '234567890123', 'ABCDE1234F', '2026-01-15 09:00:00'),
    (2, 'Meera Shah', 'meera.shah.synthetic@example.test', '9123456780', 'XXXX-XXXX-0123', 'PQRSX9876L', '2026-01-16 10:30:00'),
    (3, 'Ravi Kumar', 'ravi.alt.synthetic@example.test', '9988776655', '345678901234', 'LMNOP4321Q', '2026-01-17 11:45:00'),
    (4, 'Anika Rao', 'anika.rao.synthetic@example.test', '9000011111', '123456789123', 'BADPAN1234', '2026-01-18 14:15:00'),
    (5, 'Encrypted User', 'encrypted.user.synthetic@example.test', '9777712345', 'QWxhZGRpbjpPcGVuU2VzYW1lMTIzNDU2', 'ZZZZZ9999Z', '2026-01-19 08:20:00');

INSERT INTO synthetic_raid.bank_accounts
    (account_id, user_id, ifsc_code, account_number, balance)
VALUES
    (1001, 1, 'HDFC0001234', '1234567890123456', 12500.50),
    (1002, 2, 'ICIC0005678', 'XXXX-XXXX-XXXX-7788', 54000.00),
    (1003, 3, 'SBIN0001111', '9876543210987654', 875.25),
    (1004, 4, 'BADFSC00123', '####-####-####-0000', 0.00),
    (1005, 5, 'HDFC0001234', 'QUNDTlRfVE9LRU5fU1lOVEhFVElDXzAwMQ==', 99999.99);

INSERT INTO synthetic_raid.employees
    (emp_id, name, aadhaar, salary)
VALUES
    (501, 'Ravi Kumar', '234567890123', 1200000.00),
    (502, 'Priya Menon', '456789012345', 980000.00),
    (503, 'Masked Employee', 'XXXX-XXXX-2345', 750000.00),
    (504, 'Encrypted Employee', 'U1lOVEhFVElDX0FBREhBQVJfVE9LRU5fMDAx', 880000.00);

