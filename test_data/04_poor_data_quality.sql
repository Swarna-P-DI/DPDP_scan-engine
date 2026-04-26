-- Dataset 4: Poor Data Quality
-- Expected: null-heavy columns, duplicates, and invalid formats flagged as DQ issues.

DROP SCHEMA IF EXISTS dpdp_poor_quality CASCADE;
CREATE SCHEMA dpdp_poor_quality;

CREATE TABLE dpdp_poor_quality.customer_imports (
    import_id INTEGER,
    full_name VARCHAR(120),
    email VARCHAR(160),
    phone_number VARCHAR(20),
    birth_date VARCHAR(30),
    city VARCHAR(80),
    loaded_at DATE
);

CREATE TABLE dpdp_poor_quality.payment_imports (
    payment_ref VARCHAR(40),
    customer_email VARCHAR(160),
    amount NUMERIC(10, 2),
    payment_date VARCHAR(30),
    status VARCHAR(30)
);

INSERT INTO dpdp_poor_quality.customer_imports VALUES
(1, 'Anika Bose', 'anika.bose@mail.com', '9876543210', '1990-02-01', 'Kolkata', '2026-03-01'),
(1, 'Anika Bose', 'anika.bose@mail.com', '9876543210', '1990-02-01', 'Kolkata', '2026-03-01'),
(2, NULL, 'bad-email-format', NULL, '32-13-2020', NULL, '2026-03-01'),
(3, 'Dev Patel', NULL, '123', 'not-a-date', NULL, '2026-03-02'),
(4, NULL, NULL, NULL, NULL, NULL, '2026-03-02'),
(5, 'Leena Roy', 'leena.roy@mail.com', '9000011111', '1988-11-09', NULL, '2026-03-03');

INSERT INTO dpdp_poor_quality.payment_imports VALUES
('PAY-001', 'anika.bose@mail.com', 1200.00, '2026-03-04', 'SUCCESS'),
('PAY-001', 'anika.bose@mail.com', 1200.00, '2026-03-04', 'SUCCESS'),
('PAY-002', 'missing-at-mail.com', NULL, '31-02-2026', 'SUCCESS'),
('PAY-003', NULL, -99.00, 'not-a-date', NULL),
('PAY-004', 'leena.roy@mail.com', 450.00, '2026-03-06', 'SUCCESS');
