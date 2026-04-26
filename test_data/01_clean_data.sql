-- Dataset 1: Clean Data
-- Expected: valid emails, no null-heavy columns, low risk.

DROP SCHEMA IF EXISTS dpdp_clean CASCADE;
CREATE SCHEMA dpdp_clean;

CREATE TABLE dpdp_clean.customers (
    customer_id INTEGER PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL UNIQUE,
    city VARCHAR(80) NOT NULL,
    consent_status VARCHAR(20) NOT NULL,
    created_at DATE NOT NULL
);

CREATE TABLE dpdp_clean.orders (
    order_id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES dpdp_clean.customers(customer_id),
    order_total NUMERIC(10, 2) NOT NULL,
    order_status VARCHAR(30) NOT NULL,
    order_date DATE NOT NULL
);

INSERT INTO dpdp_clean.customers VALUES
(1, 'Asha Sharma', 'asha.sharma@example.com', 'Mumbai', 'ACTIVE', '2026-01-10'),
(2, 'Rahul Mehta', 'rahul.mehta@example.com', 'Pune', 'ACTIVE', '2026-01-12'),
(3, 'Neha Iyer', 'neha.iyer@example.com', 'Chennai', 'ACTIVE', '2026-01-15'),
(4, 'Vikram Rao', 'vikram.rao@example.com', 'Bengaluru', 'ACTIVE', '2026-01-20');

INSERT INTO dpdp_clean.orders VALUES
(1001, 1, 1299.00, 'PAID', '2026-02-01'),
(1002, 2, 2499.50, 'PAID', '2026-02-03'),
(1003, 3, 799.00, 'SHIPPED', '2026-02-06'),
(1004, 4, 1540.75, 'PAID', '2026-02-08');
