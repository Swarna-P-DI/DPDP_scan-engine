-- Dataset 5: No Relationships
-- Expected: unrelated tables scanned, relationship inference should assume no relationships.

DROP SCHEMA IF EXISTS dpdp_no_relationships CASCADE;
CREATE SCHEMA dpdp_no_relationships;

CREATE TABLE dpdp_no_relationships.branch_targets (
    branch_code VARCHAR(20) PRIMARY KEY,
    region VARCHAR(80) NOT NULL,
    quarterly_target NUMERIC(12, 2) NOT NULL
);

CREATE TABLE dpdp_no_relationships.product_catalog (
    sku VARCHAR(40) PRIMARY KEY,
    product_name VARCHAR(120) NOT NULL,
    category VARCHAR(80) NOT NULL,
    active_flag BOOLEAN NOT NULL
);

CREATE TABLE dpdp_no_relationships.weather_observations (
    station_code VARCHAR(40) PRIMARY KEY,
    observed_on DATE NOT NULL,
    temperature_c NUMERIC(5, 2) NOT NULL,
    rainfall_mm NUMERIC(6, 2) NOT NULL
);

INSERT INTO dpdp_no_relationships.branch_targets VALUES
('BR-WEST-01', 'West', 2500000.00),
('BR-SOUTH-02', 'South', 1800000.00),
('BR-NORTH-03', 'North', 2100000.00);

INSERT INTO dpdp_no_relationships.product_catalog VALUES
('SKU-100', 'Desk Organizer', 'Office', TRUE),
('SKU-200', 'Wireless Mouse', 'Electronics', TRUE),
('SKU-300', 'Notebook Pack', 'Stationery', TRUE);

INSERT INTO dpdp_no_relationships.weather_observations VALUES
('WX-MUM-001', '2026-04-01', 32.40, 0.00),
('WX-DEL-002', '2026-04-01', 35.20, 0.00),
('WX-BLR-003', '2026-04-01', 28.10, 4.50);
