-- Dataset 3: Masked Data
-- Expected: partial masking detected for email and phone fields.

DROP SCHEMA IF EXISTS dpdp_masked CASCADE;
CREATE SCHEMA dpdp_masked;

CREATE TABLE dpdp_masked.masked_customers (
    customer_id INTEGER PRIMARY KEY,
    customer_alias VARCHAR(120) NOT NULL,
    masked_email VARCHAR(160) NOT NULL,
    masked_phone VARCHAR(20) NOT NULL,
    city VARCHAR(80) NOT NULL,
    consent_status VARCHAR(20) NOT NULL
);

CREATE TABLE dpdp_masked.communication_preferences (
    preference_id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES dpdp_masked.masked_customers(customer_id),
    channel VARCHAR(30) NOT NULL,
    masked_contact VARCHAR(160) NOT NULL
);

INSERT INTO dpdp_masked.masked_customers VALUES
(1, 'CUST-A1', 'j********@m.com', '98******10', 'Hyderabad', 'ACTIVE'),
(2, 'CUST-B2', 'r********@m.com', '91******22', 'Delhi', 'ACTIVE'),
(3, 'CUST-C3', 'm********@m.com', '88******33', 'Pune', 'ACTIVE'),
(4, 'CUST-D4', 'i********@m.com', '77******44', 'Mumbai', 'ACTIVE');

INSERT INTO dpdp_masked.communication_preferences VALUES
(701, 1, 'EMAIL', 'j********@m.com'),
(702, 2, 'SMS', '91******22'),
(703, 3, 'EMAIL', 'm********@m.com'),
(704, 4, 'SMS', '77******44');
