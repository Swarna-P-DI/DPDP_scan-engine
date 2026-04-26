-- Dataset 2: PII Exposure
-- Expected: unmasked name/email PII detected with HIGH risk.

DROP SCHEMA IF EXISTS dpdp_pii_exposure CASCADE;
CREATE SCHEMA dpdp_pii_exposure;

CREATE TABLE dpdp_pii_exposure.customer_profiles (
    profile_id INTEGER PRIMARY KEY,
    full_name VARCHAR(120) NOT NULL,
    email VARCHAR(160) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    address_line VARCHAR(240) NOT NULL,
    consent_status VARCHAR(20) NOT NULL
);

CREATE TABLE dpdp_pii_exposure.support_tickets (
    ticket_id INTEGER PRIMARY KEY,
    profile_id INTEGER NOT NULL REFERENCES dpdp_pii_exposure.customer_profiles(profile_id),
    requester_email VARCHAR(160) NOT NULL,
    issue_summary VARCHAR(240) NOT NULL
);

INSERT INTO dpdp_pii_exposure.customer_profiles VALUES
(1, 'Priya Nair', 'priya.nair@mail.com', '9876543210', '12 MG Road Bengaluru', 'ACTIVE'),
(2, 'Amit Verma', 'amit.verma@mail.com', '9876501234', '44 Park Street Kolkata', 'ACTIVE'),
(3, 'Sara Khan', 'sara.khan@mail.com', '9988776655', '18 Carter Road Mumbai', 'ACTIVE'),
(4, 'Kabir Sen', 'kabir.sen@mail.com', '9123456780', '7 Anna Salai Chennai', 'ACTIVE');

INSERT INTO dpdp_pii_exposure.support_tickets VALUES
(501, 1, 'priya.nair@mail.com', 'Billing address correction requested'),
(502, 2, 'amit.verma@mail.com', 'Phone number update requested'),
(503, 3, 'sara.khan@mail.com', 'Account access issue'),
(504, 4, 'kabir.sen@mail.com', 'Consent preference update');
