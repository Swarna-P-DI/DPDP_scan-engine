CREATE TABLE IF NOT EXISTS pii_field_catalog (
    field_id VARCHAR(512) PRIMARY KEY,
    source_system VARCHAR(128) NOT NULL,
    schema_name VARCHAR(128) NOT NULL,
    table_name VARCHAR(128) NOT NULL,
    column_name VARCHAR(128) NOT NULL,
    pii_type VARCHAR(64) NOT NULL,
    pii_category VARCHAR(128) NOT NULL,
    sensitivity_level VARCHAR(32) NOT NULL,
    sensitivity_score DOUBLE PRECISION NOT NULL,
    detection_confidence DOUBLE PRECISION NOT NULL,
    is_masked BOOLEAN NOT NULL DEFAULT FALSE,
    is_encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    is_tokenized BOOLEAN NOT NULL DEFAULT FALSE,
    data_owner TEXT,
    business_unit TEXT,
    steward_email TEXT,
    retention_period_days INTEGER,
    last_accessed TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS is_encrypted BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS is_tokenized BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS data_owner TEXT;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS business_unit TEXT;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS steward_email TEXT;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS retention_period_days INTEGER;
ALTER TABLE pii_field_catalog ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMPTZ;
ALTER TABLE pii_field_catalog ALTER COLUMN sensitivity_score TYPE DOUBLE PRECISION USING sensitivity_score::DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_pii_field_catalog_source ON pii_field_catalog (source_system);
CREATE INDEX IF NOT EXISTS idx_pii_field_catalog_type ON pii_field_catalog (pii_type);
CREATE INDEX IF NOT EXISTS idx_pii_field_catalog_sensitivity ON pii_field_catalog (sensitivity_level);

CREATE TABLE IF NOT EXISTS pii_detection_events (
    event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    field_id VARCHAR(512) NOT NULL REFERENCES pii_field_catalog(field_id) ON DELETE CASCADE,
    hashed_value VARCHAR(64) NOT NULL,
    last4_value VARCHAR(8),
    detection_method VARCHAR(64) NOT NULL,
    confidence_score DOUBLE PRECISION NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE pii_detection_events ADD COLUMN IF NOT EXISTS hashed_value VARCHAR(64);
ALTER TABLE pii_detection_events ADD COLUMN IF NOT EXISTS last4_value VARCHAR(8);
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_name = 'pii_detection_events'
          AND column_name = 'detected_value'
    ) THEN
        ALTER TABLE pii_detection_events ALTER COLUMN detected_value DROP NOT NULL;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_pii_detection_events_field ON pii_detection_events (field_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pii_detection_event_idempotent
    ON pii_detection_events (field_id, hashed_value, detection_method);

CREATE TABLE IF NOT EXISTS pii_api_mapping (
    mapping_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    field_id VARCHAR(512) NOT NULL REFERENCES pii_field_catalog(field_id) ON DELETE CASCADE,
    api_path VARCHAR(512) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    service_name VARCHAR(128) NOT NULL,
    exposure_type VARCHAR(32) NOT NULL CHECK (exposure_type IN ('INTERNAL', 'PARTNER', 'PUBLIC', 'internal', 'external')),
    risk_level VARCHAR(32) NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    response_count INTEGER NOT NULL DEFAULT 0,
    request_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    last_accessed TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE pii_api_mapping ADD COLUMN IF NOT EXISTS request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pii_api_mapping ADD COLUMN IF NOT EXISTS response_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pii_api_mapping ADD COLUMN IF NOT EXISTS request_rate DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE pii_api_mapping ADD COLUMN IF NOT EXISTS last_accessed TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_pii_api_mapping_field ON pii_api_mapping (field_id);
CREATE INDEX IF NOT EXISTS idx_pii_api_mapping_exposure ON pii_api_mapping (exposure_type, risk_level);
CREATE UNIQUE INDEX IF NOT EXISTS uq_pii_api_mapping_idempotent
    ON pii_api_mapping (field_id, api_path, http_method);

CREATE TABLE IF NOT EXISTS pii_risk_assessment (
    assessment_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    field_id VARCHAR(512) NOT NULL REFERENCES pii_field_catalog(field_id) ON DELETE CASCADE,
    sensitivity_score DOUBLE PRECISION NOT NULL,
    exposure_score DOUBLE PRECISION NOT NULL,
    volume_score DOUBLE PRECISION NOT NULL,
    overall_risk_score DOUBLE PRECISION NOT NULL,
    exposure_type TEXT NOT NULL DEFAULT 'INTERNAL',
    anomaly_flag BOOLEAN NOT NULL DEFAULT FALSE,
    retention_violation BOOLEAN NOT NULL DEFAULT FALSE,
    risk_category VARCHAR(32) NOT NULL,
    risk_factors TEXT,
    confidence_factors TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    request_rate DOUBLE PRECISION NOT NULL DEFAULT 0,
    recommendation TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS exposure_type TEXT NOT NULL DEFAULT 'INTERNAL';
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS anomaly_flag BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS retention_violation BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS risk_factors TEXT;
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS confidence_factors TEXT;
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS request_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE pii_risk_assessment ADD COLUMN IF NOT EXISTS request_rate DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE pii_risk_assessment ALTER COLUMN sensitivity_score TYPE DOUBLE PRECISION USING sensitivity_score::DOUBLE PRECISION;
ALTER TABLE pii_risk_assessment ALTER COLUMN exposure_score TYPE DOUBLE PRECISION USING exposure_score::DOUBLE PRECISION;
ALTER TABLE pii_risk_assessment ALTER COLUMN volume_score TYPE DOUBLE PRECISION USING volume_score::DOUBLE PRECISION;
ALTER TABLE pii_risk_assessment ALTER COLUMN overall_risk_score TYPE DOUBLE PRECISION USING overall_risk_score::DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_pii_risk_assessment_field ON pii_risk_assessment (field_id);
CREATE INDEX IF NOT EXISTS idx_pii_risk_assessment_category ON pii_risk_assessment (risk_category);
