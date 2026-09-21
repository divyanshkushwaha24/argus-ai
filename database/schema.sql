-- ============================================================================
-- Argus AI — PostgreSQL Storage Schema
--
-- Stage 8:
-- PostgreSQL stores two persistent entities:
--   1. alerts
--   2. incidents
--
-- IMPORTANT:
-- This file defines the canonical database structure.
-- Alert validation at the application boundary is handled by:
--     alerting/schema.py
--
-- Database writes are handled only by:
--     alerting/writer.py
-- ============================================================================


-- ============================================================================
-- INCIDENTS
-- ============================================================================
--
-- One incident can contain multiple related alerts from the same source
-- within the configured correlation window.
--
-- The correlation layer currently produces:
--   incident_id
--   source IP
--   alert count
--   combined risk
--   risk level
--   first seen
--   last seen
--   threat classes
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.incidents (
    incident_id UUID PRIMARY KEY,

    source_ip INET NOT NULL,

    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,

    alert_count INTEGER NOT NULL DEFAULT 0
        CHECK (alert_count >= 0),

    combined_risk INTEGER NOT NULL
        CHECK (combined_risk >= 0 AND combined_risk <= 100),

    risk_level VARCHAR(10) NOT NULL
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),

    threat_classes JSONB NOT NULL DEFAULT '[]'::jsonb
        CHECK (jsonb_typeof(threat_classes) = 'array'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);


-- ============================================================================
-- ALERTS
-- ============================================================================
--
-- This is the canonical Stage-8 alert schema.
--
-- The fields correspond to the project's standardized alert contract:
--   alert_id
--   timestamp
--   flow_id
--   threat_class
--   confidence
--   risk_score
--   severity
--   evidence
--   incident_id
--
-- No detector-specific/internal fusion fields belong here.
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.alerts (
    alert_id UUID PRIMARY KEY,

    timestamp TIMESTAMPTZ NOT NULL,

    flow_id VARCHAR(255) NOT NULL
        CHECK (length(trim(flow_id)) > 0),

    threat_class VARCHAR(20) NOT NULL
        CHECK (
            threat_class IN (
                'ddos',
                'beacon',
                'dns_tunnel',
                'ja3_malware',
                'portscan',
                'exfil'
            )
        ),

    confidence DOUBLE PRECISION NOT NULL
        CHECK (confidence >= 0.0 AND confidence <= 1.0),

    risk_score INTEGER NOT NULL
        CHECK (risk_score >= 0 AND risk_score <= 100),

    severity VARCHAR(10) NOT NULL
        CHECK (
            severity IN (
                'LOW',
                'MEDIUM',
                'HIGH',
                'CRITICAL'
            )
        ),

    evidence JSONB NOT NULL
        CHECK (jsonb_typeof(evidence) = 'array'),

    incident_id UUID NULL,

    CONSTRAINT fk_alert_incident
        FOREIGN KEY (incident_id)
        REFERENCES public.incidents (incident_id)
        ON DELETE SET NULL
);


-- ============================================================================
-- INDEXES
-- ============================================================================
--
-- These support the most common dashboard / storage queries.
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_alerts_timestamp
    ON public.alerts (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_flow_id
    ON public.alerts (flow_id);

CREATE INDEX IF NOT EXISTS idx_alerts_threat_class
    ON public.alerts (threat_class);

CREATE INDEX IF NOT EXISTS idx_alerts_incident_id
    ON public.alerts (incident_id);

CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
    ON public.incidents (source_ip);

CREATE INDEX IF NOT EXISTS idx_incidents_last_seen
    ON public.incidents (last_seen DESC);