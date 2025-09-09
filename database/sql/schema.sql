-- ThreatX Database Schema
-- PostgreSQL Database Setup

-- Create database (run as superuser)
-- CREATE DATABASE threatx_db;
-- CREATE USER threatx WITH PASSWORD 'password';
-- GRANT ALL PRIVILEGES ON DATABASE threatx_db TO threatx;

-- Connect to threatx_db before running the following

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Log entries table
CREATE TABLE IF NOT EXISTS log_entries (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET,
    user_id VARCHAR(255),
    event_type VARCHAR(100) NOT NULL,
    raw_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes for performance
    CONSTRAINT log_entries_timestamp_check CHECK (timestamp <= NOW())
);

-- Create indexes on log_entries
CREATE INDEX IF NOT EXISTS idx_log_entries_timestamp ON log_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_log_entries_ip ON log_entries(ip_address);
CREATE INDEX IF NOT EXISTS idx_log_entries_user ON log_entries(user_id);
CREATE INDEX IF NOT EXISTS idx_log_entries_event_type ON log_entries(event_type);
CREATE INDEX IF NOT EXISTS idx_log_entries_created_at ON log_entries(created_at);

-- Threat analyses table
CREATE TABLE IF NOT EXISTS threat_analyses (
    id SERIAL PRIMARY KEY,
    log_entry_id INTEGER REFERENCES log_entries(id) ON DELETE CASCADE,
    risk_score FLOAT NOT NULL CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_level VARCHAR(20) NOT NULL CHECK (risk_level IN ('NORMAL', 'LOW', 'MEDIUM', 'HIGH')),
    model_scores JSONB,
    threat_types TEXT[],
    recommendations TEXT[],
    confidence FLOAT CHECK (confidence >= 0 AND confidence <= 1),
    analysis_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Additional metadata
    model_version VARCHAR(50),
    processing_time_ms INTEGER,
    notes TEXT
);

-- Create indexes on threat_analyses
CREATE INDEX IF NOT EXISTS idx_threat_analyses_risk_level ON threat_analyses(risk_level);
CREATE INDEX IF NOT EXISTS idx_threat_analyses_timestamp ON threat_analyses(analysis_timestamp);
CREATE INDEX IF NOT EXISTS idx_threat_analyses_risk_score ON threat_analyses(risk_score);
CREATE INDEX IF NOT EXISTS idx_threat_analyses_log_entry ON threat_analyses(log_entry_id);

-- User risk profiles table
CREATE TABLE IF NOT EXISTS user_risk_profiles (
    user_id VARCHAR(255) PRIMARY KEY,
    current_risk_score FLOAT DEFAULT 0.5 CHECK (current_risk_score >= 0 AND current_risk_score <= 1),
    total_alerts INTEGER DEFAULT 0 CHECK (total_alerts >= 0),
    high_risk_alerts INTEGER DEFAULT 0 CHECK (high_risk_alerts >= 0),
    medium_risk_alerts INTEGER DEFAULT 0 CHECK (medium_risk_alerts >= 0),
    last_suspicious_activity TIMESTAMP WITH TIME ZONE,
    risk_history JSONB,
    trust_score FLOAT DEFAULT 0.5 CHECK (trust_score >= 0 AND trust_score <= 1),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Additional profile data
    department VARCHAR(100),
    access_level VARCHAR(50),
    last_login TIMESTAMP WITH TIME ZONE,
    login_count INTEGER DEFAULT 0,
    failed_login_count INTEGER DEFAULT 0
);

-- Create indexes on user_risk_profiles
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_risk_score ON user_risk_profiles(current_risk_score);
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_total_alerts ON user_risk_profiles(total_alerts);
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_last_activity ON user_risk_profiles(last_suspicious_activity);
CREATE INDEX IF NOT EXISTS idx_user_risk_profiles_updated_at ON user_risk_profiles(updated_at);

-- Suspicious IPs table
CREATE TABLE IF NOT EXISTS suspicious_ips (
    ip_address INET PRIMARY KEY,
    reputation_score FLOAT DEFAULT 0.5 CHECK (reputation_score >= 0 AND reputation_score <= 1),
    threat_count INTEGER DEFAULT 0 CHECK (threat_count >= 0),
    last_threat_time TIMESTAMP WITH TIME ZONE,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    country_code VARCHAR(2),
    country_name VARCHAR(100),
    is_blocked BOOLEAN DEFAULT FALSE,
    block_reason TEXT,
    is_whitelisted BOOLEAN DEFAULT FALSE,
    whitelist_reason TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- GeoIP data
    latitude FLOAT,
    longitude FLOAT,
    city VARCHAR(100),
    region VARCHAR(100),
    timezone VARCHAR(50),
    isp VARCHAR(200),
    organization VARCHAR(200),
    asn INTEGER,
    
    -- Threat intelligence data
    malware_family VARCHAR(100),
    attack_types TEXT[],
    severity_level VARCHAR(20),
    confidence_level FLOAT
);

-- Create indexes on suspicious_ips
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_threat_count ON suspicious_ips(threat_count);
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_last_threat ON suspicious_ips(last_threat_time);
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_country ON suspicious_ips(country_code);
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_blocked ON suspicious_ips(is_blocked);
CREATE INDEX IF NOT EXISTS idx_suspicious_ips_reputation ON suspicious_ips(reputation_score);

-- Threat intelligence feed
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash', 'email')),
    indicator_value TEXT NOT NULL,
    threat_type VARCHAR(100),
    malware_family VARCHAR(100),
    confidence_score FLOAT CHECK (confidence_score >= 0 AND confidence_score <= 1),
    severity VARCHAR(20) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    source VARCHAR(100) NOT NULL,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    tags TEXT[],
    description TEXT,
    references TEXT[],
    
    UNIQUE(indicator_type, indicator_value, source)
);

-- Create indexes on threat_intelligence
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_type_value ON threat_intelligence(indicator_type, indicator_value);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_active ON threat_intelligence(is_active);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_severity ON threat_intelligence(severity);
CREATE INDEX IF NOT EXISTS idx_threat_intelligence_last_seen ON threat_intelligence(last_seen);

-- System configuration table
CREATE TABLE IF NOT EXISTS system_config (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT,
    description TEXT,
    category VARCHAR(50),
    data_type VARCHAR(20) DEFAULT 'string',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default configuration
INSERT INTO system_config (key, value, description, category, data_type) VALUES
('anomaly_threshold', '0.1', 'Threshold for anomaly detection models', 'ml_models', 'float'),
('high_risk_threshold', '0.8', 'Threshold for high risk classification', 'risk_scoring', 'float'),
('medium_risk_threshold', '0.6', 'Threshold for medium risk classification', 'risk_scoring', 'float'),
('low_risk_threshold', '0.3', 'Threshold for low risk classification', 'risk_scoring', 'float'),
('max_login_attempts', '5', 'Maximum failed login attempts before alert', 'authentication', 'integer'),
('suspicious_ip_threshold', '10', 'Threat count threshold for suspicious IP classification', 'ip_analysis', 'integer'),
('model_update_interval', '7', 'Days between model retraining', 'ml_models', 'integer'),
('data_retention_days', '90', 'Days to retain log data', 'data_management', 'integer'),
('auto_block_enabled', 'false', 'Automatically block high-risk IPs', 'security', 'boolean'),
('notification_email', 'admin@threatx.com', 'Email for security notifications', 'notifications', 'string')
ON CONFLICT (key) DO NOTHING;

-- Model performance metrics table
CREATE TABLE IF NOT EXISTS model_metrics (
    id SERIAL PRIMARY KEY,
    model_name VARCHAR(100) NOT NULL,
    model_version VARCHAR(50),
    metric_name VARCHAR(100) NOT NULL,
    metric_value FLOAT NOT NULL,
    evaluation_timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    dataset_size INTEGER,
    training_time_seconds INTEGER,
    notes TEXT
);

-- Create indexes on model_metrics
CREATE INDEX IF NOT EXISTS idx_model_metrics_name ON model_metrics(model_name);
CREATE INDEX IF NOT EXISTS idx_model_metrics_timestamp ON model_metrics(evaluation_timestamp);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    user_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes on audit_log
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);

-- Create views for common queries

-- View for recent high-risk threats
CREATE OR REPLACE VIEW recent_high_risk_threats AS
SELECT 
    ta.id,
    ta.risk_score,
    ta.risk_level,
    ta.threat_types,
    ta.analysis_timestamp,
    le.ip_address,
    le.user_id,
    le.event_type,
    le.timestamp as log_timestamp
FROM threat_analyses ta
JOIN log_entries le ON ta.log_entry_id = le.id
WHERE ta.risk_level = 'HIGH'
    AND ta.analysis_timestamp >= NOW() - INTERVAL '24 hours'
ORDER BY ta.analysis_timestamp DESC;

-- View for threat statistics
CREATE OR REPLACE VIEW threat_statistics AS
SELECT 
    DATE_TRUNC('hour', analysis_timestamp) as hour,
    risk_level,
    COUNT(*) as threat_count,
    AVG(risk_score) as avg_risk_score,
    AVG(confidence) as avg_confidence
FROM threat_analyses
WHERE analysis_timestamp >= NOW() - INTERVAL '7 days'
GROUP BY DATE_TRUNC('hour', analysis_timestamp), risk_level
ORDER BY hour DESC, risk_level;

-- View for user risk summary
CREATE OR REPLACE VIEW user_risk_summary AS
SELECT 
    urp.user_id,
    urp.current_risk_score,
    urp.total_alerts,
    urp.last_suspicious_activity,
    COUNT(ta.id) as recent_threats,
    MAX(ta.risk_score) as max_recent_risk_score
FROM user_risk_profiles urp
LEFT JOIN log_entries le ON urp.user_id = le.user_id
LEFT JOIN threat_analyses ta ON le.id = ta.log_entry_id 
    AND ta.analysis_timestamp >= NOW() - INTERVAL '24 hours'
GROUP BY urp.user_id, urp.current_risk_score, urp.total_alerts, urp.last_suspicious_activity
ORDER BY urp.current_risk_score DESC, urp.total_alerts DESC;

-- Functions for data management

-- Function to update user risk profile
CREATE OR REPLACE FUNCTION update_user_risk_profile(
    p_user_id VARCHAR(255),
    p_risk_score FLOAT,
    p_is_suspicious BOOLEAN DEFAULT FALSE
) RETURNS VOID AS $$
BEGIN
    INSERT INTO user_risk_profiles (user_id, current_risk_score, total_alerts, updated_at)
    VALUES (p_user_id, p_risk_score, CASE WHEN p_is_suspicious THEN 1 ELSE 0 END, NOW())
    ON CONFLICT (user_id) DO UPDATE SET
        current_risk_score = p_risk_score,
        total_alerts = user_risk_profiles.total_alerts + CASE WHEN p_is_suspicious THEN 1 ELSE 0 END,
        high_risk_alerts = user_risk_profiles.high_risk_alerts + CASE WHEN p_risk_score >= 0.8 AND p_is_suspicious THEN 1 ELSE 0 END,
        medium_risk_alerts = user_risk_profiles.medium_risk_alerts + CASE WHEN p_risk_score >= 0.6 AND p_risk_score < 0.8 AND p_is_suspicious THEN 1 ELSE 0 END,
        last_suspicious_activity = CASE WHEN p_is_suspicious THEN NOW() ELSE user_risk_profiles.last_suspicious_activity END,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to update suspicious IP
CREATE OR REPLACE FUNCTION update_suspicious_ip(
    p_ip_address INET,
    p_reputation_score FLOAT DEFAULT NULL,
    p_increment_threat_count BOOLEAN DEFAULT TRUE
) RETURNS VOID AS $$
BEGIN
    INSERT INTO suspicious_ips (ip_address, reputation_score, threat_count, last_threat_time, updated_at)
    VALUES (p_ip_address, COALESCE(p_reputation_score, 0.5), CASE WHEN p_increment_threat_count THEN 1 ELSE 0 END, NOW(), NOW())
    ON CONFLICT (ip_address) DO UPDATE SET
        reputation_score = COALESCE(p_reputation_score, suspicious_ips.reputation_score),
        threat_count = suspicious_ips.threat_count + CASE WHEN p_increment_threat_count THEN 1 ELSE 0 END,
        last_threat_time = NOW(),
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to clean old data
CREATE OR REPLACE FUNCTION cleanup_old_data(retention_days INTEGER DEFAULT 90) RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Delete old log entries and their associated threat analyses
    WITH deleted AS (
        DELETE FROM log_entries 
        WHERE created_at < NOW() - INTERVAL '1 day' * retention_days
        RETURNING id
    )
    SELECT COUNT(*) INTO deleted_count FROM deleted;
    
    -- Clean up orphaned records
    DELETE FROM threat_analyses WHERE log_entry_id NOT IN (SELECT id FROM log_entries);
    
    -- Clean up old model metrics
    DELETE FROM model_metrics WHERE evaluation_timestamp < NOW() - INTERVAL '1 day' * retention_days;
    
    -- Clean up old audit logs
    DELETE FROM audit_log WHERE timestamp < NOW() - INTERVAL '1 day' * retention_days;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Triggers

-- Trigger to update user risk profile when threat analysis is inserted
CREATE OR REPLACE FUNCTION trigger_update_user_risk_profile() RETURNS TRIGGER AS $$
BEGIN
    -- Get user_id from associated log entry
    UPDATE user_risk_profiles 
    SET updated_at = NOW()
    WHERE user_id = (SELECT user_id FROM log_entries WHERE id = NEW.log_entry_id);
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tr_threat_analysis_user_update
    AFTER INSERT ON threat_analyses
    FOR EACH ROW
    EXECUTE FUNCTION trigger_update_user_risk_profile();

-- Trigger to update suspicious IP when threat analysis is inserted
CREATE OR REPLACE FUNCTION trigger_update_suspicious_ip() RETURNS TRIGGER AS $$
DECLARE
    log_ip INET;
BEGIN
    -- Get IP address from associated log entry
    SELECT ip_address INTO log_ip FROM log_entries WHERE id = NEW.log_entry_id;
    
    IF log_ip IS NOT NULL AND NEW.risk_level IN ('HIGH', 'MEDIUM') THEN
        PERFORM update_suspicious_ip(log_ip, 1.0 - NEW.risk_score, TRUE);
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tr_threat_analysis_ip_update
    AFTER INSERT ON threat_analyses
    FOR EACH ROW
    EXECUTE FUNCTION trigger_update_suspicious_ip();

-- Grant permissions to threatx user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO threatx;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO threatx;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO threatx;

-- Create scheduled job for data cleanup (requires pg_cron extension)
-- SELECT cron.schedule('cleanup-old-data', '0 2 * * *', 'SELECT cleanup_old_data(90);');