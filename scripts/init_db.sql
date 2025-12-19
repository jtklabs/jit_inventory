-- Network Device Inventory Database Schema

-- Devices table: stores discovered devices
CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address INET NOT NULL,
    hostname VARCHAR(255),
    vendor VARCHAR(100),
    device_type VARCHAR(100),
    platform VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    software_version VARCHAR(100),
    sys_object_id VARCHAR(255),
    sys_description TEXT,
    first_discovered TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_updated TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB,
    UNIQUE(ip_address)
);

-- Scan history: every scan attempt with full results
CREATE TABLE IF NOT EXISTS scan_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id UUID REFERENCES devices(id) ON DELETE SET NULL,
    ip_address INET NOT NULL,
    scan_type VARCHAR(50) NOT NULL,
    scan_status VARCHAR(50) NOT NULL,
    started_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_ms INTEGER,
    error_message TEXT,
    hostname VARCHAR(255),
    vendor VARCHAR(100),
    device_type VARCHAR(100),
    platform VARCHAR(100),
    model VARCHAR(100),
    serial_number VARCHAR(100),
    software_version VARCHAR(100),
    sys_object_id VARCHAR(255),
    sys_description TEXT,
    raw_snmp_data JSONB,
    credential_profile_name VARCHAR(255),
    snmp_version VARCHAR(10)
);

-- Batch scan jobs
CREATE TABLE IF NOT EXISTS batch_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255),
    status VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    total_targets INTEGER NOT NULL,
    completed_count INTEGER DEFAULT 0,
    success_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    input_type VARCHAR(50),
    input_data TEXT,
    credential_profile_name VARCHAR(255)
);

-- Batch job targets
CREATE TABLE IF NOT EXISTS batch_job_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    batch_job_id UUID NOT NULL REFERENCES batch_jobs(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    scan_history_id UUID REFERENCES scan_history(id),
    processed_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT
);

-- Credential profiles (metadata only, secrets stored externally)
CREATE TABLE IF NOT EXISTS credential_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    snmp_version VARCHAR(10) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    is_default BOOLEAN DEFAULT FALSE,
    v3_username VARCHAR(100),
    v3_auth_protocol VARCHAR(20),
    v3_priv_protocol VARCHAR(20),
    v3_security_level VARCHAR(20)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address);
CREATE INDEX IF NOT EXISTS idx_devices_vendor ON devices(vendor);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_scan_history_device ON scan_history(device_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_ip ON scan_history(ip_address);
CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at);
CREATE INDEX IF NOT EXISTS idx_batch_jobs_status ON batch_jobs(status);
CREATE INDEX IF NOT EXISTS idx_batch_targets_job ON batch_job_targets(batch_job_id);
CREATE INDEX IF NOT EXISTS idx_batch_targets_status ON batch_job_targets(status);
