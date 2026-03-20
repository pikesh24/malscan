-- MalScan Pro Initial Database Schema
-- To be executed against PostgreSQL or SQLite

CREATE TABLE IF NOT EXISTS scan_jobs (
    job_id VARCHAR(64) PRIMARY KEY,
    status VARCHAR(32) NOT NULL DEFAULT 'Submitted',
    file_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    results JSON
);

CREATE TABLE IF NOT EXISTS artifacts (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(64) REFERENCES scan_jobs(job_id),
    original_filename VARCHAR(255),
    file_size_bytes BIGINT,
    mime_type VARCHAR(128),
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS analysis_results (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(64) REFERENCES scan_jobs(job_id),
    module_name VARCHAR(64),
    verdict VARCHAR(32),
    confidence_score INTEGER,
    raw_output JSON,
    completed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
