ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS cvss_score FLOAT;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS severity VARCHAR(50);
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS affected_vendor VARCHAR(255);
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS affected_product VARCHAR(255);
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS affected_version VARCHAR(255);
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS source VARCHAR(50);
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS published_at TIMESTAMP;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP;
ALTER TABLE cve_enrichment ADD COLUMN IF NOT EXISTS last_synced_at TIMESTAMP;

UPDATE cve_enrichment
SET cvss_score = COALESCE(cvss_score, cvss)
WHERE cvss IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_cve_enrichment_product_version
  ON cve_enrichment(LOWER(affected_product), affected_version);

ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS cve VARCHAR(50);
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS cvss_score FLOAT;
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS severity VARCHAR(50);
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS match_reason TEXT;
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS affected_vendor VARCHAR(255);
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS affected_product VARCHAR(255);
ALTER TABLE port_cve_matches ADD COLUMN IF NOT EXISTS affected_version VARCHAR(255);

UPDATE port_cve_matches
SET cve = COALESCE(cve, cve_id),
    cvss_score = COALESCE(cvss_score, cvss)
WHERE cve IS NULL OR (cvss IS NOT NULL AND cvss_score IS NULL);

CREATE TABLE IF NOT EXISTS target_cve_matches (
  id SERIAL PRIMARY KEY,
  target_id INT NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
  cve_id VARCHAR(50) NOT NULL,
  cve VARCHAR(50),
  product VARCHAR(255),
  version VARCHAR(255),
  cvss FLOAT,
  cvss_score FLOAT,
  severity VARCHAR(50),
  epss FLOAT,
  kev BOOLEAN DEFAULT false,
  match_type VARCHAR(50),
  match_confidence FLOAT,
  match_reason TEXT,
  source TEXT,
  affected_vendor VARCHAR(255),
  affected_product VARCHAR(255),
  affected_version VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW()
);

ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS cve_id VARCHAR(50);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS cve VARCHAR(50);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS product VARCHAR(255);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS version VARCHAR(255);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS cvss FLOAT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS cvss_score FLOAT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS severity VARCHAR(50);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS epss FLOAT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS kev BOOLEAN DEFAULT false;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS match_type VARCHAR(50);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS match_confidence FLOAT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS match_reason TEXT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS affected_vendor VARCHAR(255);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS affected_product VARCHAR(255);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS affected_version VARCHAR(255);
ALTER TABLE target_cve_matches ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW();

CREATE UNIQUE INDEX IF NOT EXISTS idx_target_cve_matches_unique
  ON target_cve_matches(target_id, cve_id, COALESCE(match_type, ''));

CREATE INDEX IF NOT EXISTS idx_target_cve_matches_target
  ON target_cve_matches(target_id);
