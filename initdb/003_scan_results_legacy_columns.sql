-- For DBs created before target_id / scan_type were added to scan_results.
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS target_id INT REFERENCES targets(id);
ALTER TABLE scan_results ADD COLUMN IF NOT EXISTS scan_type VARCHAR(50);
