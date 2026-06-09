-- Remove duplicates before adding unique index (keep lowest id).
DELETE FROM open_ports a
USING open_ports b
WHERE a.id > b.id
  AND a.scan_run_id = b.scan_run_id
  AND a.port = b.port
  AND a.protocol = b.protocol;

CREATE UNIQUE INDEX IF NOT EXISTS idx_open_ports_scan_run_port_protocol
  ON open_ports(scan_run_id, port, protocol);
