-- Alerts raised by detection/live_detector.py. Run once as the database owner:
--   sudo -u postgres psql -d vmi_sentinel -f database/alerts.sql
CREATE TABLE IF NOT EXISTS alerts (
    alert_id       BIGSERIAL PRIMARY KEY,
    vm_id          INTEGER NOT NULL REFERENCES virtual_machines(vm_id),
    window_start   TIMESTAMPTZ NOT NULL,
    window_end     TIMESTAMPTZ NOT NULL,
    detector       VARCHAR(50) NOT NULL,
    anomaly_score  DOUBLE PRECISION NOT NULL,
    features       JSONB NOT NULL,
    top_programs   JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (vm_id, window_start, detector)
);
CREATE INDEX IF NOT EXISTS alerts_vm_time ON alerts (vm_id, window_start);

GRANT SELECT, INSERT ON alerts TO vmi_app;
GRANT USAGE, SELECT ON SEQUENCE alerts_alert_id_seq TO vmi_app;
