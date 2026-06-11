-- Retention + persistence signals (subarr #196/#202 follow-up).
-- install_age_days: days since the install_id was created (telemetry_state.created_at) —
--   lets us tell genuine retention from install_id churn (non-persistent /data
--   mints a fresh id, age ~0, every restart).
-- data_persistent: is the install's /data a real mount vs the container's
--   ephemeral writable layer. Measures how widespread the lose-everything footgun is.
ALTER TABLE pings ADD COLUMN install_age_days REAL;
ALTER TABLE pings ADD COLUMN data_persistent INTEGER;
