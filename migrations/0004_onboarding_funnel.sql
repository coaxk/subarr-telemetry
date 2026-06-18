-- 0004_onboarding_funnel.sql
--
-- subarr #202: onboarding activation-funnel signals. Coarse + non-identifying,
-- so they fit the privacy-by-construction schema (the worker's enumerated INSERT
-- is the enforcement layer). Lets us see WHERE in onboarding installs drop off
-- (e.g. never reached the integration step vs reached it and bounced).
--   onboarding_step: furthest/current wizard step reached (0-11).
--   onboarding_complete: 1 once the wizard is finished, else 0.
ALTER TABLE pings ADD COLUMN onboarding_step INTEGER;
ALTER TABLE pings ADD COLUMN onboarding_complete INTEGER;
