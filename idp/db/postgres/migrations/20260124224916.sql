-- Update max_attempts default from 5 to 10 (~5 hours of retry with exponential backoff)
ALTER TABLE ssf_event_log ALTER COLUMN max_attempts SET DEFAULT 10;
