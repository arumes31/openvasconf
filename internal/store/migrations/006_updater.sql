CREATE TABLE update_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    feed_enabled INTEGER NOT NULL DEFAULT 1 CHECK (feed_enabled IN (0, 1)),
    feed_minute INTEGER NOT NULL DEFAULT 120 CHECK (feed_minute BETWEEN 0 AND 1439),
    stack_enabled INTEGER NOT NULL DEFAULT 0 CHECK (stack_enabled IN (0, 1)),
    stack_weekday INTEGER NOT NULL DEFAULT 7 CHECK (stack_weekday BETWEEN 1 AND 7),
    stack_start_minute INTEGER NOT NULL DEFAULT 180 CHECK (stack_start_minute BETWEEN 0 AND 1439),
    stack_window_minutes INTEGER NOT NULL DEFAULT 180 CHECK (stack_window_minutes BETWEEN 30 AND 720),
    timezone TEXT NOT NULL,
    backup_retention INTEGER NOT NULL DEFAULT 3 CHECK (backup_retention BETWEEN 1 AND 30),
    verification_timeout_minutes INTEGER NOT NULL DEFAULT 180
        CHECK (verification_timeout_minutes BETWEEN 5 AND 720),
    updated_at TEXT NOT NULL
);

INSERT INTO update_settings(singleton, timezone, updated_at)
SELECT 1, timezone, updated_at FROM settings WHERE singleton = 1;
