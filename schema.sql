-- Run this in your Postgres (Render or local) ONCE

CREATE TABLE IF NOT EXISTS admins (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'admin',
  active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS thresholds (
  id INT PRIMARY KEY,
  sal_low REAL NOT NULL,
  sal_high REAL NOT NULL,
  ph_low REAL NOT NULL,
  ph_high REAL NOT NULL,
  temp_low REAL NOT NULL,
  temp_high REAL NOT NULL,
  bat_low REAL NOT NULL,
  offline_minutes INT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by INT NULL REFERENCES admins(id)
);

INSERT INTO thresholds(id, sal_low, sal_high, ph_low, ph_high, temp_low, temp_high, bat_low, offline_minutes)
VALUES (1, 8, 12, 6.5, 8.5, 25, 32, 20, 10)
ON CONFLICT (id) DO NOTHING;
