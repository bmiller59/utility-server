-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0021_trust_task_boundary.sql
-- Trust Task boundary persistence (sections 3.5, 3.7 and 3.10 of the conformance plan).
--
-- 1. `trust_tasks` gains the columns the boundary will record (all nullable; the boundary
--    recorder fills them in). The existing `proof` column is written by the recorder too.
-- 2. `trust_task_accepted`: the durable duplicate record (framework 7.2 item 11), keyed by the
--    document `id` ALONE. The primary key column is named `id` on purpose: the distributed-database
--    data source appends `RETURNING id` to plain inserts. Times are epoch MILLISECONDS in BIGINT
--    (a 32-bit INTEGER would overflow on the Postgres dialect). `state` is 'claimed' | 'completed'.
--
-- Additive and dialect-neutral (no defaults, no DB-side time): the file is identical in the core
-- SQLite tree and the utility-server tree apart from the licence header. Reverting the code after
-- this lands does not remove the columns or the table.

ALTER TABLE trust_tasks ADD COLUMN raw_document   TEXT;
ALTER TABLE trust_tasks ADD COLUMN digest         TEXT;
ALTER TABLE trust_tasks ADD COLUMN task_digest    TEXT;
ALTER TABLE trust_tasks ADD COLUMN issued_at      BIGINT;
ALTER TABLE trust_tasks ADD COLUMN expires_at     BIGINT;
ALTER TABLE trust_tasks ADD COLUMN in_reply_to    TEXT;
ALTER TABLE trust_tasks ADD COLUMN error_code     TEXT;
ALTER TABLE trust_tasks ADD COLUMN disposition    TEXT;
ALTER TABLE trust_tasks ADD COLUMN verified_signer TEXT;
ALTER TABLE trust_tasks ADD COLUMN lifecycle      TEXT;

CREATE TABLE IF NOT EXISTS trust_task_accepted (
  id           TEXT PRIMARY KEY,
  digest       TEXT NOT NULL,
  issuer       TEXT,
  type         TEXT,
  thread_id    TEXT,
  tx_id        TEXT,
  state        TEXT NOT NULL,
  retain_until BIGINT NOT NULL,
  response     TEXT,
  created_at   BIGINT NOT NULL,
  updated_at   BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trust_task_accepted_retain ON trust_task_accepted(retain_until);
CREATE INDEX IF NOT EXISTS idx_trust_task_accepted_tx     ON trust_task_accepted(tx_id);
