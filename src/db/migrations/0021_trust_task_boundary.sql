-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
-- Copyright (C) 2026 Trust Stackers

-- 0021_trust_task_boundary.sql
-- Trust Task boundary persistence (conformance plan 06, sections 3.5, 3.7 and 3.10; phase P3).
--
-- 1. `trust_tasks` gains the columns the boundary will record (all nullable; nothing writes them
--    until the attestation phase). The existing `proof` column starts to be written then too.
-- 2. `trust_task_accepted`: the durable duplicate record (framework 7.2 item 11), keyed by the
--    document `id` ALONE. The primary key column is named `id` on purpose: the distributed-database
--    data source appends `RETURNING id` to plain inserts. Times are epoch MILLISECONDS in BIGINT
--    (a 32-bit INTEGER would overflow on the Postgres dialect). `state` is 'claimed' | 'completed'.
-- 3. `vrc_exchange_relationship_dids`: the per-VRC relationship-DID mapping, keyed by the `propose`
--    document id (the exchange / thread id). Schema only here; minting is a later phase.
--
-- Additive and dialect-neutral (no defaults, no DB-side time): the file is identical in the core
-- SQLite tree and the utility-server tree apart from the licence header. A recorded schema version
-- newer than the code refuses to start, so reverting the code after this lands does not remove it.

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

CREATE TABLE IF NOT EXISTS vrc_exchange_relationship_dids (
  exchange_id               TEXT PRIMARY KEY,
  local_connection_did      TEXT NOT NULL,
  remote_connection_did     TEXT NOT NULL,
  local_relationship_did    TEXT NOT NULL,
  remote_relationship_did   TEXT,
  local_identity_uuid       TEXT,
  remote_identity_uuid      TEXT,
  role                      TEXT NOT NULL,
  state                     TEXT NOT NULL,
  recorded_by_node          TEXT,
  created_at                BIGINT NOT NULL,
  updated_at                BIGINT NOT NULL,
  UNIQUE(local_relationship_did),
  UNIQUE(remote_relationship_did)
);

CREATE INDEX IF NOT EXISTS idx_vred_connections ON vrc_exchange_relationship_dids(local_connection_did, remote_connection_did);
