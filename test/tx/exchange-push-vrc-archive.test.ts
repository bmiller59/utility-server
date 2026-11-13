// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5c: the archive push of a conformant (per-VRC relationship DID) credential. It is
 * applied as a credential row only: no identity is created or updated and no relationship edge is
 * written; dedup is by digest, so a second exchange between the same identities is a new row; and the
 * legacy per-pair dedup ignores conformant credentials. In-memory databases only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import { applyTxSchemaAdditions, TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { ExchangePushParticipant } from '../../src/tx/exchange-push-participant.js';

async function setup() {
  const appDb = new SqliteDataSource(':memory:');
  runMigrations(appDb.getRawDb(), getMigrationsDir());
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  await applyTxSchemaAdditions(txDb);
  const issuer = await identitiesRepo.create(appDb, { realDid: 'did:scid:vh:issuer', role: 'vta', subjectKind: 'human', custody: 'remote' });
  const subject = await identitiesRepo.create(appDb, { realDid: 'did:scid:vh:subject', role: 'vta', subjectKind: 'human', custody: 'remote' });
  return { appDb, participant: new ExchangePushParticipant('server:s', appDb, txDb), issuer, subject };
}

const cred = (uuid: string, issuer: string, subject: string, digest: string, w3c: string) => ({
  uuid, vcType: 'vrc', issuerIdentityUuid: issuer, subjectIdentityUuid: subject, w3cVcJson: w3c, claim: '{}',
  status: 'issued', thresholdRequired: null, validFrom: 1, validUntil: null, credentialDigest: digest, createdAt: 1,
});
const vc = (n: number) => JSON.stringify({ issuer: `did:peer:4zRel${n}`, issuerScope: 'pairwise', n });
const op = (payload: unknown) => [{ op: 'exchange:identity', params: { payload } } as never];
const count = async (ds: SqliteDataSource, table: string) => (await ds.get<{ n: number }>(`SELECT COUNT(*) AS n FROM ${table}`))!.n;

test('a conformant archive push stores credential rows only: no identity or relationship written', async () => {
  const { appDb, participant, issuer, subject } = await setup();
  const identitiesBefore = await count(appDb, 'identities');
  const relationshipsBefore = await count(appDb, 'relationships');
  const keysBefore = await count(appDb, 'keys');
  const payload = { vrcArchive: { credentials: [cred('c1', issuer, subject, 'd1', vc(1))] } };
  assert.equal(await participant.prepare('tx-1', op(payload)), 'yes');
  assert.equal(await count(appDb, 'credentials'), 1);
  assert.equal(await count(appDb, 'identities'), identitiesBefore);
  assert.equal(await count(appDb, 'relationships'), relationshipsBefore);
  assert.equal(await count(appDb, 'keys'), keysBefore);
});

test('a second exchange between the same identities is a second row; a repeat of one is not', async () => {
  const { appDb, participant, issuer, subject } = await setup();
  await participant.prepare('tx-1', op({ vrcArchive: { credentials: [cred('c1', issuer, subject, 'd1', vc(1))] } }));
  await participant.prepare('tx-2', op({ vrcArchive: { credentials: [cred('c2', issuer, subject, 'd2', vc(2))] } }));
  await participant.prepare('tx-3', op({ vrcArchive: { credentials: [cred('c1', issuer, subject, 'd1', vc(1))] } }));
  assert.equal(await count(appDb, 'credentials'), 2);
});

test('credentials for identities the server does not hold are skipped, not created', async () => {
  const { appDb, participant, subject } = await setup();
  assert.equal(await participant.prepare('tx-1', op({ vrcArchive: { credentials: [cred('c1', 'no-such-identity', subject, 'd1', vc(1))] } })), 'yes');
  assert.equal(await count(appDb, 'credentials'), 0);
  assert.equal(await count(appDb, 'identities'), 2);
});

test('the legacy identity push still refuses a payload with no realDid and no archive', async () => {
  const { participant } = await setup();
  assert.equal(await participant.prepare('tx-1', op({ credentials: [] })), 'no');
});
