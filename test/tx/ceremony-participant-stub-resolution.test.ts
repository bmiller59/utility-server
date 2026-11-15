// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * resolveRealVtaForStub maps an endpoint-less did:peer:4 stub identity to the
 * authoritative VTA that shares its key. Its queries name the same bound
 * parameter more than once (`$1` ... `$1`); node:sqlite (the test data source)
 * rejects that when only one value is passed, so crystallising a ceremony
 * whose founding admin is a stub failed on the SQLite data source.
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs \
 *     --test test/tx/ceremony-participant-stub-resolution.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/schema.js';
import { CeremonyCoordinatorParticipant } from '../../src/tx/ceremony-participant.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { generateEd25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

type Resolver = { resolveRealVtaForStub(db: SqliteDataSource, stubUuid: string): Promise<{ uuid: string } | null> };

async function seed(appDb: SqliteDataSource, did: string, publicKey: Uint8Array, withEndpoint: boolean): Promise<string> {
  const uuid = await identitiesRepo.create(appDb, { realDid: did, role: 'vta', name: did });
  await didDocumentsRepo.create(appDb, { identityUuid: uuid, did, method: did.startsWith('did:peer') ? 'peer' : 'scid', isPrimary: true });
  await keysRepo.create(appDb, { identityUuid: uuid, keyType: 'ed25519', publicKey: Buffer.from(publicKey) });
  if (withEndpoint) {
    appDb.getRawDb().prepare(
      `INSERT INTO peer_endpoints (uuid, identity_uuid, peer_id, multiaddrs, is_active, created_at)
       VALUES (?, ?, ?, '[]', 1, 1)`,
    ).run(`pe-${uuid}`, uuid, `peer-${uuid}`);
  }
  return uuid;
}

test('resolveRealVtaForStub maps an endpoint-less stub to the real VTA sharing its key', async () => {
  const appDb = makeDb();
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const { publicKey } = generateEd25519KeyPair();
  const real = await seed(appDb, 'did:scid:vh:real-vta', publicKey, true);
  const stub = await seed(appDb, 'did:peer:4:stub', publicKey, false);

  const resolved = await (participant as unknown as Resolver).resolveRealVtaForStub(appDb, stub);
  assert.equal(resolved?.uuid, real);
});

test('resolveRealVtaForStub returns null when no other VTA shares the stub key', async () => {
  const appDb = makeDb();
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  const participant = new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb);

  const stub = await seed(appDb, 'did:peer:4:lonely', generateEd25519KeyPair().publicKey, false);
  await seed(appDb, 'did:scid:vh:unrelated', generateEd25519KeyPair().publicKey, true);

  const resolved = await (participant as unknown as Resolver).resolveRealVtaForStub(appDb, stub);
  assert.equal(resolved, null);
});
