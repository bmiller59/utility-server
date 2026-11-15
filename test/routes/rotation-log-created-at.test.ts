// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * POST /did-documents/:uuid/rotation-log stores a client-signed rotation entry.
 * The entry digest the client signed covers its `createdAt`, and resolution
 * recomputes that digest from the stored row. If the route stamps the row with
 * the insertion time instead of the signed `createdAt`, an entry signed at any
 * earlier second no longer validates and the DID silently falls back to the
 * cached snapshot.
 *
 * Run with:
 *   cd utility-server && node --conditions=development --experimental-strip-types \
 *     --loader ./test-loader.mjs --test test/routes/rotation-log-created-at.test.ts
 */
import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import Fastify from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { DidResolutionService } from '@p2p-trust-stack/core/did/did-resolution-service.js';
import { packRotationEntry } from '@p2p-trust-stack/core/did/rotation-entry-codec.js';
import { registerRotationRoutes } from '../../src/routes/layer1-infrastructure/rotation.js';

function makeDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

test('a rotation entry pushed through the route resolves from the log when signed in the past', async () => {
  const ds = makeDb();
  const realNow = Date.now();
  // Sign the genesis entry an hour ago, so its createdAt is not the insert second.
  const clock = mock.method(Date, 'now', () => realNow - 3_600_000);
  const created = await new ScidVhMethod({}).create();
  clock.mock.restore();
  const genesis = created.log[0];
  assert.ok(genesis.createdAt < Math.floor(realNow / 1000) - 3000, 'precondition: signed in the past');

  const now = Math.floor(realNow / 1000);
  await ds.run(
    `INSERT INTO identities (uuid, role, subject_kind, custody, name, created_at, updated_at)
     VALUES ('id-1', 'vta', 'human', 'local', 'alice', ?, ?)`, now, now,
  );
  await ds.run(
    `INSERT INTO did_documents (uuid, identity_uuid, did, method, document_json, is_primary, status, created_at, updated_at)
     VALUES ('doc-1', 'id-1', ?, 'did:scid:vh', ?, 1, 'active', ?, ?)`,
    created.did, JSON.stringify(created.document), now, now,
  );

  const app = Fastify();
  registerRotationRoutes(app, ds);
  await app.ready();
  const payload = {
    version: genesis.version,
    newPublicKey: Buffer.from(
      JSON.stringify(genesis.nextKeyCommitments.map((k) => Buffer.from(k).toString('base64'))),
    ).toString('base64'),
    signedEntry: Buffer.from(
      packRotationEntry({
        didDocument: genesis.didDocument,
        parameters: genesis.parameters,
        digest: genesis.digest,
        signature: genesis.signature,
        mlDsa65Signature: genesis.mlDsa65Signature,
      }),
    ).toString('base64'),
    createdAt: genesis.createdAt,
  };
  const res = await app.inject({ method: 'POST', url: '/did-documents/doc-1/rotation-log', payload });
  assert.equal(res.statusCode, 201, res.body);

  const report = await new DidResolutionService(ds).resolve(created.did);
  assert.equal(report.source, 'log', 'the signed entry must verify against its stored createdAt');
  assert.equal(report.result.didResolutionMetadata.chainValid, true);

  // The same version again is a conflict, not a second row or a database error.
  const dup = await app.inject({ method: 'POST', url: '/did-documents/doc-1/rotation-log', payload });
  assert.equal(dup.statusCode, 409, dup.body);

  // A createdAt that is not a non-negative integer is refused.
  const bad = await app.inject({
    method: 'POST', url: '/did-documents/doc-1/rotation-log', payload: { ...payload, version: 1, createdAt: -5 },
  });
  assert.equal(bad.statusCode, 400, bad.body);

  await app.close();
  await ds.close();
});
