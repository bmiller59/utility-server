// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * `POST /trust-tasks` with the DID-resolving verifier and signed replies (conformance phase P4):
 * proofs are verified over the received bytes; an invalid proof is `proofInvalid`; a resolution that
 * cannot be completed is `unavailable` (503, retryable); a signed request addressed to the server's
 * own DID gets a signed reply; the attested profile (Tier 2) requires a proof and signs every reply;
 * the server's own DID is the default answering identifier once startup has recorded it.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks-attested.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';
import { ed25519 } from '@noble/curves/ed25519.js';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { POLICY_EVALUATE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/legacy-evaluate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { DidKeyResolver, CompositeKeyResolver, didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import type { KeyResolver } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { setServerNodeDid } from '../../src/services/server-node-info.js';

const CLUB_DID = 'did:scid:vh:club';
const SERVER_DID = 'did:scid:vh:server';
const START = Date.parse('2026-11-12T10:00:00Z');
const T = '2026-11-12T10:00:00Z';
const PING = 'https://trusttasks.org/spec/conformance/widget/0.1';

const keyOf = (byte: number) => {
  const secretKey = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
  return createEd25519BoundarySigner({ did, secretKey, fragment: did.slice('did:key:'.length) });
};
const PEER = keyOf(5);
const serverSigner = createEd25519BoundarySigner({ did: SERVER_DID, secretKey: new Uint8Array(32).fill(6) });
/** Knows the server's own identifier (the unit under test signs as it) so a test can verify the replies. */
const serverKeys: KeyResolver = {
  async resolve(did) {
    return did === SERVER_DID
      ? { did, source: 'offline', keySetAt: 'latest', keys: [{ fragment: 'key-1', publicKey: serverSigner.publicKey, relationships: ['authentication', 'assertionMethod'] }] }
      : null;
  },
};
const checker = new DidProofVerifier({ resolver: new CompositeKeyResolver([serverKeys, new DidKeyResolver()]) });

const ping: PipelineHandler = {
  types: [PING],
  spec: { typeUri: PING, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true },
  consequential: true,
  handle: (d, ctx) => ({ id: ctx.newId(), threadId: d.threadId ?? d.id, type: `${PING}#response`, issuer: ctx.myVid, recipient: d.issuer, issuedAt: ctx.clock(), payload: {} }) as never,
};

async function seed(options: Record<string, unknown> = {}) {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const uuid = generateUuid();
  await identitiesRepo.create(ds, { uuid, realDid: CLUB_DID, role: 'vtc', name: 'Chess Club', recordedByNode: 'test' });
  await didDocumentsRepo.create(ds, { identityUuid: uuid, did: CLUB_DID, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
  const adminUuid = generateUuid();
  await identitiesRepo.create(ds, { uuid: adminUuid, realDid: 'did:scid:vh:admin', role: 'vta', name: 'Admin', recordedByNode: 'test' });
  await membershipsRepo.create(ds, { memberIdentityUuid: adminUuid, communityIdentityUuid: uuid, role: 'founding_admin', status: 'active' });
  await governanceRepo.create(ds, { communityIdentityUuid: uuid, adminThresholdM: 2, adminThresholdN: 3 });
  await seedDefaultBindings(ds, uuid, 'vtc');
  const app: FastifyInstance = Fastify();
  registerTrustTaskRoutes(app, ds, { now: () => START, defaultVid: SERVER_DID, extraHandlers: [ping], ...options });
  await app.ready();
  return { app, ds };
}
const post = (app: FastifyInstance, body: unknown) =>
  app.inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
const base = (over: Record<string, unknown> = {}) => ({ id: 'urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', type: PING, issuer: PEER.did, recipient: SERVER_DID, issuedAt: T, payload: {}, ...over });
const sign = (d: Record<string, unknown>, who = PEER, purpose?: string) => signDocument(d, who, { created: START, ...(purpose === undefined ? {} : { purpose }) });
const code = (res: { json: () => { payload?: { code?: string } } }) => res.json().payload?.code;

test('a signed request to the server is accepted and the reply is signed by the server as #key-1 under authentication (Tier 1)', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 1 });
  const res = await post(app, sign(base()));
  assert.equal(res.statusCode, 200);
  const reply = res.json();
  assert.equal(reply.issuer, SERVER_DID);
  assert.equal(reply.proof.verificationMethod, `${SERVER_DID}#key-1`);
  assert.equal(reply.proof.proofPurpose, 'authentication');
  assert.match(reply.proof.created, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
  const verdict = await checker.verify(reply, { nowMs: START });
  assert.equal(verdict.valid, true, verdict.detail);
});

test('Tier 1: an unsigned request to a task that does not require a proof is still accepted; the reply is signed', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 1 });
  const res = await post(app, base());
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().proof);
});

test('a tampered proof is proofInvalid (422) and the handler does not run; the error is signed', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 1 });
  const res = await post(app, { ...sign(base()), payload: { changed: true } });
  assert.equal(res.statusCode, 422);
  assert.equal(code(res), 'proofInvalid');
  assert.equal((await checker.verify(res.json(), { nowMs: START })).valid, true, 'the error reply is signed too');
});

test('a did:scid:vh issuer whose log the server does not hold is unavailable (503, retryable), never proofInvalid', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 1, verifier: undefined });
  const stranger = createEd25519BoundarySigner({ did: 'did:scid:vh:1:zQmStrangerStrangerStrangerStrangerStranger', secretKey: new Uint8Array(32).fill(8) });
  const res = await post(app, signDocument(base({ issuer: stranger.did }), stranger, { created: START }));
  assert.equal(res.statusCode, 503);
  assert.equal(code(res), 'unavailable');
  assert.equal(res.json().payload.retryable, true);
});

test('Tier 2 (attested): a request without a proof is proofRequired; the purpose is pinned to authentication; every reply is signed', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 2, verifier: new DidProofVerifier({ resolver: new DidKeyResolver() }) });
  const unsigned = await post(app, base());
  assert.equal(unsigned.statusCode, 422);
  assert.equal(code(unsigned), 'proofRequired');
  assert.equal((await checker.verify(unsigned.json(), { nowMs: START })).valid, true);
  const assertion = await post(app, sign(base({ id: 'urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }), PEER, 'assertionMethod'));
  assert.equal(code(assertion), 'proofInvalid');
  const ok = await post(app, sign(base({ id: 'urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc' })));
  assert.equal(ok.statusCode, 200);
  assert.equal((await checker.verify(ok.json(), { nowMs: START })).valid, true);
});

test('Tier 2 fails closed: a reply issued as a hosted community (no boundary signer for it) is never sent unsigned', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 2, verifier: new DidProofVerifier({ resolver: new DidKeyResolver() }) });
  const res = await post(app, sign({ id: 'urn:uuid:dddddddd-dddd-4ddd-8ddd-dddddddddddd', type: POLICY_EVALUATE_WIRE_TYPE, issuer: PEER.did, recipient: CLUB_DID, issuedAt: T, payload: { action: 'register_name' } }));
  assert.equal(res.statusCode, 503);
  assert.equal(res.json().proof, undefined);
  assert.equal(res.json().code, 'unavailable');
});

test('Tier 1: a signed evaluate request for a hosted community is accepted; its reply (issued as the community) is not signed', async () => {
  const { app } = await seed({ signer: serverSigner, tier: 1 });
  const res = await post(app, sign({ id: 'urn:uuid:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee', type: POLICY_EVALUATE_WIRE_TYPE, issuer: PEER.did, recipient: CLUB_DID, issuedAt: T, payload: { action: 'register_name' } }));
  assert.equal(res.statusCode, 200);
  assert.equal(res.json().issuer, CLUB_DID);
  assert.equal(res.json().proof, undefined);
});

test('the default answering identifier is the server DID recorded at startup (no defaultVid option)', async () => {
  setServerNodeDid('did:scid:vh:recorded-server');
  const { app } = await seed({ defaultVid: undefined, tier: 1 });
  const res = await post(app, base({ recipient: 'did:scid:vh:somebody-else' }));
  assert.equal(code(res), 'wrongRecipient');
  assert.equal(res.json().issuer, 'did:scid:vh:recorded-server');
});
