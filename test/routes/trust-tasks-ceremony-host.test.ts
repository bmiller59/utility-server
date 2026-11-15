// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Item 1 on the utility server: signed founding-ceremony documents posted to `POST /trust-tasks` run against the REAL host
 * (core ceremony-doc handlers and participant, this server's effect over the real `createVtc`, a real two-phase-commit
 * coordinator), in-memory databases. Approvals count by the pipeline-verified proof (D1.1); the effect is checked at
 * prepare and applied at commit (D1.3); the fan-out is queued once per community. With the host off (the default) the
 * ceremony types are not served.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks-ceremony-host.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { ed25519 } from '@noble/curves/ed25519.js';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as peerEndpointsRepo from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_ADDITIVE_COLUMNS, TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/index.js';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { clearAbortReasons } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import type { EstablishedCommunity } from '@p2p-trust-stack/core/services/founding/community-effect.js';
import { registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { ceremonyHostRequested, createCeremonyHost } from '../../src/services/ceremony-host.js';

const SERVER_DID = 'did:scid:vh:server';
const START = Date.parse('2026-11-12T10:00:00Z');
const T = '2026-11-12T10:00:00Z';

const keyOf = (byte: number) => {
  const secretKey = new Uint8Array(32).fill(byte);
  return createEd25519BoundarySigner({ did: didKeyFromEd25519(ed25519.getPublicKey(secretKey)), secretKey, fragment: didKeyFromEd25519(ed25519.getPublicKey(secretKey)).slice('did:key:'.length) });
};
const ADMIN_A = keyOf(11);
const ADMIN_B = keyOf(12);
const OUTSIDER = keyOf(13);
const serverSigner = createEd25519BoundarySigner({ did: SERVER_DID, secretKey: new Uint8Array(32).fill(6) });

async function seedAdmin(db: SqliteDataSource, did: string): Promise<string> {
  const uuid = await identitiesRepo.create(db, { realDid: did, role: 'vta', subjectKind: 'human', name: did.slice(-8) });
  await didDocumentsRepo.create(db, { identityUuid: uuid, did, method: 'key', isPrimary: true });
  await peerEndpointsRepo.upsertForIdentity(db, { identityUuid: uuid, peerId: `peer-${uuid}`, multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  return uuid;
}

async function world(opts: { host?: boolean } = {}) {
  clearAbortReasons();
  const db = new SqliteDataSource(':memory:');
  runMigrations(db.getRawDb(), getMigrationsDir());
  const txDb = new SqliteDataSource(':memory:');
  txDb.getRawDb().exec(TX_SCHEMA_SQL);
  for (const col of TX_ADDITIVE_COLUMNS) { try { txDb.getRawDb().exec(col.ddl); } catch { /* present */ } }
  const a = await seedAdmin(db, ADMIN_A.did);
  const b = await seedAdmin(db, ADMIN_B.did);
  await relationshipsRepo.create(db, { localIdentityUuid: a, remoteIdentityUuid: b, direction: 'bidirectional', status: 'established' });
  const txm = new TransactionManager(new TransactionCoordinator(new TransactionLog(new DataSourceLogSink(txDb))), new CompensationExecutor());
  const fanouts: EstablishedCommunity[] = [];
  const host = opts.host === false ? undefined : createCeremonyHost({ appDb: db, txDb, txManager: txm, fanout: async (c) => { fanouts.push(c); } });
  const app: FastifyInstance = Fastify();
  registerTrustTaskRoutes(app, db, {
    now: () => START, defaultVid: SERVER_DID, signer: serverSigner, tier: 1,
    ...(host === undefined ? {} : { extraHandlers: host.handlers, guard: host.guard }),
  });
  await app.ready();
  return { app, db, txDb, txm, host, fanouts };
}

const post = (app: FastifyInstance, body: unknown) =>
  app.inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'application/json' }, payload: JSON.stringify(body) });
const uuid = () => `urn:uuid:${randomUUID()}`;
const doc = (who: ReturnType<typeof keyOf>, type: string, thread: string, payload: Record<string, unknown>, id = uuid()) =>
  ({ id, threadId: thread, type, issuer: who.did, recipient: SERVER_DID, issuedAt: T, payload });
const signed = (who: ReturnType<typeof keyOf>, type: string, thread: string, payload: Record<string, unknown> = {}, id = uuid()) =>
  signDocument(doc(who, type, thread, payload, id), who, { created: START });
const begin = (who: ReturnType<typeof keyOf>, thread: string, name = 'Route Club') =>
  signed(who, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name, kind: 'vtc', threshold: 2, adminDids: [ADMIN_A.did, ADMIN_B.did] });
const cosign = (who: ReturnType<typeof keyOf>, thread: string) => signed(who, CEREMONY_CO_SIGN_WIRE_TYPE, thread);
const communities = async (db: SqliteDataSource) => (await db.get<{ n: number }>("SELECT COUNT(*) AS n FROM identities WHERE role IN ('vtc','vtn')"))!.n;

test('signed ceremony documents posted to POST /trust-tasks found one real community; the quorum reply is a #response and the fan-out is queued once', async () => {
  const { app, db, fanouts } = await world();
  const thread = uuid();
  const opened = await post(app, begin(ADMIN_A, thread));
  assert.equal(opened.statusCode, 200);
  assert.equal(opened.json().payload.continuation, 'proceed');
  assert.deepEqual(opened.json().payload.ext.quorum, { required: 2, received: 0 });

  const first = await post(app, cosign(ADMIN_A, thread));
  assert.equal(first.json().payload.ext.quorum.received, 1);
  assert.equal(await communities(db), 0, 'nothing is established before the quorum');

  const last = await post(app, cosign(ADMIN_B, thread));
  assert.equal(last.statusCode, 200);
  assert.equal(last.json().type, `${CEREMONY_CO_SIGN_WIRE_TYPE}#response`);
  assert.equal(last.json().payload.status, 'crystallized');
  assert.equal(await communities(db), 1);
  assert.equal(fanouts.length, 1);
  assert.equal(fanouts[0]!.foundingAdmins.length, 2);

  const status = await post(app, signed(ADMIN_A, CEREMONY_STATUS_WIRE_TYPE, thread));
  assert.equal(status.json().payload.status, 'crystallized');
});

test('D1.1: a co-sign whose proof does not verify is refused by the pipeline and never counts; the genuine one still completes the ceremony', async () => {
  const { app, db, host } = await world();
  const thread = uuid();
  await post(app, begin(ADMIN_A, thread));
  await post(app, cosign(ADMIN_A, thread));
  const forged = await post(app, { ...cosign(ADMIN_B, thread), id: uuid() });
  assert.equal(forged.statusCode, 422);
  assert.equal(forged.json().payload.code, 'proofInvalid');
  assert.equal((await host!.participant.store.getApprovals(thread)).length, 1);
  // Signed by the outsider, issued as B: the proof covers the issuer.
  const impostor = await post(app, { ...cosign(OUTSIDER, thread), issuer: ADMIN_B.did });
  assert.equal(impostor.json().payload.code, 'proofInvalid');
  assert.equal(await communities(db), 0);
  const real = await post(app, cosign(ADMIN_B, thread));
  assert.equal(real.json().payload.status, 'crystallized');
});

test('an unsigned co-sign is refused proofRequired (the co-sign type requires a proof), nothing recorded', async () => {
  const { app, host } = await world();
  const thread = uuid();
  await post(app, begin(ADMIN_A, thread));
  const res = await post(app, doc(ADMIN_B, CEREMONY_CO_SIGN_WIRE_TYPE, thread, {}));
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().payload.code, 'proofRequired');
  assert.equal((await host!.participant.store.getApprovals(thread)).length, 0);
});

test('a signer who is not on the ceremony and a ceremony that does not exist get the same refusal', async () => {
  const { app, db } = await world();
  const thread = uuid();
  await post(app, begin(ADMIN_A, thread));
  const outsider = await post(app, cosign(OUTSIDER, thread));
  const unknown = await post(app, cosign(ADMIN_A, uuid()));
  assert.equal(outsider.statusCode, 403);
  assert.equal(unknown.statusCode, 403);
  assert.equal(outsider.json().payload.details.reason, 'notFoundOrNotPermitted');
  assert.deepEqual(unknown.json().payload.details, outsider.json().payload.details);
  assert.equal(await communities(db), 0);
});

test('replay: the same co-sign delivered twice answers the same and founds one community', async () => {
  const { app, db, fanouts } = await world();
  const thread = uuid();
  await post(app, begin(ADMIN_A, thread));
  await post(app, cosign(ADMIN_A, thread));
  const last = cosign(ADMIN_B, thread);
  const first = await post(app, last);
  const again = await post(app, last);
  assert.equal(again.statusCode, first.statusCode);
  assert.equal(again.json().type, first.json().type);
  await post(app, cosign(ADMIN_B, thread));
  assert.equal(await communities(db), 1);
  assert.equal(fanouts.length, 1);
});

test('a taken name is refused nameTaken on the wire and leaves one community and a failed ceremony', async () => {
  const { app, db, host } = await world();
  const one = uuid();
  await post(app, begin(ADMIN_A, one, 'Dup Club')); await post(app, cosign(ADMIN_A, one)); await post(app, cosign(ADMIN_B, one));
  const two = uuid();
  await post(app, begin(ADMIN_A, two, 'dup club')); await post(app, cosign(ADMIN_A, two));
  const refused = await post(app, cosign(ADMIN_B, two));
  assert.equal(refused.statusCode, 422);
  assert.equal(refused.json().payload.details.reason, 'nameTaken');
  assert.equal(await communities(db), 1);
  assert.equal((await host!.participant.store.getProposal(two))!.status, 'failed');
});

test('a begin naming an admin this server does not hold is refused and stores nothing', async () => {
  const { app, host } = await world();
  const thread = uuid();
  const res = await post(app, signed(ADMIN_A, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name: 'Ghost Club', kind: 'vtc', threshold: 2, adminDids: [ADMIN_A.did, OUTSIDER.did] }));
  assert.equal(res.statusCode >= 400, true);
  assert.equal(await host!.participant.store.getProposal(thread), null);
});

test('crash between the apply and the status update: reconcile at boot finishes the ceremony without a second community', async () => {
  const { app, db, txDb, txm, host, fanouts } = await world();
  const thread = uuid();
  await post(app, begin(ADMIN_A, thread));
  await post(app, cosign(ADMIN_A, thread));
  const realUpdate = host!.participant.store.updateStatus.bind(host!.participant.store);
  host!.participant.store.updateStatus = async () => { throw new Error('process died'); };
  const res = await post(app, cosign(ADMIN_B, thread));
  assert.notEqual(res.json().payload.status, 'crystallized', 'the ceremony was not marked, so the reply is not a #response');
  assert.equal(await communities(db), 1, 'the establishment is durable');
  host!.participant.store.updateStatus = realUpdate;

  const rebooted = createCeremonyHost({ appDb: db, txDb, txManager: txm, fanout: async (c) => { fanouts.push(c); } });
  const result = await rebooted.reconcile();
  assert.equal(result.committed.length, 1);
  assert.equal(await communities(db), 1);
  assert.equal((await rebooted.participant.store.getProposal(thread))!.status, 'crystallized');
});

test('the host is off by default: with no host registered the ceremony types are not served', async () => {
  const { app, db } = await world({ host: false });
  const res = await post(app, begin(ADMIN_A, uuid()));
  assert.equal(res.statusCode >= 400, true);
  assert.equal(res.json().payload.code, 'unsupportedType');
  assert.equal(await communities(db), 0);
});

test('the opt-in flag: 1 serves, unset, empty and 0 do not, anything else is an error at startup', () => {
  assert.equal(ceremonyHostRequested({}), false);
  assert.equal(ceremonyHostRequested({ TRUST_TASKS_CEREMONY_HOST: '' }), false);
  assert.equal(ceremonyHostRequested({ TRUST_TASKS_CEREMONY_HOST: '0' }), false);
  assert.equal(ceremonyHostRequested({ TRUST_TASKS_CEREMONY_HOST: '1' }), true);
  assert.throws(() => ceremonyHostRequested({ TRUST_TASKS_CEREMONY_HOST: 'yes' }), /must be 1 or 0/);
});
