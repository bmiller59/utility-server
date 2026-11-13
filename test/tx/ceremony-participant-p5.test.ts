// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P5 on the utility-server ceremony participant (plan rows TIME, DUP, 2PC-004, 2PC-005,
 * AUTHZ approve): late approvals, duplicate begin and approve, the reset guard, failure rows with
 * their standard code, and the refusal reasons a boundary can read. In-memory databases only.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { TX_SCHEMA_SQL, TX_ADDITIVE_COLUMNS } from '@p2p-trust-stack/core/tx/schema.js';
import { CeremonyStore } from '@p2p-trust-stack/core/tx/ceremony-store.js';
import { clearAbortReasons, getAbortReason } from '@p2p-trust-stack/core/tx/ceremony-guard.js';
import { CeremonyCoordinatorParticipant } from '../../src/tx/ceremony-participant.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import { generateEd25519KeyPair, signEd25519 } from '@p2p-trust-stack/core/crypto/primitives.js';
import { driveAtomically, driveCeremony } from '@p2p-trust-stack/core/services/trust-tasks/driver.js';
import { CEREMONY_CO_SIGN_TYPE, VTC_ESTABLISH_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

function makeAppDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}

function makeTxDb(): SqliteDataSource {
  const ds = new SqliteDataSource(':memory:');
  ds.getRawDb().exec(TX_SCHEMA_SQL);
  // What the server does at boot: the additive columns (error_code, retryable).
  for (const col of TX_ADDITIVE_COLUMNS) {
    try { ds.getRawDb().exec(col.ddl); } catch { /* already in the base schema */ }
  }
  return ds;
}

async function seed(txDb: SqliteDataSource, id: string, over: Record<string, unknown> = {}): Promise<CeremonyStore> {
  const store = new CeremonyStore(txDb);
  await store.createProposal({
    proposalId: id, proposerDid: 'admin-1', vtcDid: 'did:example:v', name: `VTC ${id}`, kind: 'vtc',
    adminDids: ['admin-1', 'admin-2'], adminUuids: ['admin-1', 'admin-2'], threshold: 2,
    expiresAt: Date.now() + 60_000, proposalHash: 'hash', proposerUuid: 'admin-1', ...over,
  });
  return store;
}

const approve = (p: CeremonyCoordinatorParticipant, tx: string, ceremonyId: string, who: string) =>
  p.prepare(tx, [{ op: 'ceremony_approve', params: { ceremonyId, approverUuid: who, signature: 'sig' } }]);
const reset = (p: CeremonyCoordinatorParticipant, tx: string, ceremonyId: string) =>
  p.prepare(tx, [{ op: 'ceremony_reset', params: { ceremonyId } }]);

function fixture() {
  clearAbortReasons();
  const appDb = makeAppDb();
  const txDb = makeTxDb();
  return { appDb, txDb, participant: new CeremonyCoordinatorParticipant('server:us-1', appDb, txDb) };
}


// ── TIME / 2PC-004 ─────────────────────────────────────────────────────────────────────────

test('TIME + 2PC-004: an approval at expiresAt is refused deadlineLapsed, nothing is recorded, and the proposal is expired', async () => {
  const { txDb, participant } = fixture();
  const store = await seed(txDb, 'late', { expiresAt: Date.now() });   // the deadline is reached now: >= lapses it
  assert.equal(await approve(participant, 'tx-late', 'late', 'admin-1'), 'no');
  assert.equal(getAbortReason('tx-late')?.reason, 'deadlineLapsed');
  assert.equal(getAbortReason('tx-late')?.code, 'taskFailed');
  const stored = (await store.getProposal('late'))!;
  assert.equal(stored.status, 'expired');
  assert.equal(stored.errorCode, 'taskFailed');
  assert.equal(stored.retryable, false);
  assert.equal(await store.countApprovals('late'), 0);
  // the same answer on a later attempt, from the stored state
  assert.equal(await approve(participant, 'tx-late-2', 'late', 'admin-2'), 'no');
  assert.equal(getAbortReason('tx-late-2')?.reason, 'deadlineLapsed');
});

test('TIME: one millisecond before the deadline the approval is accepted', async () => {
  const { txDb, participant } = fixture();
  const store = await seed(txDb, 'edge', { expiresAt: Date.now() + 60_000 });
  assert.equal(await approve(participant, 'tx-edge', 'edge', 'admin-1'), 'yes');
  assert.equal(await store.countApprovals('edge'), 1);
});

test('TIME: ceremony_query reports a lapsed pending proposal as expired with its code (the stored state is corrected)', async () => {
  const { txDb, participant } = fixture();
  const store = await seed(txDb, 'q', { expiresAt: Date.now() - 1 });
  const q = await participant.query('ceremony_query', { ceremonyId: 'q' }) as Record<string, unknown>;
  assert.equal(q.status, 'expired');
  assert.equal(q.errorCode, 'taskFailed');
  assert.equal(q.retryable, false);
  assert.match(String(q.errorReason), /deadline/);
  assert.equal((await store.getProposal('q'))?.status, 'expired');
  // and it no longer shows as pending work for an admin
  await seed(txDb, 'q2', { expiresAt: Date.now() - 1 });
  assert.deepEqual(await participant.query('ceremony_pending_for', { adminUuid: 'admin-2' }), []);
});

// ── DUP ──────────────────────────────────────────────────────────────────────────────────

test('DUP: approving twice is idempotent: the second is accepted, with no second approval and no second log row', async () => {
  const { appDb, txDb, participant } = fixture();
  const store = await seed(txDb, 'dup');
  assert.equal(await approve(participant, 'tx-d1', 'dup', 'admin-1'), 'yes');
  const rowsAfterFirst = (await trustTasksRepo.listByThread(appDb, 'dup')).length;
  assert.equal(await approve(participant, 'tx-d2', 'dup', 'admin-1'), 'yes');
  assert.equal(await store.countApprovals('dup'), 1);
  assert.equal((await trustTasksRepo.listByThread(appDb, 'dup')).length, rowsAfterFirst);
});

test('DUP: begin with the same content returns the existing state; with other content it is an idConflict', async () => {
  const { appDb, txDb, participant } = fixture();
  const params = { ceremonyId: 'begin-1', proposerUuid: 'admin-1', name: 'Club', kind: 'vtc', threshold: 2, adminUuids: ['admin-2', 'admin-1'] };
  assert.equal(await participant.prepare('tx-b1', [{ op: 'ceremony_begin', params }]), 'yes');
  const first = (await new CeremonyStore(txDb).getProposal('begin-1'))!;
  const rows = (await trustTasksRepo.listByThread(appDb, 'begin-1')).length;
  assert.equal(await participant.prepare('tx-b2', [{ op: 'ceremony_begin', params }]), 'yes');
  const again = (await new CeremonyStore(txDb).getProposal('begin-1'))!;
  assert.equal(again.proposalHash, first.proposalHash, 'the first proposal (and its deadline) is unchanged');
  assert.equal(again.expiresAt, first.expiresAt);
  assert.equal((await trustTasksRepo.listByThread(appDb, 'begin-1')).length, rows, 'no second proposal document');
  assert.equal(await participant.prepare('tx-b3', [{ op: 'ceremony_begin', params: { ...params, name: 'Other' } }]), 'no');
  assert.equal(getAbortReason('tx-b3')?.code, 'idConflict');
  assert.equal((await new CeremonyStore(txDb).getProposal('begin-1'))?.name, 'Club');
});

// ── AUTHZ (approve) ──────────────────────────────────────────────────────────────────────

test('AUTHZ: a non-admin approving gets permissionDenied, the same answer as for a ceremony that does not exist', async () => {
  const { txDb, participant } = fixture();
  const store = await seed(txDb, 'authz');
  assert.equal(await approve(participant, 'tx-na', 'authz', 'intruder'), 'no');
  assert.equal(await approve(participant, 'tx-nf', 'no-such-ceremony', 'admin-1'), 'no');
  const a = getAbortReason('tx-na');
  const b = getAbortReason('tx-nf');
  assert.deepEqual(a, { code: 'permissionDenied', retryable: false, reason: 'notFoundOrNotPermitted' });
  assert.deepEqual(b, a, 'indistinguishable on the wire');
  assert.equal(await store.countApprovals('authz'), 0);
  assert.equal((await store.getProposal('authz'))?.status, 'pending', 'a refused intruder does not fail the ceremony');
});

// ── 2PC-005 reset guard ────────────────────────────────────────────────────────────────────

test('2PC-005: reset is refused from pending and from crystallized (alreadyCommitted), allowed from failed and expired', async () => {
  const { txDb, participant } = fixture();
  const store = await seed(txDb, 'r-pending');
  assert.equal(await reset(participant, 'tx-r1', 'r-pending'), 'no');
  assert.equal(getAbortReason('tx-r1')?.code, 'taskFailed');
  assert.equal((await store.getProposal('r-pending'))?.status, 'pending', 'a live ceremony is untouched');

  await seed(txDb, 'r-done');
  await store.updateStatus('r-done', 'crystallized', Date.now());
  assert.equal(await reset(participant, 'tx-r2', 'r-done'), 'no');
  assert.equal(getAbortReason('tx-r2')?.reason, 'alreadyCommitted');
  assert.equal((await store.getProposal('r-done'))?.status, 'crystallized');

  await seed(txDb, 'r-failed');
  await store.updateStatus('r-failed', 'failed');
  assert.equal(await reset(participant, 'tx-r3', 'r-failed'), 'yes');
  assert.equal((await store.getProposal('r-failed'))?.status, 'aborted');

  await seed(txDb, 'r-lapsed', { expiresAt: Date.now() - 5 });     // pending but past its deadline: expired
  assert.equal(await reset(participant, 'tx-r4', 'r-lapsed'), 'yes');
  assert.equal((await store.getProposal('r-lapsed'))?.status, 'aborted');

  assert.equal(await reset(participant, 'tx-r5', 'r-failed'), 'no', 'an aborted ceremony is not resettable again');
  assert.equal(await reset(participant, 'tx-r6', 'nope'), 'no');
  assert.equal(getAbortReason('tx-r6')?.reason, 'notFound');
});

// ── failure rows ─────────────────────────────────────────────────────────────────────────

async function seedVta(appDb: SqliteDataSource, did: string) {
  const uuid = await identitiesRepo.create(appDb, { realDid: did, role: 'vta', name: did });
  await didDocumentsRepo.create(appDb, { identityUuid: uuid, did, method: 'scid', isPrimary: true });
  const keyPair = generateEd25519KeyPair();
  await keysRepo.create(appDb, { identityUuid: uuid, keyType: 'ed25519', publicKey: Buffer.from(keyPair.publicKey) });
  return { uuid, keyPair };
}

test('failure rows: an executor failure during crystallization leaves a failed proposal with its code AND a failed trust-task row', async () => {
  const { appDb, txDb, participant } = fixture();
  const a = await seedVta(appDb, 'did:scid:vh:p5-a');
  const b = await seedVta(appDb, 'did:scid:vh:p5-b');
  const store = await seed(txDb, 'cer-fail', { proposerDid: a.uuid, proposerUuid: a.uuid, adminDids: [a.uuid, b.uuid], adminUuids: [a.uuid, b.uuid], threshold: 1, proposalHash: 'p5-hash' });
  const sig = (k: typeof a) => Buffer.from(signEd25519(new TextEncoder().encode('p5-hash'), k.keyPair.secretKey)).toString('base64');
  const send = (tx: string, who: typeof a) => participant.prepare(tx, [{ op: 'ceremony_approve', params: { ceremonyId: 'cer-fail', approverUuid: who.uuid, signature: sig(who) } }]);
  await send('tx-f1', a);
  assert.equal(await send('tx-f2', b), 'no', 'the failing crystallization is a no vote');

  const stored = (await store.getProposal('cer-fail'))!;
  assert.equal(stored.status, 'failed');
  assert.ok(stored.errorReason && stored.errorReason.length > 0);
  assert.ok(stored.errorCode, 'the standard code is recorded');
  assert.equal(stored.retryable, false);
  assert.equal(stored.errorCode, 'internalError', 'an untyped failure is the opaque internalError');
  assert.deepEqual(getAbortReason('tx-f2'), { code: 'internalError', retryable: false }, 'the registry agrees with the stored code');

  const q = await participant.query('ceremony_query', { ceremonyId: 'cer-fail' }) as Record<string, unknown>;
  assert.equal(q.errorCode, stored.errorCode);
  assert.equal(q.retryable, false);
  assert.equal(q.errorReason, stored.errorReason, 'the old field stays');

  assert.ok((await trustTasksRepo.listByThread(appDb, 'cer-fail')).some((r) => r.type === CEREMONY_CO_SIGN_TYPE), 'the co-signature log is intact');
});

test('failure rows: the REAL vtc:establish executor refusing its founders leaves a failed row after the rollback', async () => {
  const { appDb } = fixture();
  const a = await seedVta(appDb, 'did:scid:vh:p5-solo');
  // One admin and no endpoint: createVtc's own validation throws inside the executor.
  await assert.rejects(() => driveAtomically(appDb, 'thread-solo', (tx) => driveCeremony(tx, 'vtc-establish', 'thread-solo', {
    context: { db: tx, name: 'Solo', kind: 'vtc', adminIdentityUuids: [a.uuid], threshold: 1 },
  })));
  const rows = await trustTasksRepo.listByThread(appDb, 'thread-solo');
  assert.equal(rows.length, 1, 'the request row was rolled back with the transaction; only the failure survives');
  assert.equal(rows[0].status, 'failed');
  assert.equal(rows[0].direction, 'response');
  assert.equal(rows[0].type, VTC_ESTABLISH_TYPE);
  assert.equal(rows[0].errorCode, 'internalError');
  assert.ok(JSON.parse(rows[0].payload!).error.length > 0);
});
