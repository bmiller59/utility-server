// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The operator tool for the server's dedicated #key-boundary key: provision, publish, rotate, retire,
 * destroy, status. Real server-shaped identity (Slot-A, seeded), real key store, real rotation-log store.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/services/boundary-key-admin.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { DidResolutionService } from '@p2p-trust-stack/core/did/did-resolution-service.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { generateEd25519KeyPairFromSeed } from '@p2p-trust-stack/core/crypto/primitives.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { BoundaryKeyError, loadBoundaryKey } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { YugabyteRotationLogStore } from '../../src/db/yugabyte-rotation-log-store.js';
import { loadServerBoundaryIdentity, readPublishedBoundaryKey, runBoundaryAdmin, withPublishedBoundaryKey } from '../../src/services/boundary-key-admin.js';
import type { BoundaryAdminContext } from '../../src/services/boundary-key-admin.js';
import { parseArgs, runCli } from '../../src/scripts/boundary-key.js';

const PASS = 'test-passphrase-not-a-secret';
const DID_SEED_HEX = '11'.repeat(32);

async function server() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x22));
  const created = await new ScidVhMethod().create({ peerId: 'peer', multiaddrs: [] }, { identitySeed: new Uint8Array(32).fill(0x11), transportSigningKeyPair: tsp });
  const uuid = didToUuid(created.did);
  await identitiesRepo.create(ds, { uuid, realDid: created.did, role: 'vta', subjectKind: 'organization', custody: 'local', name: 'utility-server', recordedByNode: 'test' });
  const docUuid = await didDocumentsRepo.create(ds, { identityUuid: uuid, did: created.did, method: 'did:scid:vh', documentJson: JSON.stringify(created.document), isPrimary: true, recordedByNode: 'test' });
  for (const e of created.log) await new YugabyteRotationLogStore(ds).appendEntry(docUuid, e);
  const keystore = new SqliteKeyStore(':memory:');
  const identity = await loadServerBoundaryIdentity({ db: ds, nodeName: 'utility-server', configJson: { identity: { didSeedHex: DID_SEED_HEX } }, passphrase: PASS });
  const ctx = (over: Partial<BoundaryAdminContext> = {}): BoundaryAdminContext => ({ db: ds, keystore, passphrase: PASS, identity, execute: true, ...over });
  const logLen = async () => (await new YugabyteRotationLogStore(ds).getLog(docUuid)).length;
  return { ds, keystore, identity, ctx, did: created.did, docUuid, logLen, local: created.document };
}

test('refuses without the passphrase: no default, nothing opened or written', async () => {
  const s = await server();
  await assert.rejects(runBoundaryAdmin('provision', s.ctx({ passphrase: undefined }), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'config' && /TSP_SEED_PASSPHRASE/.test(e.message));
  await assert.rejects(runBoundaryAdmin('status', s.ctx({ passphrase: '' })), (e: BoundaryKeyError) => e.code === 'config');
  const out: string[] = []; const err: string[] = [];
  assert.equal(await runCli(['provision', '--generation', '1', '--execute'], {}, (l) => out.push(l), (l) => err.push(l), { keystore: s.keystore }), 1);
  assert.deepEqual(out, []);
  assert.match(err[0]!, /TSP_SEED_PASSPHRASE is required/);
  await assert.rejects(loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === 'missing');
});

test('dry run is the default and writes nothing; execute provisions; a generation is never overwritten', async () => {
  const s = await server();
  const dry = await runBoundaryAdmin('provision', s.ctx({ execute: false }), { generation: 1 });
  assert.equal(dry.executed, false);
  await assert.rejects(loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === 'missing');
  const done = await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  assert.equal(done.executed, true);
  assert.match(done.fingerprint!, /^[0-9a-f]{16}$/);
  const before = await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 });
  await assert.rejects(runBoundaryAdmin('provision', s.ctx(), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'exists');
  await assert.rejects(runBoundaryAdmin('provision', s.ctx({ execute: false }), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'exists');
  const after = await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 });
  assert.deepEqual(after.secretKey, before.secretKey);
});

test('publish: dry run builds and validates but appends nothing; execute appends one entry that resolves from the log; republishing is refused', async () => {
  const s = await server();
  await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  const n = await s.logLen();
  // an entry signed in the past exercises the stored createdAt (the cutover does not go through the POST route)
  const past = Date.now() - 3_600_000;
  const dry = await runBoundaryAdmin('publish', s.ctx({ execute: false, now: past }), { generation: 1 });
  assert.equal(dry.version, n, 'the entry that would be appended is validated and numbered');
  assert.equal(await s.logLen(), n);
  const done = await runBoundaryAdmin('publish', s.ctx({ now: past }), { generation: 1 });
  assert.equal(await s.logLen(), n + 1);
  const report = await new DidResolutionService(s.ds).resolve(s.did);
  assert.equal(report.source, 'log', 'resolves from the log with the signed createdAt');
  assert.equal(report.result.didResolutionMetadata.chainValid, true);
  const doc = report.result.didDocument!;
  assert.ok(doc.verificationMethod.some((v) => v.id === '#key-boundary'));
  assert.ok(doc.authentication.includes('#key-boundary'));
  const held = await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 });
  assert.deepEqual(await readPublishedBoundaryKey(s.ds, s.docUuid), held.publicKey);
  assert.equal(done.version, n);
  await assert.rejects(runBoundaryAdmin('publish', s.ctx(), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'exists');
  assert.equal(await s.logLen(), n + 1);
});

test('publish without a provisioned key fails closed (missing) and writes nothing; a wrong passphrase is corrupt', async () => {
  const s = await server();
  const n = await s.logLen();
  await assert.rejects(runBoundaryAdmin('publish', s.ctx(), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'missing');
  await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  await assert.rejects(runBoundaryAdmin('publish', s.ctx({ passphrase: 'another-passphrase' }), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'corrupt');
  assert.equal(await s.logLen(), n);
});

test('rotate replaces the key with a NEW generation only; same generation, a missing publication and a missing key are refused', async () => {
  const s = await server();
  await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  await runBoundaryAdmin('provision', s.ctx(), { generation: 2 });
  await assert.rejects(runBoundaryAdmin('rotate', s.ctx(), { generation: 2 }), (e: BoundaryKeyError) => e.code === 'notPublished', 'rotate needs a first publication');
  await runBoundaryAdmin('publish', s.ctx(), { generation: 1 });
  await assert.rejects(runBoundaryAdmin('rotate', s.ctx(), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'exists');
  await assert.rejects(runBoundaryAdmin('rotate', s.ctx(), { generation: 3 }), (e: BoundaryKeyError) => e.code === 'missing');
  const n = await s.logLen();
  const r = await runBoundaryAdmin('rotate', s.ctx(), { generation: 2 });
  assert.equal(await s.logLen(), n + 1);
  assert.match(r.note, /BOUNDARY_KEY_GENERATION=2/);
  const g2 = await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 2 });
  assert.deepEqual(await readPublishedBoundaryKey(s.ds, s.docUuid), g2.publicKey);
  assert.equal((await new DidResolutionService(s.ds).resolve(s.did)).source, 'log');
});

test('retire removes #key-boundary and only that; retiring again is refused; destroy refuses the published generation', async () => {
  const s = await server();
  await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  await runBoundaryAdmin('publish', s.ctx(), { generation: 1 });
  await assert.rejects(runBoundaryAdmin('destroy', s.ctx(), { generation: 1 }), (e: BoundaryKeyError) => e.code === 'exists');
  const dry = await runBoundaryAdmin('retire', s.ctx({ execute: false }));
  assert.equal(dry.executed, false);
  assert.notEqual(await readPublishedBoundaryKey(s.ds, s.docUuid), null);
  await runBoundaryAdmin('retire', s.ctx());
  assert.equal(await readPublishedBoundaryKey(s.ds, s.docUuid), null);
  const doc = (await new DidResolutionService(s.ds).resolve(s.did)).result.didDocument!;
  assert.ok(doc.verificationMethod.some((v) => v.id === '#key-1'));
  assert.ok(doc.verificationMethod.some((v) => v.id === '#key-scid'));
  await assert.rejects(runBoundaryAdmin('retire', s.ctx()), (e: BoundaryKeyError) => e.code === 'notPublished');
  assert.equal((await runBoundaryAdmin('destroy', s.ctx({ execute: false }), { generation: 1 })).executed, false);
  await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 });
  await runBoundaryAdmin('destroy', s.ctx(), { generation: 1 });
  await assert.rejects(loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 }), (e: BoundaryKeyError) => e.code === 'missing');
});

test('status and every result carry no key material: no secret, no public key, only fingerprints', async () => {
  const s = await server();
  const lines: string[] = [];
  for (const [cmd, gen] of [['provision', 1], ['publish', 1], ['status', undefined]] as const) {
    lines.push(JSON.stringify(await runBoundaryAdmin(cmd, s.ctx(), gen === undefined ? {} : { generation: gen })));
  }
  const key = await loadBoundaryKey({ store: s.keystore, vid: s.did, passphrase: PASS, generation: 1 });
  const all = lines.join('\n');
  for (const bytes of [key.secretKey, key.publicKey, s.identity.identityKeyPair.secretKey]) {
    assert.equal(all.includes(Buffer.from(bytes).toString('hex')), false);
    assert.equal(all.includes(Buffer.from(bytes).toString('base64')), false);
  }
  assert.equal(all.includes(PASS), false);
  const status = JSON.parse(lines[2]!);
  assert.deepEqual(status.generationsHeld, [1]);
  assert.ok(status.published.fingerprint);
});

test('the server runtime document gains #key-boundary only from its own published log, and nothing else of it', async () => {
  const s = await server();
  const none = await withPublishedBoundaryKey(s.ds, s.docUuid, s.local);
  assert.deepEqual(none, s.local, 'unpublished: the local document is unchanged');
  await runBoundaryAdmin('provision', s.ctx(), { generation: 1 });
  await runBoundaryAdmin('publish', s.ctx(), { generation: 1 });
  const merged = await withPublishedBoundaryKey(s.ds, s.docUuid, s.local);
  assert.ok(merged.verificationMethod.some((v) => v.id === '#key-boundary'));
  assert.ok(merged.authentication.includes('#key-boundary'));
  assert.deepEqual(merged.verificationMethod.filter((v) => v.id !== '#key-boundary'), s.local.verificationMethod);
  assert.deepEqual(merged.service, s.local.service);
});

test('a server without identity.didSeedHex is refused (the chain key is never guessed)', async () => {
  const s = await server();
  await assert.rejects(loadServerBoundaryIdentity({ db: s.ds, nodeName: 'utility-server', configJson: {}, passphrase: PASS }), (e: BoundaryKeyError) => e.code === 'config');
  await assert.rejects(loadServerBoundaryIdentity({ db: s.ds, nodeName: 'nobody', configJson: { identity: { didSeedHex: DID_SEED_HEX } }, passphrase: PASS }), (e: BoundaryKeyError) => e.code === 'config');
});

test('CLI: argument parsing is strict; the passphrase is never an argument', async () => {
  assert.deepEqual(parseArgs(['publish', '--generation', '2', '--execute']), { command: 'publish', generation: 2, execute: true });
  assert.deepEqual(parseArgs(['status']), { command: 'status', execute: false });
  for (const bad of [[], ['nope'], ['publish'], ['status', '--generation', '1'], ['publish', '--generation', '0'], ['publish', '--generation', 'x'], ['provision', '--generation', '1', '--passphrase', 'x']]) {
    assert.throws(() => parseArgs(bad), Error, JSON.stringify(bad));
  }
  const s = await server();
  const out: string[] = []; const err: string[] = [];
  const env = { TSP_SEED_PASSPHRASE: PASS };
  const deps = { configJson: { identity: { didSeedHex: DID_SEED_HEX } }, openDb: async () => ({ db: s.ds, close: async () => {} }) };
  const ks = s.keystore; const realClose = ks.close.bind(ks); ks.close = () => {};
  try {
    assert.equal(await runCli(['provision', '--generation', '1'], env, (l) => out.push(l), (l) => err.push(l), { ...deps, keystore: ks }), 0);
    assert.equal(JSON.parse(out[0]!).executed, false, 'dry run by default');
    assert.equal(await runCli(['provision', '--generation', '1', '--execute'], env, (l) => out.push(l), (l) => err.push(l), { ...deps, keystore: ks }), 0);
    assert.equal(await runCli(['provision', '--generation', '1', '--execute'], env, (l) => out.push(l), (l) => err.push(l), { ...deps, keystore: ks }), 1);
    assert.match(err.at(-1)!, /^refused: .*never overwritten/);
  } finally { realClose(); }
});
