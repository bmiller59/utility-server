// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * K4: one document, three places. The `#key-boundary` method of the server's cached `did_documents.document_json`,
 * of the document served in the TSP handshake and of the rotation log head must agree at boot. Only the boundary
 * key is compared and repaired: the row carries live transport endpoints the log omits, and they are kept.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/services/boundary-document-sync.test.ts
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { didToUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { generateEd25519KeyPairFromSeed } from '@p2p-trust-stack/core/crypto/primitives.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { BoundaryKeyError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import { YugabyteRotationLogStore } from '../../src/db/yugabyte-rotation-log-store.js';
import { loadServerBoundaryIdentity, readPublishedBoundaryKey, runBoundaryAdmin } from '../../src/services/boundary-key-admin.js';
import type { BoundaryAdminContext } from '../../src/services/boundary-key-admin.js';
import { reconcileBoundaryKey } from '../../src/services/boundary-document-sync.js';

const PASS = 'test-passphrase-not-a-secret';
const LIVE_ENDPOINT = { id: '#live-transport', type: 'TspTransport', serviceEndpoint: 'https://live.example/tsp' };

async function server() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const tsp = generateEd25519KeyPairFromSeed(new Uint8Array(32).fill(0x22));
  const created = await new ScidVhMethod().create({ peerId: 'peer', multiaddrs: [] }, { identitySeed: new Uint8Array(32).fill(0x11), transportSigningKeyPair: tsp });
  const uuid = didToUuid(created.did);
  await identitiesRepo.create(ds, { uuid, realDid: created.did, role: 'vta', subjectKind: 'organization', custody: 'local', name: 'utility-server', recordedByNode: 'test' });
  // the cached row carries a live endpoint the log does not
  const local: DidDocument = { ...structuredClone(created.document), service: [...(created.document.service ?? []), LIVE_ENDPOINT] };
  const docUuid = await didDocumentsRepo.create(ds, { identityUuid: uuid, did: created.did, method: 'did:scid:vh', documentJson: JSON.stringify(local), isPrimary: true, recordedByNode: 'test' });
  for (const e of created.log) await new YugabyteRotationLogStore(ds).appendEntry(docUuid, e);
  const keystore = new SqliteKeyStore(':memory:');
  const identity = await loadServerBoundaryIdentity({ db: ds, nodeName: 'utility-server', configJson: { identity: { didSeedHex: '11'.repeat(32) } }, passphrase: PASS });
  const ctx = (over: Partial<BoundaryAdminContext> = {}): BoundaryAdminContext => ({ db: ds, keystore, passphrase: PASS, identity, execute: true, ...over });
  const publish = async (generation = 1) => {
    await runBoundaryAdmin('provision', ctx(), { generation });
    await runBoundaryAdmin('publish', ctx(), { generation });
  };
  const row = async () => (await ds.get<Record<string, unknown>>('SELECT * FROM did_documents WHERE uuid = ?', docUuid))!;
  const rowDoc = async (): Promise<DidDocument> => JSON.parse((await row()).document_json as string) as DidDocument;
  const sync = (over: { dedicated?: boolean; served?: DidDocument; warn?: (m: string) => void } = {}) =>
    reconcileBoundaryKey(ds, { didDocumentUuid: docUuid, did: created.did, served: over.served ?? local, dedicated: over.dedicated ?? true, ...(over.warn ? { warn: over.warn } : {}) });
  const tamperHead = async () => ds.run('UPDATE rotation_log SET created_at = created_at + 1 WHERE did_document_uuid = ? AND version = (SELECT MAX(version) FROM rotation_log WHERE did_document_uuid = ?)', docUuid, docUuid);
  return { ds, local, docUuid, did: created.did, publish, row, rowDoc, sync, tamperHead };
}

const boundary = (d: DidDocument) => d.verificationMethod.find((v) => v.id === '#key-boundary');
const withoutBoundary = (d: DidDocument) => ({ ...d, verificationMethod: d.verificationMethod.filter((v) => v.id !== '#key-boundary'), authentication: d.authentication.filter((a) => a !== '#key-boundary') });

test('stale document_json vs the log head: repaired, the live endpoint kept, nothing else in the row changes', async () => {
  const s = await server();
  await s.publish();
  const before = await s.row();
  assert.equal(boundary(await s.rowDoc()), undefined, 'the row is stale: no #key-boundary');
  const out = await s.sync();
  assert.equal(out.action, 'repaired');
  const after = await s.row();
  const doc = await s.rowDoc();
  const head = await readPublishedBoundaryKey(s.ds, s.docUuid);
  assert.ok(head);
  assert.ok(boundary(doc), 'the row now lists #key-boundary');
  assert.ok(doc.authentication.includes('#key-boundary'));
  assert.deepEqual(doc.service, s.local.service, 'live endpoints kept');
  assert.ok(doc.service?.some((x) => x.id === LIVE_ENDPOINT.id));
  assert.deepEqual(withoutBoundary(doc), s.local, 'everything but the boundary method is as before');
  assert.deepEqual({ ...after, document_json: null }, { ...before, document_json: null }, 'no other column of the row changes');
  assert.deepEqual(out.document, doc, 'the served document equals the repaired row');
  const again = await s.sync({ served: out.document });
  assert.equal(again.action, 'consistent');
  assert.deepEqual(await s.row(), after, 'a second boot writes nothing');
});

test('a row holding an older boundary key is repaired to the log head key; endpoints kept', async () => {
  const s = await server();
  await s.publish(1);
  await s.sync();
  const staleKey = boundary(await s.rowDoc())!;
  // rotate in the log through the admin path, leaving the row on the old key
  const keystore = new SqliteKeyStore(':memory:');
  const identity = await loadServerBoundaryIdentity({ db: s.ds, nodeName: 'utility-server', configJson: { identity: { didSeedHex: '11'.repeat(32) } }, passphrase: PASS });
  const ctx: BoundaryAdminContext = { db: s.ds, keystore, passphrase: PASS, identity, execute: true };
  await runBoundaryAdmin('provision', ctx, { generation: 2 });
  await runBoundaryAdmin('rotate', ctx, { generation: 2 });
  const out = await s.sync();
  assert.equal(out.action, 'repaired');
  const now = boundary(await s.rowDoc())!;
  assert.notEqual(now.publicKeyMultibase, staleKey.publicKeyMultibase);
  assert.ok((await s.rowDoc()).service?.some((x) => x.id === LIVE_ENDPOINT.id));
});

test('log chain invalid: fail closed in dedicated mode, the row untouched', async () => {
  const s = await server();
  await s.publish();
  await s.tamperHead();
  const before = await s.row();
  await assert.rejects(s.sync({ dedicated: true }), (e: BoundaryKeyError) => e instanceof BoundaryKeyError && /rotation log/.test(e.message) && /valid/.test(e.message));
  assert.deepEqual(await s.row(), before);
});

test('log chain invalid with the gate off: nothing repaired or overlaid, a warning is logged, the server keeps serving the document it has', async () => {
  const s = await server();
  await s.publish();
  await s.tamperHead();
  const before = await s.row();
  const warnings: string[] = [];
  const out = await s.sync({ dedicated: false, warn: (m) => warnings.push(m) });
  assert.equal(out.action, 'unverified');
  assert.deepEqual(out.document, s.local);
  assert.deepEqual(await s.row(), before);
  assert.equal(warnings.length, 1);
});

test('gate off, no key published: no change at all', async () => {
  const s = await server();
  const before = await s.row();
  const out = await s.sync({ dedicated: false });
  assert.equal(out.action, 'noKey');
  assert.deepEqual(out.document, s.local);
  assert.deepEqual(await s.row(), before);
});

test('gate off, key published: the key is overlaid and the row repaired, endpoints kept (K7: publish precedes cutover; signing stays #key-1)', async () => {
  const s = await server();
  await s.publish();
  const out = await s.sync({ dedicated: false });
  assert.equal(out.action, 'repaired');
  assert.ok(boundary(out.document));
  assert.ok(out.document.authentication.includes('#key-boundary'));
  assert.ok(out.document.service?.some((x) => x.id === LIVE_ENDPOINT.id));
  assert.ok(boundary(await s.rowDoc()));
});

test('dedicated mode, no key published: the local boundary method is stripped from the served document (the signer check then refuses), the row is not written', async () => {
  const s = await server();
  const before = await s.row();
  const stale: DidDocument = { ...structuredClone(s.local), verificationMethod: [...s.local.verificationMethod, { id: '#key-boundary', type: 'Multikey', controller: s.did, publicKeyMultibase: 'z6Mkstale' } as never], authentication: [...s.local.authentication, '#key-boundary'] };
  const out = await s.sync({ dedicated: true, served: stale });
  assert.equal(boundary(out.document), undefined);
  assert.deepEqual(await s.row(), before);
});

test('served document stale while the row is current: the served one is overlaid, the row is not rewritten', async () => {
  const s = await server();
  await s.publish();
  await s.sync();
  const before = await s.row();
  const out = await s.sync({ served: s.local });
  assert.equal(out.action, 'consistent');
  assert.ok(boundary(out.document));
  assert.deepEqual(await s.row(), before);
});

test('unreadable document_json: dedicated mode fails closed, gate off warns and serves what it has; the row is not written', async () => {
  const s = await server();
  await s.publish();
  await s.ds.run('UPDATE did_documents SET document_json = ? WHERE uuid = ?', '{not json', s.docUuid);
  await assert.rejects(s.sync({ dedicated: true }), BoundaryKeyError);
  const warnings: string[] = [];
  const out = await s.sync({ dedicated: false, warn: (m) => warnings.push(m) });
  assert.equal(out.action, 'unverified');
  assert.equal(warnings.length, 1);
  assert.equal((await s.row()).document_json, '{not json');
});
