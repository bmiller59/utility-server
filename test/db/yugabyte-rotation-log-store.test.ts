// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * YugabyteRotationLogStore against a REAL private PostgreSQL (initdb, a free port, a temp dir; the same wire
 * protocol as YugabyteDB; the pattern of test/e2e/boundary-key-boot.test.ts). Never touches a shared database.
 *
 * Pins K3: the optional ML-DSA-65 signature of a rotation entry is persisted by appendEntry and returned by
 * getLog; a row written before PQ signing (no trailing block) still reads; a damaged block fails closed.
 *
 * Skipped (loudly) when no PostgreSQL server binaries are installed.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/db/yugabyte-rotation-log-store.test.ts
 */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';
import { ML_DSA_65_SIG_BYTES } from '@p2p-trust-stack/core/crypto/pqc.js';
import { runDataSourceMigrations } from '@p2p-trust-stack/core/db/migrate-via-datasource.js';
import { YugabyteDataSource } from '../../src/db/yugabyte-data-source.js';
import { YugabyteRotationLogStore } from '../../src/db/yugabyte-rotation-log-store.js';

const ROOT = join(import.meta.dirname, '..', '..');
const TMP_BASE = process.env.TMPDIR ?? '/tmp';

function findPgBin(): string | undefined {
  const dirs = [
    ...(existsSync('/usr/lib/postgresql') ? readdirSync('/usr/lib/postgresql').sort().reverse().map((v) => join('/usr/lib/postgresql', v, 'bin')) : []),
    ...(process.env.PATH ?? '').split(':'),
  ];
  return dirs.find((d) => existsSync(join(d, 'initdb')) && existsSync(join(d, 'pg_ctl')) && existsSync(join(d, 'createdb')));
}
const PGBIN = findPgBin();
const skip = PGBIN === undefined ? 'PostgreSQL server binaries (initdb, pg_ctl, createdb) are not installed; test skipped' : false;

function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => { const p = (s.address() as { port: number }).port; s.close(() => resolve(p)); });
  });
}

let dir = '';
let ds: YugabyteDataSource;
let store: YugabyteRotationLogStore;

before(async () => {
  if (PGBIN === undefined) return;
  dir = mkdtempSync(join(TMP_BASE, 'ybrl-'));
  const port = await freePort();
  const init = spawnSync(join(PGBIN, 'initdb'), ['-D', join(dir, 'pg'), '-A', 'trust', '-U', 'yugabyte'], { encoding: 'utf8' });
  assert.equal(init.status, 0, init.stderr);
  const start = spawnSync(join(PGBIN, 'pg_ctl'), ['-D', join(dir, 'pg'), '-o', `-p ${port} -c listen_addresses=127.0.0.1 -c unix_socket_directories=${dir}`, '-l', join(dir, 'pg.log'), '-w', '-t', '60', 'start'], { encoding: 'utf8' });
  assert.equal(start.status, 0, start.stderr);
  const created = spawnSync(join(PGBIN, 'createdb'), ['-h', '127.0.0.1', '-p', String(port), '-U', 'yugabyte', 'p2pts'], { encoding: 'utf8' });
  assert.equal(created.status, 0, created.stderr);
  ds = new YugabyteDataSource({ host: '127.0.0.1', port, database: 'p2pts', user: 'yugabyte', password: '', poolMax: 2, poolMin: 0 });
  await runDataSourceMigrations(ds, join(ROOT, 'src', 'db', 'migrations'));
  store = new YugabyteRotationLogStore(ds);
});

after(async () => {
  if (PGBIN === undefined || dir === '') return;
  await ds?.close();
  spawnSync(join(PGBIN, 'pg_ctl'), ['-D', join(dir, 'pg'), '-m', 'immediate', '-w', '-t', '30', 'stop'], { encoding: 'utf8' });
  rmSync(dir, { recursive: true, force: true });
});

const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
function entry(version: number, mlDsa?: Uint8Array): RotationLogEntry {
  return {
    version,
    parameters: { method: 'did:scid:vh:1' } as RotationLogEntry['parameters'],
    didDocument: { id: 'did:scid:vh:1:abc', verificationMethod: [] } as unknown as RotationLogEntry['didDocument'],
    prevHash: version === 0 ? null : fill(32, 7),
    nextKeyCommitments: [fill(32, 9)],
    createdAt: 1_700_000_000 + version,
    digest: fill(32, 0xd0 + version),
    signature: fill(64, 0x51),
    ...(mlDsa ? { mlDsa65Signature: mlDsa } : {}),
    witnessAttestations: [],
  };
}

test('K3: yugabyte rotation log store', { skip, timeout: 180_000 }, async (t) => {
  await t.test('an entry with an ML-DSA-65 signature reads back with it, byte for byte', async () => {
    const sig = fill(ML_DSA_65_SIG_BYTES, 0xab);
    sig[0] = 1; sig[ML_DSA_65_SIG_BYTES - 1] = 2;
    await store.appendEntry('doc-pq', entry(0, sig));
    const [got] = await store.getLog('doc-pq');
    assert.ok(got!.mlDsa65Signature, 'ML-DSA signature must not be dropped');
    assert.deepEqual(Buffer.from(got!.mlDsa65Signature!), Buffer.from(sig));
    assert.deepEqual(Buffer.from(got!.signature), Buffer.from(fill(64, 0x51)));
    assert.deepEqual(Buffer.from(got!.digest), Buffer.from(fill(32, 0xd0)));
  });

  await t.test('an entry without one reads back without one, and mixed logs keep order', async () => {
    await store.appendEntry('doc-mixed', entry(0));
    await store.appendEntry('doc-mixed', entry(1, fill(ML_DSA_65_SIG_BYTES, 3)));
    const log = await store.getLog('doc-mixed');
    assert.equal(log.length, 2);
    assert.equal(log[0]!.mlDsa65Signature, undefined);
    assert.equal(log[1]!.mlDsa65Signature?.length, ML_DSA_65_SIG_BYTES);
  });

  await t.test('an old row (written by the previous store code: no trailing block) still reads', async () => {
    const { packRotationEntry } = await import('@p2p-trust-stack/core/did/rotation-entry-codec.js');
    const e = entry(0);
    const legacy = packRotationEntry({ didDocument: e.didDocument, parameters: e.parameters, digest: e.digest, signature: e.signature });
    await ds.run(
      `INSERT INTO rotation_log (did_document_uuid, version, previous_hash, new_public_key, signed_entry, uuid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      'doc-old', 0, null, Buffer.from(JSON.stringify([Buffer.from(fill(32, 9)).toString('base64')])), Buffer.from(legacy), crypto.randomUUID(), 5,
    );
    const [got] = await store.getLog('doc-old');
    assert.equal(got!.mlDsa65Signature, undefined);
    assert.deepEqual(got!.didDocument, e.didDocument);
    assert.deepEqual(Buffer.from(got!.signature), Buffer.from(e.signature));
  });

  await t.test('a damaged ML-DSA block fails closed on read (not read as "no signature")', async () => {
    await store.appendEntry('doc-bad', entry(0, fill(ML_DSA_65_SIG_BYTES, 5)));
    // truncate the stored blob by 10 bytes
    await ds.run(`UPDATE rotation_log SET signed_entry = substring(signed_entry from 1 for length(signed_entry) - 10) WHERE did_document_uuid = ?`, 'doc-bad');
    await assert.rejects(() => store.getLog('doc-bad'), SyntaxError);
  });

  await t.test('appendEntry refuses a wrong-sized ML-DSA signature and stores nothing', async () => {
    await assert.rejects(() => store.appendEntry('doc-short', entry(0, fill(10, 1))), RangeError);
    assert.equal((await store.getLog('doc-short')).length, 0);
  });
});
