// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * The opt-in Trust Task listener of the utility server (gate G2 process wiring): default off, own
 * port, Tier 2 by default, document surface only, strict settings, graceful close, and the dedicated
 * key gate failing closed.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks-listener.test.ts
 */
import { afterEach, test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import Fastify from 'fastify';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { createEd25519BoundarySigner, setBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { BoundaryKeyError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { POLICY_EVALUATE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/legacy-evaluate.js';
import { defaultVerifier, registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { startUtilityBoundaryListener } from '../../src/trust-tasks-listener.js';

const SERVER_DID = 'did:scid:vh:server';
afterEach(() => setBoundarySigner(undefined));

function db() {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
}
async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once('error', reject);
    s.listen(0, '127.0.0.1', () => {
      const { port } = s.address() as { port: number };
      s.close(() => resolve(port));
    });
  });
}
const unsigned = () => ({
  id: 'urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', type: POLICY_EVALUATE_WIRE_TYPE, issuer: 'did:key:z6MkPeer', recipient: SERVER_DID,
  issuedAt: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString().replace('.000Z', 'Z'), payload: { action: 'register_name' },
});

test('DEFAULT OFF: nothing is started, bound or logged unless the switch is set', async () => {
  const lines: string[] = [];
  for (const env of [{}, { TRUST_TASKS_LISTENER_PORT: '4999' }, { TRUST_TASKS_LISTENER: '0', TRUST_TASKS_LISTENER_PORT: '4999' }]) {
    assert.equal(await startUtilityBoundaryListener({ db: db(), env, forbiddenPorts: [], log: (l) => lines.push(l) }), undefined);
  }
  assert.deepEqual(lines, []);
});

test('DEFAULT OFF, byte identical: the main route still serves the read routes and the POST route exactly as before', async () => {
  const app = Fastify();
  registerTrustTaskRoutes(app, db(), { defaultVid: SERVER_DID });
  await app.ready();
  assert.equal((await app.inject({ method: 'GET', url: '/trust-tasks/threads' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'application/json' }, payload: '{}' })).statusCode >= 400, true);
  // the verifier default is the pre-G2 one when the gate is unset
  assert.ok(defaultVerifier(db()));
});

test('strict settings: a bad port, a reserved port, a bad tier or a missing signer refuses to start', async () => {
  setBoundarySigner(createEd25519BoundarySigner({ did: SERVER_DID, secretKey: new Uint8Array(32).fill(6) }));
  const base = { TRUST_TASKS_LISTENER: '1' };
  await assert.rejects(startUtilityBoundaryListener({ db: db(), env: base, forbiddenPorts: [] }), /no valid port/);
  await assert.rejects(startUtilityBoundaryListener({ db: db(), env: { ...base, TRUST_TASKS_LISTENER_PORT: '8080' }, forbiddenPorts: [8080] }), /reserved/);
  await assert.rejects(startUtilityBoundaryListener({ db: db(), env: { ...base, TRUST_TASKS_LISTENER_PORT: '4999', TRUST_TASKS_TIER: '7' }, forbiddenPorts: [] }), /TRUST_TASKS_TIER/);
  setBoundarySigner(undefined);
  await assert.rejects(startUtilityBoundaryListener({ db: db(), env: { ...base, TRUST_TASKS_LISTENER_PORT: '4999' }, forbiddenPorts: [] }), /no boundary signer/);
});

test('on: its own port, Tier 2 by default (an unsigned document is refused for want of a proof, by a signed reply), document surface only, and it stops cleanly', async () => {
  setBoundarySigner(createEd25519BoundarySigner({ did: SERVER_DID, secretKey: new Uint8Array(32).fill(6) }));
  const port = await freePort();
  const lines: string[] = [];
  const listener = await startUtilityBoundaryListener({ db: db(), env: { TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: String(port) }, forbiddenPorts: [], log: (l) => lines.push(l), routeOptions: { defaultVid: SERVER_DID } });
  assert.ok(listener);
  try {
    assert.equal(listener.settings.tier, 2);
    assert.equal(listener.settings.host, '127.0.0.1');
    const res = await fetch(`http://127.0.0.1:${port}/trust-tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(unsigned()) });
    const reply = (await res.json()) as { issuer: string; payload: { code: string }; proof?: { verificationMethod: string } };
    assert.equal(reply.payload.code, 'proofRequired');
    assert.equal(reply.issuer, SERVER_DID);
    assert.match(reply.proof?.verificationMethod ?? '', /#key-1$/);
    assert.equal((await fetch(`http://127.0.0.1:${port}/trust-tasks/threads`)).status, 404, 'no read routes on the boundary port');
    assert.equal((await fetch(`http://127.0.0.1:${port}/api/identities`)).status, 404);
  } finally {
    await listener.close();
  }
  await assert.rejects(() => fetch(`http://127.0.0.1:${port}/trust-tasks`, { method: 'POST', body: '{}' }), /fetch failed/);
  assert.equal(lines.length, 2);
  for (const l of lines) assert.match(l, /^\[trust-tasks\] \{"event":"listener\.(started|stopped)"/);
  assert.equal(lines.some((l) => /secret|passphrase|seed/i.test(l)), false);
});

test('the dedicated gate FAILS CLOSED in the verifier default: a typo or a missing cutover throws instead of verifying under the legacy rules', () => {
  const saved = { k: process.env.TRUST_TASKS_BOUNDARY_KEY, c: process.env.BOUNDARY_KEY_CUTOVER_AT };
  try {
    process.env.TRUST_TASKS_BOUNDARY_KEY = 'dedicated';
    delete process.env.BOUNDARY_KEY_CUTOVER_AT;
    assert.throws(() => defaultVerifier(db()), (e: BoundaryKeyError) => e.code === 'config');
    process.env.BOUNDARY_KEY_CUTOVER_AT = '2030-01-01T00:00:00Z';
    assert.ok(defaultVerifier(db()), 'a valid gate builds the policy verifier');
  } finally {
    if (saved.k === undefined) delete process.env.TRUST_TASKS_BOUNDARY_KEY; else process.env.TRUST_TASKS_BOUNDARY_KEY = saved.k;
    if (saved.c === undefined) delete process.env.BOUNDARY_KEY_CUTOVER_AT; else process.env.BOUNDARY_KEY_CUTOVER_AT = saved.c;
  }
});
