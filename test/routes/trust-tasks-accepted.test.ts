// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Conformance P3 on the utility server: migration 0021 in this tree (same body as core's, version 26),
 * and POST /trust-tasks with a consequential handler against the durable accepted-id store as the
 * route's duplicate record (DUP vectors on the wire: same bytes, other payload, window edge, restart,
 * fail closed, concurrent double claim). Only the read-only evaluate task is served in production code
 * today, so the consequential handler here is a test double registered through `extraHandlers`.
 *
 * The distributed database was not available: the store runs on SQLite (the data source the tests use);
 * its dialect-portability is covered by the Postgres-dialect emulation in the core store tests.
 *
 * Run with:
 *   cd utility-server && node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks-accepted.test.ts
 * (against an unreleased core: link the local core into node_modules, see the P1/P2 reports)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';

const SERVER_DID = 'did:scid:vh:server';
const SENDER = 'did:scid:vh:admin';
const TYPE = 'https://trusttasks.org/spec/conformance/widget/0.1';
const T0 = Date.parse('2026-11-12T10:00:00Z');
const ID = 'urn:uuid:5f0c2a4e-8d1b-4c3a-9e2f-000000000001';
const UTILITY_MIGRATIONS = join(import.meta.dirname, '..', '..', 'src', 'db', 'migrations');

const bytes = (over: Record<string, unknown> = {}): string =>
  JSON.stringify({ id: ID, type: TYPE, issuer: SENDER, recipient: SERVER_DID, issuedAt: '2026-11-12T10:00:00Z', payload: { subject: 'did:web:alice.example' }, ...over });

function widget(counter: { n: number }): PipelineHandler {
  return {
    types: [TYPE],
    spec: {
      typeUri: TYPE, isBearer: false, isProofRequired: false, isRecipientRequired: true, isIssuedAtRequired: true,
      payloadSchema: { type: 'object', required: ['subject'], properties: { subject: { type: 'string' } } },
    },
    consequential: true,
    handle: (doc, ctx) => {
      counter.n++;
      return { id: ctx.newId(), threadId: doc.id, type: `${TYPE}#response`, issuer: doc.recipient, recipient: doc.issuer, issuedAt: ctx.clock(), payload: { executed: counter.n } } as never;
    },
  };
}

async function boot(ds: DataSource, counter: { n: number }, now: { ms: number }, guardDs: DataSource = ds): Promise<FastifyInstance> {
  const app = Fastify();
  registerTrustTaskRoutes(app, ds, {
    now: () => now.ms,
    defaultVid: SERVER_DID,
    extraHandlers: [widget(counter)],
    ...(guardDs === ds ? {} : { guard: new AcceptedIdStore(guardDs) }),
    pruneIntervalMs: 0,
  });
  await app.ready();
  return app;
}
const post = (app: FastifyInstance, payload: string) => app.inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'application/json' }, payload });
const fresh = (): SqliteDataSource => {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  return ds;
};

test('migration 0021 in the utility tree: same body as core, next free number, SCHEMA_VERSION 26', () => {
  const files = readdirSync(UTILITY_MIGRATIONS).filter((f) => f.endsWith('.sql')).sort();
  assert.ok(files.includes('0021_trust_task_boundary.sql'));
  assert.deepEqual(files.slice(-3), ['0020_community_policy_bindings.sql', '0021_trust_task_boundary.sql', '0501_namespace_config.sql'], 'sorts before the server-only 0501');
  assert.equal(readFileSync(join(UTILITY_MIGRATIONS, '..', 'SCHEMA_VERSION'), 'utf8').trim(), '26');
  const body = (p: string) => readFileSync(p, 'utf8').split('\n').slice(2).join('\n');
  assert.equal(body(join(UTILITY_MIGRATIONS, '0021_trust_task_boundary.sql')), body(join(getMigrationsDir(), '0021_trust_task_boundary.sql')));
  assert.match(readFileSync(join(UTILITY_MIGRATIONS, '0021_trust_task_boundary.sql'), 'utf8'), /^-- SPDX-License-Identifier: AGPL-3\.0-only/);
});

test('DUP-001 on the wire: the same bytes again return the first response and the effect happens once', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const app = await boot(ds, counter, { ms: T0 + 5000 });
  const first = await post(app, bytes());
  assert.equal(first.statusCode, 200);
  const again = await post(app, bytes());
  assert.equal(again.statusCode, 200);
  assert.deepEqual(again.json(), first.json());
  assert.equal(counter.n, 1);
  const row = await ds.get<{ state: string; type: string; issuer: string }>('SELECT state, type, issuer FROM trust_task_accepted WHERE id = ?', ID);
  assert.deepEqual({ ...row }, { state: 'completed', type: TYPE, issuer: SENDER });
});

test('DUP-003 on the wire: another payload under the same id is idConflict (409), not executed', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const app = await boot(ds, counter, { ms: T0 + 5000 });
  await post(app, bytes());
  const res = await post(app, bytes({ payload: { subject: 'did:web:bob.example' } }));
  assert.equal(res.json().payload.code, 'idConflict');
  assert.equal(res.statusCode, 409);
  assert.equal(counter.n, 1);
});

test('DUP-110/111 on the wire: window edge at issuedAt + 5 min + 60 s (live a millisecond before, expired at the instant)', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const now = { ms: T0 + 30_000 };
  const app = await boot(ds, counter, now);
  await post(app, bytes());
  now.ms = Date.parse('2026-11-12T10:05:59.999Z');
  assert.equal((await post(app, bytes())).statusCode, 200);
  now.ms = Date.parse('2026-11-12T10:06:00Z');
  const edge = await post(app, bytes());
  assert.equal(edge.json().payload.code, 'expired');
  assert.equal(counter.n, 1);
});

test('DUP restart on the wire: a new process over the same database still absorbs the resend', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const first = await (await boot(ds, counter, { ms: T0 + 5000 })).inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'application/json' }, payload: bytes() });
  const restarted = await boot(ds, counter, { ms: T0 + 10_000 });
  const again = await post(restarted, bytes());
  assert.deepEqual(again.json(), first.json());
  assert.equal(counter.n, 1);
});

test('DUP fail closed on the wire: an unreadable record is 503 unavailable, retryable, nothing executed, no connection detail', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const failing = { all: () => { throw new Error('connection refused: yb.internal:5433'); }, get: () => { throw new Error('connection refused: yb.internal:5433'); }, run: () => { throw new Error('x'); }, exec: () => { throw new Error('x'); }, transaction: () => { throw new Error('x'); }, close: async () => {} } as unknown as DataSource;
  const app = await boot(ds, counter, { ms: T0 + 5000 }, failing);
  const res = await post(app, bytes());
  assert.equal(res.statusCode, 503);
  assert.equal(res.json().payload.code, 'unavailable');
  assert.equal(res.json().payload.retryable, true);
  assert.ok(!res.body.includes('yb.internal'));
  assert.equal(counter.n, 0);
});

test('DUP concurrent double claim on the wire: two simultaneous deliveries execute once', async () => {
  const ds = fresh();
  const counter = { n: 0 };
  const app = await boot(ds, counter, { ms: T0 + 5000 });
  const [a, b] = await Promise.all([post(app, bytes()), post(app, bytes())]);
  assert.equal(counter.n, 1);
  assert.deepEqual([a.statusCode, b.statusCode].filter((s) => s === 200 || s === 202).length, 2, `${a.statusCode} ${b.statusCode}`);
});

test('the default route (evaluate only, no claim) leaves the record empty: no behaviour change', async () => {
  const ds = fresh();
  const app = Fastify();
  registerTrustTaskRoutes(app, ds, { now: () => T0, defaultVid: SERVER_DID, pruneIntervalMs: 0 });
  await app.ready();
  const res = await post(app, bytes({ type: 'urn:p2pts:tasks:spec:policy:evaluate:0.1', payload: { action: 'register_name' } }));
  // No cookie: evaluate is permissionDenied (403, conformance P5). Either way, nothing is claimed.
  assert.ok([200, 403, 422].includes(res.statusCode));
  assert.equal((await ds.all('SELECT * FROM trust_task_accepted')).length, 0);
});

test('the prune interval is stopped when the app closes (no timer left behind)', async () => {
  const ds = fresh();
  const app = Fastify();
  registerTrustTaskRoutes(app, ds, { now: () => T0, pruneIntervalMs: 20 });
  await app.ready();
  await new Promise((r) => setTimeout(r, 60));
  await app.close();
});
