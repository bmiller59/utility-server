// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers


/**
 * `POST /trust-tasks` on the core boundary pipeline (conformance phase P2): the suite vectors that
 * apply to an HTTPS carrier with one read task, by id, plus the binding concerns the suite has no
 * vectors for yet (named "design BND-00N": path and method, authentication mapping, status table,
 * raw JSON retained, error body parseable, deployment-chosen path). The same ENV, TIME and ID
 * vectors run against the core adapter in p2p-trust-stack; here they run on the wire.
 *
 * Run with:
 *   cd utility-server && node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks-pipeline.test.ts
 * (against an unreleased core: link the local core into node_modules, see the P1/P2 reports)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import Fastify, { type FastifyInstance } from 'fastify';

import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { runMigrations } from '@p2p-trust-stack/core/db/migrate.js';
import { generateUuid } from '@p2p-trust-stack/core/db/uuid-helpers.js';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as membershipsRepo from '@p2p-trust-stack/core/db/repositories/memberships-repo.js';
import * as governanceRepo from '@p2p-trust-stack/core/db/repositories/governance-repo.js';
import { seedDefaultBindings } from '@p2p-trust-stack/core/services/policy-bindings.js';
import { POLICY_EVALUATE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import { POLICY_EVALUATE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/legacy-evaluate.js';
import type { PipelineResult } from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';
import { registerTrustTaskRoutes, strictnessFromEnv } from '../../src/routes/layer3-tasks/trust-tasks.js';
import type { TrustTaskRouteOptions } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { createSession, generateSessionSecret } from '../../src/session.js';

const CLUB_DID = 'did:scid:vh:club';
const ADMIN_DID = 'did:scid:vh:admin';
const SERVER_DID = 'did:scid:vh:server';
const START = Date.parse('2026-11-12T10:00:00Z');
const T = '2026-11-12T10:00:00Z';
const BINDING_STATUSES = [200, 202, 204, 400, 403, 409, 413, 422, 500, 503];

async function seed(options: TrustTaskRouteOptions & { before?: (app: FastifyInstance) => void } = {}) {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), getMigrationsDir());
  const mk = async (did: string, role: 'vtc' | 'vta', name: string) => {
    const uuid = generateUuid();
    await identitiesRepo.create(ds, { uuid, realDid: did, role, name, recordedByNode: 'test' });
    await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
    return uuid;
  };
  const clubUuid = await mk(CLUB_DID, 'vtc', 'Chess Club');
  const adminUuid = await mk(ADMIN_DID, 'vta', 'Admin');
  await membershipsRepo.create(ds, { memberIdentityUuid: adminUuid, communityIdentityUuid: clubUuid, role: 'founding_admin', status: 'active' });
  await governanceRepo.create(ds, { communityIdentityUuid: clubUuid, adminThresholdM: 2, adminThresholdN: 3 });
  await seedDefaultBindings(ds, clubUuid, 'vtc');
  const secret = generateSessionSecret();
  const app: FastifyInstance = Fastify();
  (app as unknown as { hmacSecret: Buffer }).hmacSecret = secret;
  const seen: PipelineResult[] = [];
  options.before?.(app);
  const { before: _before, ...routeOptions } = options;
  registerTrustTaskRoutes(app, ds, { now: () => START, defaultVid: SERVER_DID, observe: (r) => seen.push(r), ...routeOptions });
  await app.ready();
  return { app, ds, secret, seen, adminCookie: createSession(adminUuid, secret).cookie };
}

const doc = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  id: 'urn:uuid:aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  type: POLICY_EVALUATE_WIRE_TYPE,
  issuer: ADMIN_DID,
  recipient: CLUB_DID,
  issuedAt: T,
  payload: { action: 'register_name' },
  ...over,
});

const post = (app: FastifyInstance, body: unknown, headers: Record<string, string> = {}, url = '/trust-tasks') =>
  app.inject({ method: 'POST', url, headers: { 'content-type': 'application/json', ...headers }, payload: typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body) });

const code = (res: { json: () => { payload?: { code?: string } } }): string | undefined => res.json().payload?.code;

// ── ENV ─────────────────────────────────────────────────────────────────────

test('ENV-001: a minimal valid request is answered, under the wire URN form and the legacy internal name', async () => {
  const { app } = await seed();
  const wire = await post(app, doc());
  assert.equal(wire.statusCode, 200);
  assert.equal(wire.json().type, `${POLICY_EVALUATE_WIRE_TYPE}#response`);
  const legacy = await post(app, doc({ type: POLICY_EVALUATE_TYPE, id: 'urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }));
  assert.equal(legacy.statusCode, 200);
  assert.equal(legacy.json().type, `${POLICY_EVALUATE_TYPE}#response`);
  assert.equal(wire.json().issuedAt, T, 'whole-second timestamps from the injected clock');
});

test('ENV-002: undecodable bytes get no invented reply: 400 minimal body, not a Trust Task document, nothing run', async () => {
  const { app, seen } = await seed();
  const truncated = JSON.stringify(doc()).slice(0, -12);
  for (const body of [truncated, Buffer.from([0x7b, 0xff, 0xfe, 0x7d])]) {
    const res = await post(app, body);
    assert.equal(res.statusCode, 400);
    assert.deepEqual(Object.keys(res.json()).sort(), ['code', 'message', 'retryable']);
  }
  assert.ok(seen.every((r) => r.kind === 'refused' && r.refusedBeforeProof));
});

test('ENV-003/004/005: missing id, type or payload is refused, never executed', async () => {
  const { app } = await seed();
  for (const member of ['id', 'type', 'payload']) {
    const body = doc();
    delete body[member];
    const res = await post(app, body);
    assert.equal(res.statusCode, 400, member);
    if (member === 'type') assert.equal(res.json().payload?.code ?? res.json().code, 'malformedRequest');
    else assert.equal(code(res), 'malformedRequest', member);
  }
});

test('ENV-006/007/008/009/010: type refusals', async () => {
  const { app } = await seed();
  const t = (type: string) => post(app, doc({ type }));
  assert.ok(['unsupportedType', 'malformedRequest'].includes(code(await t('http://trusttasks.org/spec/policy/evaluate/0.1'))!), 'ENV-006');
  assert.ok(['unsupportedType', 'malformedRequest'].includes(code(await t('https://trusttasks.org/spec/policy/Evaluate/0.1'))!), 'ENV-007');
  assert.ok(['unsupportedType', 'malformedRequest'].includes(code(await t('https://trusttasks.org/spec/bindings/https/0.3'))!), 'ENV-008');
  const unknown = await t('https://trusttasks.org/spec/policy/gadget/0.1');
  assert.equal(code(unknown), 'unsupportedType', 'ENV-009');
  assert.equal(unknown.statusCode, 422);
  const major = await t('urn:p2pts:tasks:spec:policy:evaluate:1.0');
  assert.equal(code(major), 'unsupportedVersion', 'ENV-010');
  assert.deepEqual(major.json().payload.details, { servedVersions: ['0.1'] });
});

test('ENV-011/012/014: a payload that violates the schema is refused; unknown members are ignored; any timestamp spelling is accepted', async () => {
  const { app } = await seed();
  assert.equal(code(await post(app, doc({ payload: { action: 5 } }))), 'malformedRequest');
  assert.equal(code(await post(app, doc({ payload: {} }))), 'malformedRequest');
  assert.equal((await post(app, doc({ 'x-unrecognised': { anything: 1 }, id: 'urn:uuid:cccccccc-cccc-4ccc-8ccc-cccccccccccc' }))).statusCode, 200);
  assert.equal((await post(app, doc({ issuedAt: '2026-11-12T10:00:00.000Z', id: 'urn:uuid:dddddddd-dddd-4ddd-8ddd-dddddddddddd' }))).statusCode, 200);
});

// ── TIME (a read task: the pinned window applies when the document dates itself) ─

test('TIME-101/102/003/008: stale is expired (was never checked), future beyond skew is malformedRequest, edges are half-open', async () => {
  const { app } = await seed();
  const at = (issuedAt: string) => post(app, doc({ issuedAt }));
  const stale = await at('2026-11-12T09:52:00Z');
  assert.equal(code(stale), 'expired');
  assert.equal(stale.statusCode, 422);
  assert.equal((await at('2026-11-12T09:54:00Z')).statusCode, 422, 'exactly issuedAt + maxAge + skew: refused');
  assert.equal((await at('2026-11-12T09:54:01Z')).statusCode, 200, 'one second inside: accepted');
  assert.equal(code(await at('2026-11-12T10:05:00Z')), 'malformedRequest', 'TIME-102');
  assert.equal((await at('2026-11-12T10:01:00Z')).statusCode, 200, 'TIME-007: exactly the skew ahead');
  assert.equal(code(await at('2026-11-12T10:01:01Z')), 'malformedRequest', 'TIME-008');
  assert.equal(code(await at('2026-01-31T24:00:00Z')), 'malformedRequest', 'TIME-023');
  assert.equal(code(await post(app, doc({ expiresAt: T }))), 'expired', 'TIME-012: inclusive expiry');
});

test('design TIME: the strictness flag. strict by default; lenient lets a stale read task through; the proof policy never moves', async () => {
  assert.equal(strictnessFromEnv(undefined), 'strict');
  assert.equal(strictnessFromEnv('lenient'), 'lenient');
  assert.equal(strictnessFromEnv('off'), 'strict');
  assert.equal(strictnessFromEnv('LENIENT'), 'strict');
  const stale = { issuedAt: '2026-11-12T08:00:00Z' };
  const strict = await seed();
  assert.equal(code(await post(strict.app, doc(stale))), 'expired');
  const lenient = await seed({ strictness: 'lenient' });
  assert.equal((await post(lenient.app, doc(stale))).statusCode, 200);
  const withProof = await post(lenient.app, doc({ proof: { type: 'DataIntegrityProof' }, id: 'urn:uuid:eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee' }));
  assert.equal(withProof.statusCode, 400);
  assert.equal(code(withProof), 'malformedRequest');
  const unknownCommunity = await post(lenient.app, doc({ recipient: 'did:scid:vh:none', id: 'urn:uuid:ffffffff-ffff-4fff-8fff-ffffffffffff' }));
  assert.equal(code(unknownCommunity), 'wrongRecipient', 'the handler still resolves the community');
});

// ── ID ──────────────────────────────────────────────────────────────────────

test('ID-001: wrong recipient: wrongRecipient issued by the server identifier, the contested DID not echoed', async () => {
  const { app } = await seed();
  const res = await post(app, doc({ recipient: 'did:scid:vh:somebody-else' }));
  assert.equal(res.statusCode, 422);
  const d = res.json();
  assert.equal(d.payload.code, 'wrongRecipient');
  assert.equal(d.issuer, SERVER_DID);
  assert.equal(d.recipient, ADMIN_DID);
  assert.ok(!JSON.stringify(d.payload).includes('somebody-else'));
});

test('ID-002: the session identity differs from the in-band issuer: identityMismatch to the sender, request id withheld, no identity in the message', async () => {
  const { app, ds, secret } = await seed();
  const otherUuid = generateUuid();
  await identitiesRepo.create(ds, { uuid: otherUuid, realDid: 'did:scid:vh:other', role: 'vta', name: 'Other', recordedByNode: 'test' });
  await didDocumentsRepo.create(ds, { identityUuid: otherUuid, did: 'did:scid:vh:other', method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
  const res = await post(app, doc(), { cookie: createSession(otherUuid, secret).cookie });
  assert.equal(res.statusCode, 422);
  const d = res.json();
  assert.equal(d.payload.code, 'identityMismatch');
  assert.equal(d.recipient, 'did:scid:vh:other');
  assert.equal(d.payload.inResponseTo.id, undefined);
  assert.ok(!d.payload.message.includes(ADMIN_DID) && !d.payload.message.includes('did:scid:vh:other'));
});

// ── BND (design ids: the suite has no BND vectors yet) ──────────────────────

test('design BND-001: path and method. POST /trust-tasks only; other methods on the path are not routed', async () => {
  const { app } = await seed();
  for (const method of ['GET', 'PUT', 'DELETE', 'PATCH'] as const) {
    const res = await app.inject({ method, url: '/trust-tasks' });
    assert.ok([404, 405].includes(res.statusCode), `${method} ${res.statusCode}`);
  }
  assert.equal((await post(app, doc())).statusCode, 200);
});

test('design BND-002: authentication mapping. no cookie, a garbage cookie and a tampered cookie are "no sender"; the session identity is the sender', async () => {
  const { app, adminCookie } = await seed();
  assert.equal((await post(app, doc())).statusCode, 200);
  assert.equal((await post(app, doc({ id: 'urn:uuid:11111111-1111-4111-8111-111111111111' }), { cookie: 'session=garbage' })).statusCode, 200);
  assert.equal((await post(app, doc({ id: 'urn:uuid:22222222-2222-4222-8222-222222222222' }), { cookie: `${adminCookie}x` })).statusCode, 200);
  assert.equal((await post(app, doc({ id: 'urn:uuid:33333333-3333-4333-8333-333333333333' }), { cookie: adminCookie })).statusCode, 200);
});

test('design BND-002: unauthenticated evaluate is still answered here (permissionDenied for it is the AUTHZ phase, not P2)', async () => {
  const { app } = await seed();
  const res = await post(app, doc());
  assert.equal(res.statusCode, 200);
  assert.equal(typeof res.json().payload.result.allowed, 'boolean');
});

test('design BND-003: status table. every outcome maps to the binding status, none is 401 or 404', async () => {
  const { app } = await seed();
  const seen = new Map<string, number>();
  seen.set('response', (await post(app, doc())).statusCode);
  seen.set('inbound error', (await post(app, { id: 'urn:uuid:44444444-4444-4444-8444-444444444444', type: 'https://trusttasks.org/spec/trust-task-error/0.6', issuer: ADMIN_DID, recipient: CLUB_DID, payload: { code: 'taskFailed', retryable: false } })).statusCode);
  seen.set('malformed', (await post(app, doc({ payload: {} }))).statusCode);
  seen.set('unsupportedType', (await post(app, doc({ type: 'https://trusttasks.org/spec/policy/gadget/0.1' }))).statusCode);
  seen.set('expired', (await post(app, doc({ issuedAt: '2026-11-12T08:00:00Z' }))).statusCode);
  seen.set('wrongRecipient', (await post(app, doc({ recipient: 'did:scid:vh:none' }))).statusCode);
  seen.set('unparseable', (await post(app, '{')).statusCode);
  seen.set('oversize', (await post(app, JSON.stringify(doc({ payload: { action: 'x'.repeat(1_100_000) } })))).statusCode);
  assert.deepEqual([...seen], [['response', 200], ['inbound error', 204], ['malformed', 400], ['unsupportedType', 422], ['expired', 422], ['wrongRecipient', 422], ['unparseable', 400], ['oversize', 413]]);
  for (const st of seen.values()) assert.ok(BINDING_STATUSES.includes(st), String(st));
});

test('design BND-004: raw JSON retained. the pipeline sees the bytes exactly as received, in any spelling; a refusal before the claim stage is flagged as not storable', async () => {
  const { app, seen } = await seed();
  const text = `\n  {"payload":{"action":"register_name"},\n "recipient":"${CLUB_DID}","issuer":"${ADMIN_DID}",   "id":"urn:uuid:55555555-5555-4555-8555-555555555555", "type":"${POLICY_EVALUATE_WIRE_TYPE}", "issuedAt":"2026-11-12T10:00:00.000Z"}  \n`;
  assert.equal((await post(app, text)).statusCode, 200);
  assert.equal(seen[0]!.raw, text);
  await post(app, doc({ recipient: 'did:scid:vh:none' }));
  assert.equal(seen[1]!.refusedBeforeProof, true);
  assert.equal(seen[1]!.raw, JSON.stringify(doc({ recipient: 'did:scid:vh:none' })));
});

test('design BND-005: a client can parse every non-2xx body: JSON, with a trust-task-error document whenever the request was addressable', async () => {
  const { app } = await seed();
  for (const body of [doc({ payload: {} }), doc({ recipient: 'did:scid:vh:none' }), doc({ type: 'https://trusttasks.org/spec/policy/gadget/0.1' }), '{', '[1]', doc({ issuedAt: '2026-11-12T08:00:00Z' })]) {
    const res = await post(app, body);
    assert.ok(res.statusCode >= 400);
    assert.match(String(res.headers['content-type']), /^application\/json/);
    const parsed = res.json();
    if (typeof body === 'string') assert.equal(parsed.code, 'malformedRequest');
    else assert.equal(parsed.type, 'https://trusttasks.org/spec/trust-task-error/0.6');
  }
});

test('design BND-006: deployments differ on paths. the path is an option; the default path is not served then', async () => {
  const { app } = await seed({ path: '/tt/inbox' });
  assert.equal((await post(app, doc(), {}, '/tt/inbox')).statusCode, 200);
  assert.equal((await post(app, doc(), {}, '/trust-tasks')).statusCode, 404);
});

test('design: a non-JSON content type is refused by the carrier before the pipeline, and the raw-body parser is scoped to this route', async () => {
  const { app } = await seed({ before: (a) => { a.post('/echo-json', async (req) => ({ parsed: typeof req.body === 'object' && !Buffer.isBuffer(req.body) })); } });
  const res = await app.inject({ method: 'POST', url: '/trust-tasks', headers: { 'content-type': 'text/plain' }, payload: 'x' });
  assert.equal(res.statusCode, 415);
  const echoed = await app.inject({ method: 'POST', url: '/echo-json', headers: { 'content-type': 'application/json' }, payload: '{"a":1}' });
  assert.deepEqual(echoed.json(), { parsed: true });
});
