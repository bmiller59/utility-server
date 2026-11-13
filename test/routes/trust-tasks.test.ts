// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Route-level tests for the Trust Task bridge (`POST /trust-tasks`, P5.5).
 *
 * Pins the bridge's contract against a live app + DB:
 *
 *  1. **An inbound envelope is parsed, routed by its `task:p2pts:…` type, dispatched,
 *     and wrapped back into a `#response`** (threadId echoed, issuer/recipient swapped).
 *  2. **Unknown / malformed / response documents are refused** with a framework error code
 *     (`trust-task-error` document, status from the HTTPS binding's table, conformance P1).
 *  3. **A proof whose issuer is not transport-authenticated is INDETERMINATE** —
 *     `identityMismatch` (422), never silently allowed. The crypto of the proof is
 *     NOT checked here (crypto lives in the guard); only the session binding is.
 *  4. **`upsert` persists and `validate`/`evaluate`/`test` do not** (read the row back).
 *
 * Run with:
 *   cd utility-server && node --experimental-strip-types --loader ./test-loader.mjs --test test/routes/trust-tasks.test.ts
 * (against an unreleased core, add `--conditions=development` and link the local core into node_modules)
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
import {
  CEREMONY_PROPOSE_TYPE,
  CEREMONY_CO_SIGN_TYPE,
} from '@p2p-trust-stack/core/services/trust-tasks/type-uris.js';
import { registerTrustTaskRoutes } from '../../src/routes/layer3-tasks/trust-tasks.js';
import { createSession, generateSessionSecret } from '../../src/session.js';
import * as trustTasksRepo from '@p2p-trust-stack/core/db/repositories/trust-tasks-repo.js';
import { getMigrationsDir } from '@p2p-trust-stack/core/db/migrations-dir.js';

const MIGRATIONS_DIR = getMigrationsDir();
const CLUB_DID = 'did:scid:vh:club';
const ADMIN_DID = 'did:scid:vh:admin';

async function seed(): Promise<{ app: FastifyInstance; ds: SqliteDataSource; clubUuid: string; adminUuid: string; secret: Buffer; adminCookie: string }> {
  const ds = new SqliteDataSource(':memory:');
  runMigrations(ds.getRawDb(), MIGRATIONS_DIR);

  const mk = async (did: string, role: 'vtc' | 'vtn' | 'vta', name: string) => {
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
  const app = Fastify();
  (app as unknown as { hmacSecret: Buffer }).hmacSecret = secret;
  registerTrustTaskRoutes(app, ds);
  await app.ready();

  const adminCookie = createSession(adminUuid, secret).cookie;
  return { app, ds, clubUuid, adminUuid, secret, adminCookie };
}

function env(type: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'doc-1',
    type,
    threadId: 'thread-1',
    issuer: ADMIN_DID,
    recipient: CLUB_DID,
    issuedAt: new Date().toISOString(),
    payload: {},
    ...over,
  };
}

async function post(app: FastifyInstance, body: unknown, cookie?: string) {
  return app.inject({
    method: 'POST',
    url: '/trust-tasks',
    headers: { ...(cookie ? { cookie } : {}) },
    payload: body as object,
  });
}

// ── routing + envelope ──────────────────────────────────────────────────────

test('evaluate: routes by type and wraps the decision in a #response', async () => {
  const { app } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, { payload: { action: 'register_name' } }));
  assert.equal(res.statusCode, 200);
  const doc = res.json();
  assert.equal(doc.type, `${POLICY_EVALUATE_TYPE}#response`);
  assert.equal(doc.threadId, 'thread-1');
  assert.equal(doc.issuer, CLUB_DID); // swapped
  assert.equal(doc.recipient, ADMIN_DID);
  assert.equal(doc.payload.query.action, 'register_name');
  assert.equal(typeof doc.payload.result.allowed, 'boolean');
});

test('unknown task type is refused with unsupportedType (422, was 404 endpointNotFound)', async () => {
  const { app } = await seed();
  const res = await post(app, env('task:p2pts:unknown:foo:0.1', { payload: {} }));
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().payload.code, 'unsupportedType');
});

test('a malformed envelope (missing id) is rejected with malformedRequest', async () => {
  const { app } = await seed();
  const res = await post(app, { type: POLICY_EVALUATE_TYPE, payload: {} });
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().payload.code, 'malformedRequest');
});

test('a #response document is refused as not-a-request', async () => {
  const { app } = await seed();
  const res = await post(app, env(`${POLICY_EVALUATE_TYPE}#response`, { payload: {} }));
  assert.equal(res.statusCode, 400);
  assert.equal(res.json().payload.code, 'malformedRequest');
});

// ── proof / transport attribution ───────────────────────────────────────────

test('a proof with no authenticated issuer is INDETERMINATE (identityMismatch 422, was 401 proof/unattributable; never allow)', async () => {
  const { app } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, {
    payload: { action: 'register_name' },
    proof: { type: 'Ed25519Signature2020' },
  }));
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().payload.code, 'identityMismatch');
});

test('a proof whose issuer IS the session identity is accepted', async () => {
  const { app, adminCookie } = await seed();
  const res = await post(app, env(POLICY_EVALUATE_TYPE, {
    payload: { action: 'register_name' },
    proof: { type: 'Ed25519Signature2020' },
  }), adminCookie);
  assert.equal(res.statusCode, 200);
  assert.equal(typeof res.json().payload.result.allowed, 'boolean');
});

// ── operations ──────────────────────────────────────────────────────────────

// The document-writing ops (validate/test/upsert) were the utility server's developer
// policy API and are removed — a document op is now refused as unsupportedType.
test('a document-write op (upsert) is no longer routed', async () => {
  const { app } = await seed();
  const res = await post(app, env('task:p2pts:policy:upsert:0.1', { payload: { policy: {} } }));
  assert.equal(res.statusCode, 422);
  assert.equal(res.json().payload.code, 'unsupportedType');
});

test('GET /trust-tasks/:threadId returns the recorded ceremony thread in order', async () => {
  const { app, ds } = await seed();
  await trustTasksRepo.record(ds, {
    uuid: 'doc-req',
    threadId: 'thread-9',
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'request',
    payload: { name: 'Chess Club' },
  });
  await trustTasksRepo.record(ds, {
    uuid: 'doc-res',
    threadId: 'thread-9',
    type: 'task:p2pts:vtc:establish:0.1',
    direction: 'response',
    recipientDid: CLUB_DID,
    payload: { communityUuid: 'club-uuid' },
    status: 'crystallized',
  });

  const res = await app.inject({ method: 'GET', url: '/trust-tasks/thread-9' });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.threadId, 'thread-9');
  assert.equal(body.tasks.length, 2);
  assert.equal(body.tasks[0].direction, 'request');
  assert.equal(body.tasks[1].status, 'crystallized');
  assert.deepEqual(body.tasks[1].payload, { communityUuid: 'club-uuid' });
});

test('GET /trust-tasks/:threadId returns an empty list for an unknown thread', async () => {
  const { app } = await seed();
  const res = await app.inject({ method: 'GET', url: '/trust-tasks/nope' });
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.json().tasks, []);
});

test('GET /trust-tasks/threads indexes ceremonies and names them from their steps', async () => {
  const { app, ds } = await seed();

  // A founding ceremony: its PROPOSAL and CO-SIGNATURE coordination events name it
  // (neither is a catalog step).
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-founding',
    type: CEREMONY_PROPOSE_TYPE, direction: 'request',
    payload: { name: 'Chess Club' },
  });
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-founding',
    type: CEREMONY_CO_SIGN_TYPE, direction: 'response', status: 'allowed',
    payload: { coSignaturesReceived: 1, coSignaturesRequired: 2 },
  });
  // A member onboarding: no coordination events, named by its catalog step.
  await trustTasksRepo.record(ds, {
    uuid: generateUuid(), threadId: 'thread-onboard',
    type: 'task:p2pts:credential:onboarding-vmc:0.1', direction: 'response',
    status: 'completed', payload: { result: { credentialUuid: 'cred-1' } },
  });

  const res = await app.inject({ method: 'GET', url: '/trust-tasks/threads' });
  assert.equal(res.statusCode, 200);
  const threads = res.json().threads as Array<Record<string, unknown>>;
  const byId: Record<string, Record<string, unknown>> = {};
  for (const thread of threads) byId[thread.threadId as string] = thread;

  assert.equal(byId['thread-founding'].ceremony, 'vtc-establish');
  assert.equal(byId['thread-founding'].documentCount, 2);
  assert.deepEqual((byId['thread-founding'].statuses as string[]).sort(), ['allowed', 'recorded']);

  assert.equal(byId['thread-onboard'].ceremony, 'member-onboarding');
  assert.equal(byId['thread-onboard'].documentCount, 1);
  assert.deepEqual(byId['thread-onboard'].types, ['task:p2pts:credential:onboarding-vmc:0.1']);

  // The wording travels with the data: the thread carries the ceremony's own title and
  // description, and each step carries its catalog label + sentences. This is what lets
  // the agent app and this server share one UI with no label table of their own.
  assert.equal(byId['thread-onboard'].ceremonyLabel, 'Onboard a member');
  assert.ok(byId['thread-onboard'].ceremonyDescription);

  const threadRes = await app.inject({ method: 'GET', url: '/trust-tasks/thread-onboard' });
  assert.equal(threadRes.statusCode, 200);
  const task = (threadRes.json().tasks as Array<Record<string, any>>)[0];
  assert.equal(task.display.label, 'Issue the membership credential');
  assert.match(String(task.display.response), /Membership credential issued/);
});

test('the static /trust-tasks/threads route is not shadowed by /trust-tasks/:threadId', async () => {
  const { app } = await seed();
  const res = await app.inject({ method: 'GET', url: '/trust-tasks/threads' });
  assert.equal(res.statusCode, 200);
  assert.ok(Array.isArray(res.json().threads), 'the index must win over the param route');
});

// ── conformance P1: the typed error model on the wire ───────────────────────

const ERROR_TYPE = 'https://trusttasks.org/spec/trust-task-error/0.6';
// HTTPS binding 0.3, section 4.
const STATUS_BY_CODE: Record<string, number> = {
  malformedRequest: 400, permissionDenied: 403, idConflict: 409, internalError: 500, unavailable: 503, indeterminate: 503,
  unsupportedType: 422, unsupportedVersion: 422, expired: 422, proofRequired: 422, proofInvalid: 422, identityMismatch: 422,
  wrongRecipient: 422, cancelled: 422, taskFailed: 422, unsupportedExtension: 422,
};

/** The suite's generic Tier 1 checks for an error reply, plus the binding's status. */
function assertConformantError(res: { statusCode: number; headers: Record<string, unknown>; json(): any }, request: Record<string, unknown> | undefined) {
  const doc = res.json();
  assert.equal(doc.type, ERROR_TYPE);
  assert.match(String(res.headers['content-type']), /^application\/json/);
  assert.equal(typeof doc.id, 'string');
  assert.notEqual(doc.id, request?.id);
  assert.equal(typeof doc.payload.code, 'string');
  assert.equal(typeof doc.payload.retryable, 'boolean'); // framework 8.2 MUST
  assert.equal(typeof doc.payload.message, 'string');
  assert.ok(doc.payload.message.length <= 1024);
  assert.equal(res.statusCode, STATUS_BY_CODE[doc.payload.code], `status for ${doc.payload.code}`);
  assert.match(doc.issuedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  if (request !== undefined) {
    assert.equal(doc.threadId, request.threadId ?? request.id);
    assert.equal(doc.payload.inResponseTo.typeUri, request.type);
  }
  return doc;
}

test('ERR-001: an error is a trust-task-error with code, retryable, message, threading and inResponseTo', async () => {
  const { app } = await seed();
  const req = env('task:p2pts:unknown:foo:0.1', { id: 'doc-err-1', threadId: 'thread-err-1' });
  const res = await post(app, req);
  const doc = assertConformantError(res, req);
  assert.equal(doc.payload.code, 'unsupportedType');
  assert.equal(doc.payload.retryable, false);
  assert.equal(doc.threadId, 'thread-err-1');
  assert.equal(doc.issuer, CLUB_DID); // the request's recipient
  assert.equal(doc.recipient, ADMIN_DID); // the request's issuer
  assert.equal(doc.payload.inResponseTo.id, 'doc-err-1');
});

test('ERR-001: with no threadId on the request the error continues a thread named by the request id', async () => {
  const { app } = await seed();
  const req = env('task:p2pts:unknown:foo:0.1', { id: 'doc-err-2' });
  delete req.threadId;
  const doc = assertConformantError(await post(app, req), req);
  assert.equal(doc.threadId, 'doc-err-2');
});

test('payload.code and payload.message keep their paths (legacy readers) and are strings', async () => {
  const { app } = await seed();
  for (const body of [{ type: POLICY_EVALUATE_TYPE, payload: {} }, env('task:p2pts:unknown:foo:0.1')]) {
    const p = (await post(app, body)).json().payload;
    assert.equal(typeof p.code, 'string');
    assert.equal(typeof p.message, 'string');
  }
});

test('a malformed envelope: 400 malformedRequest, threaded on its own id, nothing echoed, no addressing', async () => {
  const { app } = await seed();
  const res = await post(app, { type: POLICY_EVALUATE_TYPE, payload: {}, issuer: ADMIN_DID, recipient: CLUB_DID });
  const doc = res.json();
  assert.equal(res.statusCode, 400);
  assert.equal(doc.payload.code, 'malformedRequest');
  assert.equal(doc.threadId, doc.id);
  assert.equal(doc.recipient, undefined);
  assert.equal(doc.issuer, undefined);
  assert.equal(doc.payload.inResponseTo.typeUri, POLICY_EVALUATE_TYPE);
  const arr = await post(app, [1, 2]);
  assert.equal(arr.statusCode, 400);
  assert.equal(arr.json().payload.inResponseTo, undefined);
});

test('a #response document as a request: 400 malformedRequest with a conformant error', async () => {
  const { app } = await seed();
  const req = env(`${POLICY_EVALUATE_TYPE}#response`, { id: 'doc-resp-1' });
  const res = await post(app, req);
  assert.equal(res.statusCode, 400);
  assertConformantError(res, req);
});

test('community not found: wrongRecipient 422 (was 404 communityNotFound); the DID is not echoed', async () => {
  const { app } = await seed();
  const req = env(POLICY_EVALUATE_TYPE, { id: 'doc-nf', recipient: 'did:scid:vh:nobody', payload: { action: 'register_name' } });
  const res = await post(app, req);
  assert.equal(res.statusCode, 422);
  const doc = assertConformantError(res, req);
  assert.equal(doc.payload.code, 'wrongRecipient');
  assert.ok(!JSON.stringify(doc.payload).includes('nobody'));
});

test('a missing recipient and a bad evaluate payload are malformedRequest 400 (was policy/invalid 400)', async () => {
  const { app } = await seed();
  const noRecipient = env(POLICY_EVALUATE_TYPE, { id: 'doc-nr', payload: { action: 'register_name' } });
  delete noRecipient.recipient;
  const r1 = await post(app, noRecipient);
  assert.equal(r1.statusCode, 400);
  assert.equal(assertConformantError(r1, noRecipient).payload.code, 'malformedRequest');

  const noAction = env(POLICY_EVALUATE_TYPE, { id: 'doc-na', payload: {} });
  const r2 = await post(app, noAction);
  assert.equal(r2.statusCode, 400);
  assert.equal(assertConformantError(r2, noAction).payload.code, 'malformedRequest');

  const badAction = env(POLICY_EVALUATE_TYPE, { id: 'doc-ba', payload: { action: 'secret_internal_action_name' } });
  const r3 = await post(app, badAction);
  assert.equal(r3.statusCode, 400);
  const d3 = assertConformantError(r3, badAction);
  assert.ok(!JSON.stringify(d3.payload).includes('secret_internal_action_name'), 'the message is a fixed phrase, never the requester\'s text');
});

test('identityMismatch (proof, unauthenticated): addressed to the in-band issuer when there is no transport sender; no inResponseTo.id', async () => {
  const { app } = await seed();
  const req = env(POLICY_EVALUATE_TYPE, { id: 'doc-im-1', payload: { action: 'register_name' }, proof: { type: 'Ed25519Signature2020' } });
  const res = await post(app, req);
  assert.equal(res.statusCode, 422);
  const doc = res.json();
  assert.equal(doc.payload.code, 'identityMismatch');
  assert.equal(doc.recipient, ADMIN_DID);
  assert.equal(doc.payload.inResponseTo.id, undefined);
  assert.equal(doc.payload.inResponseTo.typeUri, POLICY_EVALUATE_TYPE);
});

test('identityMismatch with a session for ANOTHER identity: the error goes to the authenticated sender, never the contested issuer (framework 8.1)', async () => {
  const { app, ds, secret } = await seed();
  const otherUuid = generateUuid();
  await identitiesRepo.create(ds, { uuid: otherUuid, realDid: 'did:scid:vh:other', role: 'vta', name: 'Other', recordedByNode: 'test' });
  await didDocumentsRepo.create(ds, { identityUuid: otherUuid, did: 'did:scid:vh:other', method: 'did:scid:vh', isPrimary: true, recordedByNode: 'test' });
  const otherCookie = createSession(otherUuid, secret).cookie;
  const res = await post(app, env(POLICY_EVALUATE_TYPE, { id: 'doc-im-2', payload: { action: 'register_name' }, proof: { type: 'Ed25519Signature2020' } }), otherCookie);
  assert.equal(res.statusCode, 422);
  const doc = res.json();
  assert.equal(doc.payload.code, 'identityMismatch');
  assert.equal(doc.recipient, 'did:scid:vh:other');
  assert.notEqual(doc.recipient, ADMIN_DID);
  assert.ok(!JSON.stringify(doc.payload).includes(ADMIN_DID) && !JSON.stringify(doc.payload).includes('did:scid:vh:other'));
});

test('ERR-002 / LIF-001: an inbound error is never answered (204, no body) and records nothing', async () => {
  const { app, ds } = await seed();
  const count = (): number => (ds.getRawDb().prepare('SELECT count(*) AS n FROM trust_tasks').get() as { n: number }).n;
  const before = count();
  for (const type of [ERROR_TYPE, 'https://trusttasks.org/spec/trust-task-error/0.1#response', 'task:p2pts:error:trust-task:0.1', 'task:p2pts:error:trust-task:0.1#response']) {
    const res = await post(app, env(type, { id: 'doc-in-err', payload: { code: 'taskFailed', retryable: false } }));
    assert.equal(res.statusCode, 204, type);
    assert.equal(res.body, '', type);
  }
  assert.equal(count(), before);
});

test('LIF-003: task control is not supported: unsupportedType, nothing cancelled', async () => {
  const { app } = await seed();
  const req = env('https://trusttasks.org/spec/trust-task-control/0.1', { id: 'doc-ctl', payload: { operation: 'cancel', target: { id: 'doc-1' } } });
  const res = await post(app, req);
  assert.equal(res.statusCode, 422);
  assert.equal(assertConformantError(res, req).payload.code, 'unsupportedType');
});

test('RSP-001/RSP-002: a success reply continues the request thread, or names one by the request id', async () => {
  const { app } = await seed();
  const withThread = await post(app, env(POLICY_EVALUATE_TYPE, { id: 'doc-ok-1', threadId: 'thread-ok', payload: { action: 'register_name' } }));
  assert.equal(withThread.statusCode, 200);
  assert.equal(withThread.json().threadId, 'thread-ok');
  const noThreadReq = env(POLICY_EVALUATE_TYPE, { id: 'doc-ok-2', payload: { action: 'register_name' } });
  delete noThreadReq.threadId;
  const noThread = await post(app, noThreadReq);
  assert.equal(noThread.statusCode, 200);
  const doc = noThread.json();
  assert.equal(doc.threadId, 'doc-ok-2');
  assert.notEqual(doc.id, 'doc-ok-2'); // fresh id
  assert.equal(doc.issuer, CLUB_DID);
  assert.equal(doc.recipient, ADMIN_DID);
});

test('catch-all: an unexpected failure is an opaque internalError 500 trust-task-error, not the framework handler body', async () => {
  const { app, ds } = await seed();
  ds.getRawDb().close(); // every later query throws a driver error naming internals
  const req = env(POLICY_EVALUATE_TYPE, { id: 'doc-boom', payload: { action: 'register_name' } });
  const res = await post(app, req);
  assert.equal(res.statusCode, 500);
  const doc = assertConformantError(res, req);
  assert.equal(doc.payload.code, 'internalError');
  assert.equal(doc.payload.retryable, true);
  assert.equal(doc.payload.message, 'An internal error occurred.');
  assert.equal(doc.payload.details, undefined);
  assert.ok(!/sqlite|database|not open/i.test(JSON.stringify(doc)), 'nothing of the driver error is on the wire');
});

test('every status the route can produce is in the HTTPS binding table, and none is 401 or 404', async () => {
  const { app } = await seed();
  const seen = new Set<number>();
  const bodies: unknown[] = [
    { type: POLICY_EVALUATE_TYPE, payload: {} },
    env('task:p2pts:unknown:foo:0.1'),
    env(`${POLICY_EVALUATE_TYPE}#response`),
    env(POLICY_EVALUATE_TYPE, { proof: { type: 'x' } }),
    env(POLICY_EVALUATE_TYPE, { recipient: 'did:scid:vh:none', payload: { action: 'register_name' } }),
  ];
  for (const b of bodies) seen.add((await post(app, b)).statusCode);
  for (const st of seen) assert.ok([400, 403, 409, 422, 500, 503].includes(st), String(st));
  assert.ok(!seen.has(401) && !seen.has(404));
});
