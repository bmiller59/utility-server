// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3 — Trust Tasks: `POST /trust-tasks` (the document-level bridge, P5.5).
 *
 * This is the ONE endpoint that speaks the Trust Task envelope: an inbound document
 * carrying `{id, type, threadId, issuer, recipient, issuedAt, payload, proof}` is parsed,
 * its `proof` checked for transport attribution, its `type` routed to a policy
 * operation, and the reply wrapped back into an envelope.
 *
 * It REUSES the P4 policy logic (`gatePolicy`, `createPolicyEngine`'s validate/evaluate,
 * the governance repo) rather than reimplementing it — the bridge only adds framing.
 * Our `type` identifiers are `task:p2pts:…` (see `src/services/trust-tasks/type-uris.ts`).
 *
 * ## The correctness rule
 *
 * A document carrying a `proof` whose issuer is NOT authenticated by this transport is
 * INDETERMINATE — we refuse it (`identityMismatch`, 422) rather than act as its
 * content asks. This is the transport-edge realization of "indeterminate, not allow":
 * a proof proves *who asked*, never *that they may*, and without a transport binding we
 * cannot even attribute it. We do NOT verify the proof's cryptosuite here (crypto stays
 * in `GovernanceGuard`) — we only require that the `issuer` matches the session's
 * authenticated identity.
 *
 * ## Envelope → operation mapping
 *
 * The `recipient` is the community DID (`task:p2pts:policy:*` always names a community to
 * act on); the `issuer` is the actor DID; the `payload` carries the operation body:
 *
 *   evaluate — payload `{ action, kind?, subjectDid?, facts? }`  → `gatePolicy` (real facts)
 *   test     — payload `{ policy, query, data? }`                 → engine dry-run on supplied input
 *   validate — payload `{ policy }`                               → engine.validatePolicy
 *   upsert   — payload `{ policy }`                               → validate + persist + fan-out
 *
 * ## Errors
 *
 * Every refusal is a framework `trust-task-error` document (built by the core boundary's
 * `buildErrorDocument`), threaded and addressed per the framework, with a status from the HTTPS
 * binding's table (`httpStatusForCode`): 400 `malformedRequest`, 422 for `unsupportedType`,
 * `wrongRecipient`, `identityMismatch` and the other refusals, 500 `internalError`. Messages come
 * from a fixed vocabulary; nothing the requester sent is echoed. Anything thrown that is not a
 * `TaskError` is the catch-all: an opaque `internalError`, logged here, never leaked. A document
 * that is itself an error is never answered (204, no body).
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import {
  listCeremonyThreads,
  getCeremonyThread,
} from '@p2p-trust-stack/core/services/trust-tasks/ceremony-log.js';
import { POLICY_ACTIONS } from '@p2p-trust-stack/core/services/policy-engine.js';
import type { PolicyQuery } from '@p2p-trust-stack/core/services/policy-engine.js';
import {
  parseTrustTask,
  buildResponse,
  isIndeterminateForProof,
  typeUriToOperation,
} from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import type {
  TrustTaskDocument,
  PolicyDocumentOperation,
} from '@p2p-trust-stack/core/services/trust-tasks/index.js';
import { gatePolicy } from '@p2p-trust-stack/core/services/policy-gate.js';
import {
  HTTP_STATUS_NO_CONTENT,
  TaskError,
  buildErrorDocument,
  httpStatusForCode,
  isInboundError,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import type { ErrorRequestRef } from '@p2p-trust-stack/core/services/trust-tasks/boundary/errors.js';
import { validateSession } from '../../session.js';

function payloadOf(doc: TrustTaskDocument): Record<string, unknown> {
  return (typeof doc.payload === 'object' && doc.payload !== null
    ? doc.payload
    : {}) as Record<string, unknown>;
}

/** Resolve the community named by the envelope's `recipient` DID. */
async function resolveCommunityByDid(
  db: DataSource,
  did: string | undefined,
): Promise<{ uuid: string; did: string; role: string }> {
  if (!did || typeof did !== 'string' || did.length === 0) {
    throw new TaskError({ code: 'malformedRequest', internalMessage: 'recipient (community DID) is required' });
  }
  const identity = await identitiesRepo.findByRealDid(db, did);
  if (!identity || !identity.did) {
    throw new TaskError({ code: 'wrongRecipient', internalMessage: `community ${did} not found` });
  }
  return { uuid: identity.uuid, did: identity.did, role: identity.role };
}

/** The DID the session cookie authenticates, if any. The transport-authenticated sender. */
async function sessionDid(
  db: DataSource,
  cookie: string | undefined,
  secret: Buffer,
): Promise<string | undefined> {
  const session = validateSession(cookie, secret);
  if (!session) return undefined;
  const identity = await identitiesRepo.findByUuid(db, session.identityUuid);
  return identity?.did ?? undefined;
}

async function evaluateTask(db: DataSource, doc: TrustTaskDocument): Promise<unknown> {
  const community = await resolveCommunityByDid(db, doc.recipient);
  const p = payloadOf(doc);
  const action = p.action;
  if (typeof action !== 'string' || !action) {
    throw new TaskError({ code: 'malformedRequest', internalMessage: 'payload.action is required' });
  }
  if (!(POLICY_ACTIONS as readonly string[]).includes(action)) {
    throw new TaskError({ code: 'malformedRequest', internalMessage: `unknown action '${action}'` });
  }
  const params: Record<string, unknown> = {};
  if (p.kind !== undefined) params.kind = p.kind;
  if (p.subjectDid !== undefined) params.subjectDid = p.subjectDid;
  const query: PolicyQuery = {
    action: action as PolicyQuery['action'],
    communityDid: community.did,
    actorDid: typeof doc.issuer === 'string' && doc.issuer ? doc.issuer : community.did,
    params,
  };
  const facts = (p.facts && typeof p.facts === 'object')
    ? p.facts as Record<string, unknown>
    : undefined;
  const result = await gatePolicy(db, query, facts);
  return { communityUuid: community.uuid, communityDid: community.did, query, result };
}

/**
 * Dispatch a policy trust-task operation. Only the read-only `evaluate` remains — the
 * document-writing ops (`upsert`/`test`/`validate`) were the utility server's developer
 * policy API and are removed. Governance changes flow through the governance-change
 * ceremony (Phase B), never a direct document write.
 */
async function dispatch(db: DataSource, op: PolicyDocumentOperation, doc: TrustTaskDocument): Promise<unknown> {
  if (op === 'evaluate') return evaluateTask(db, doc);
  throw new TaskError({ code: 'unsupportedType', internalMessage: `unsupported operation '${op}'` });
}

/**
 * Reply with a framework error document and the binding's status for its code. `recipient` is the
 * transport-authenticated sender when the in-band identity is contested; otherwise the in-band issuer.
 */
function sendError(
  reply: FastifyReply,
  request: ErrorRequestRef | undefined,
  error: unknown,
  recipient?: string,
) {
  const doc = buildErrorDocument(request, error, recipient === undefined ? {} : { recipient });
  return reply.code(httpStatusForCode(doc.payload.code)).send(doc);
}

/** What an unparseable body still tells us safely: identifiers only, never addressing. */
function partialRef(body: unknown): ErrorRequestRef | undefined {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return undefined;
  const b = body as Record<string, unknown>;
  return { id: b.id, type: b.type, threadId: b.threadId };
}

export function registerTrustTaskRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/trust-tasks',
    async (req: FastifyRequest<{ Body: unknown }>, reply: FastifyReply) => {
      // 1. Parse the envelope.
      const parsed = parseTrustTask(req.body);
      if (!parsed.ok) {
        return sendError(reply, partialRef(req.body), new TaskError({ code: 'malformedRequest', internalMessage: parsed.message }));
      }
      const doc = parsed.document;

      // 2. An error document is never answered (no error loops) and changes nothing.
      if (isInboundError(doc)) {
        return reply.code(HTTP_STATUS_NO_CONTENT).send();
      }

      // 3. A response document is not a request.
      if (doc.type.endsWith('#response')) {
        return sendError(reply, doc, new TaskError({ code: 'malformedRequest', internalMessage: 'a #response document is not a request' }));
      }

      // 4. Transport attribution of the issuer.
      const hmacSecret = (app as unknown as { hmacSecret?: Buffer }).hmacSecret;
      const senderDid = hmacSecret ? await sessionDid(db, req.headers.cookie, hmacSecret) : undefined;
      const authenticated = senderDid !== undefined && senderDid === doc.issuer;

      // 5. proof → indeterminate (never silently allow). The error goes to the authenticated sender
      //    when there is one (framework 8.1), never to the contested in-band issuer.
      if (isIndeterminateForProof(doc, authenticated)) {
        return sendError(reply, doc, new TaskError({ code: 'identityMismatch' }), senderDid);
      }

      // 6. Route by type.
      const op = typeUriToOperation(doc.type);
      if (!op) {
        return sendError(reply, doc, new TaskError({ code: 'unsupportedType' }));
      }

      // 7. Dispatch, and wrap the reply. Whatever is thrown is mapped; only a `TaskError` has a
      //    defined wire form, anything else is logged and answered as an opaque internalError.
      try {
        const result = await dispatch(db, op, doc);
        return reply.send(buildResponse(doc, result));
      } catch (err) {
        if (!(err instanceof TaskError)) req.log.error({ err }, 'trust-tasks: unexpected failure');
        return sendError(reply, doc, err);
      }
    },
  );

  // ── GET /trust-tasks/threads — the ceremony task-log index ────────────────
  // One entry per ceremony RUN, newest first. Registered before the `:threadId`
  // route in intent — Fastify resolves the static segment first, so `threads` is
  // never read as a thread id.
  app.get('/trust-tasks/threads', async () => ({ threads: await listCeremonyThreads(db) }));

  // ── GET /trust-tasks/:threadId — read a ceremony's task record ────────────
  // The queryable half of the audit trail: given a ceremony `threadId`
  // (= the ceremonyId), return every recorded task document in record order.
  app.get(
    '/trust-tasks/:threadId',
    async (req: FastifyRequest<{ Params: { threadId: string } }>) => ({
      threadId: req.params.threadId,
      tasks: await getCeremonyThread(db, req.params.threadId),
    }),
  );
}
