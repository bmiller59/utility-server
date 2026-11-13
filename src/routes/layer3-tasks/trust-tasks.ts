// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 3 — Trust Tasks: `POST /trust-tasks` (the document-level bridge, P5.5).
 *
 * This is the ONE endpoint that speaks the Trust Task envelope. Since conformance phase P2 it is a
 * thin carrier over the core boundary pipeline (`boundary/pipeline.ts`): the route captures the raw
 * body, establishes the transport-authenticated sender (the session cookie, or none) and hands both
 * to the pipeline, which does everything else (envelope and type validation, payload check,
 * freshness, recipient, sender cross-check, the interim proof policy, dispatch to the handler
 * registry, typed errors) and says what to send back. The route maps that onto HTTP.
 *
 * ## Served types
 *
 * The legacy `policy/evaluate` task (core `boundary/legacy-evaluate.ts`), under its internal name
 * `task:p2pts:policy:evaluate:0.1` and its wire form `urn:p2pts:tasks:spec:policy:evaluate:0.1`, and
 * `trust-task-discovery` 0.4 (core `boundary/discovery.ts`), which lists exactly what is registered.
 * Anything else, `trust-task-control` included, is `unsupportedType`/`unsupportedVersion`.
 *
 * ## Sender and proof
 *
 * The authenticated sender is the session cookie's identity. A document whose in-band `issuer`
 * differs from it is `identityMismatch`, addressed to the authenticated sender (framework 8.1).
 * Proof checks are never off: a document carrying a `proof` is verified by the DID-resolving
 * verifier (core `boundary/proof/verify.ts`: did:key, did:peer:4, did:scid:vh from the server's
 * rotation logs, never a cached snapshot); a proof that does not verify is `proofInvalid`, a
 * resolution that cannot be completed is `unavailable`. The cookie remains a cross-check only. A
 * caller with neither a cookie nor a verified proof is unauthenticated: `policy/evaluate` then
 * answers `permissionDenied` (403; conformance P5, decision C5), because the verified sender is the
 * policy actor and an in-band `issuer` alone never is. Replies are signed as the server's own DID with the
 * installed boundary signer (`#key-1`, `authentication`); `TRUST_TASKS_TIER=2` selects the
 * `attested` profile (proof on every request, every reply signed).
 *
 * ## Strictness (one release)
 *
 * `TRUST_TASKS_STRICTNESS=lenient` (default `strict`; any other value is `strict`) lets the legacy
 * evaluate task through with a stale or future `issuedAt` and an unserved `recipient` (the handler
 * still resolves the community), logging each. It never relaxes the proof policy.
 *
 * ## Body and statuses
 *
 * The body is read raw (the pipeline parses it, and the bytes are retained on its result for the
 * persistence phase). Statuses are the HTTPS binding's: 200 response, 204 absorbed (an inbound
 * error is never answered), 202 in flight, the code-to-status table for errors; an unparseable or
 * oversize body gets a minimal unsigned 400/413 body (415 for a content type other than JSON) that is not a Trust Task document. The path is
 * `/trust-tasks` unless the deployment passes another.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import {
  listCeremonyThreads,
  getCeremonyThread,
} from '@p2p-trust-stack/core/services/trust-tasks/ceremony-log.js';
import {
  DEFAULT_MAX_BODY_BYTES,
  Pipeline,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import type {
  PipelineResult,
  Strictness,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/pipeline.js';
import {
  createLegacyEvaluateHandler,
  isHostedCommunity,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/legacy-evaluate.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { HandlerRegistry } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import { registerDiscovery } from '@p2p-trust-stack/core/services/trust-tasks/boundary/discovery.js';
import type { ReplayGuard } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { TrustTaskRecorder } from '@p2p-trust-stack/core/services/trust-tasks/boundary/recorder.js';
import { DidResolutionService } from '@p2p-trust-stack/core/did/did-resolution-service.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { createServerKeyResolver } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/install.js';
import { getBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import type { BoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { getServerNodeInfo } from '../../services/server-node-info.js';
import { validateSession } from '../../session.js';

export interface TrustTaskRouteOptions {
  /** Default: `TRUST_TASKS_STRICTNESS` (`lenient` or `strict`), else `strict`. */
  strictness?: Strictness;
  /**
   * The identifier replies and errors are issued by when the document names no hosted community.
   * Default: the server's own DID (`getServerNodeInfo().did`, recorded at startup from the server's
   * VTA identity, the same identifier its boundary signer signs as); unset in processes that have
   * not recorded one (tests), where the pre-P4 fallback applies.
   */
  defaultVid?: string;
  /**
   * 1 (default): proofs are verified when present, unsigned requests to tasks that do not require a
   * proof stay accepted. 2: the `attested` profile (proof required on every request, purpose pinned,
   * every reply signed). Default from `TRUST_TASKS_TIER` (`2` selects the attested profile).
   */
  tier?: 1 | 2;
  /** Replies are signed with this identity; default the process's installed boundary signer. */
  signer?: BoundarySigner | (() => BoundarySigner | undefined);
  /**
   * Persist what the boundary processes (decision A4): verbatim raw document, proof, digests and
   * verified signer in `trust_tasks`, never a body refused before proof verification. Default true.
   */
  recordDocuments?: boolean;
  /** The proof verifier; default one resolving did:key, did:peer:4 and did:scid:vh (log only, never a cached snapshot). */
  verifier?: DidProofVerifier;
  /** Default `/trust-tasks`; deployments differ on paths (HTTPS binding). */
  path?: string;
  /** Test hook: the clock, epoch milliseconds. */
  now?: () => number;
  /**
   * Duplicate record for consequential handlers. Default: the durable `AcceptedIdStore` over the
   * application database (table `trust_task_accepted`, migration 0021). Today only the read-only
   * evaluate task is served, which takes no claim, so the default changes no behaviour.
   */
  guard?: ReplayGuard;
  /** Further handlers beside the legacy evaluate handler (tests; later phases register theirs here). */
  extraHandlers?: readonly PipelineHandler[];
  /** How often closed duplicate-record windows are pruned, ms. Default 10 minutes; 0 disables. */
  pruneIntervalMs?: number;
  /** Test hook: sees every pipeline result (raw bytes included) before the reply is sent. */
  observe?: (result: PipelineResult) => void;
}

export function tierFromEnv(value: string | undefined): 1 | 2 {
  return value === '2' ? 2 : 1;
}

export function strictnessFromEnv(value: string | undefined): Strictness {
  return value === 'lenient' ? 'lenient' : 'strict';
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

function reply(res: FastifyReply, result: PipelineResult) {
  res.code(result.status);
  if (result.status === 204 || result.status === 202) return res.send();
  const body = result.document !== undefined ? result.document : result.minimal;
  // The exact text sent is the document as built: a signed reply (P4) is signed over these bytes.
  return res.header('content-type', 'application/json; charset=utf-8').send(JSON.stringify(body));
}

export function registerTrustTaskRoutes(
  app: FastifyInstance,
  db: DataSource,
  options: TrustTaskRouteOptions = {},
): void {
  const strictness = options.strictness ?? strictnessFromEnv(process.env.TRUST_TASKS_STRICTNESS);
  const acceptedStore = new AcceptedIdStore(db, options.now === undefined ? {} : { now: options.now });
  const recorder = options.recordDocuments === false ? undefined : new TrustTaskRecorder(db, { node: 'utility-server', onError: (err) => app.log.error({ err }, 'trust-tasks: recording a document failed') });
  const pipeline = new Pipeline({
    handlers: registerDiscovery(new HandlerRegistry([createLegacyEvaluateHandler(db), ...(options.extraHandlers ?? [])])),
    guard: options.guard ?? acceptedStore,
    isServed: (recipient) => isHostedCommunity(db, recipient),
    defaultVid: options.defaultVid ?? (() => getServerNodeInfo()?.did ?? undefined),
    proof: {
      verifier: options.verifier ?? new DidProofVerifier({ resolver: createServerKeyResolver(new DidResolutionService(db)) }),
      tier: options.tier ?? tierFromEnv(process.env.TRUST_TASKS_TIER),
    },
    signer: options.signer ?? getBoundarySigner,
    ...(recorder === undefined ? {} : { record: (result: PipelineResult) => recorder.record(result) }),
    ...(options.now === undefined ? {} : { now: options.now }),
    strictness,
    onUnexpected: (err) => app.log.error({ err }, 'trust-tasks: unexpected failure'),
    onLenient: (event) => app.log.warn({ event }, 'trust-tasks: lenient strictness let a document through'),
    maxBodyBytes: DEFAULT_MAX_BODY_BYTES,
  });

  // Janitor hook: drop duplicate-record rows whose window has closed. Unref'd, stopped on close; a failed
  // pass is logged and retried on the next tick.
  const pruneIntervalMs = options.pruneIntervalMs ?? 10 * 60_000;
  if (pruneIntervalMs > 0) {
    const timer = setInterval(() => {
      acceptedStore.pruneExpired().catch((err: unknown) => app.log.error({ err }, 'trust-tasks: pruning the duplicate record failed'));
    }, pruneIntervalMs);
    timer.unref();
    app.addHook('onClose', async () => clearInterval(timer));
  }

  // The POST route lives in its own encapsulated scope so the raw-body parser applies to it alone.
  void app.register(async (scope) => {
    scope.removeContentTypeParser('application/json');
    scope.addContentTypeParser(
      'application/json',
      { parseAs: 'buffer', bodyLimit: DEFAULT_MAX_BODY_BYTES },
      (_req, body, done) => done(null, body),
    );
    scope.post(
      options.path ?? '/trust-tasks',
      { bodyLimit: DEFAULT_MAX_BODY_BYTES },
      async (req: FastifyRequest<{ Body: Buffer | undefined }>, res: FastifyReply) => {
        const hmacSecret = (app as unknown as { hmacSecret?: Buffer }).hmacSecret;
        const sender = hmacSecret ? await sessionDid(db, req.headers.cookie, hmacSecret) : undefined;
        // Only `application/json` is raw-captured; any other content type (Fastify still parses
        // text/plain, for one) is refused before the pipeline.
        if (!Buffer.isBuffer(req.body)) {
          return res.code(415).header('content-type', 'application/json; charset=utf-8').send(
            JSON.stringify({ code: 'malformedRequest', message: 'The content type must be application/json.', retryable: false }),
          );
        }
        const raw = req.body;
        const result = await pipeline.process({ raw, sender });
        options.observe?.(result);
        return reply(res, result);
      },
    );
  });

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
