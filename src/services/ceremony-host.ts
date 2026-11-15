// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The production host of the founding-ceremony documents (`ceremony:propose`, `ceremony:co-sign`, `ceremony:status`,
 * `ceremony:reset`) on the Trust Task boundary: the core ceremony-doc handlers and participant (one copy of the rules, D1.2)
 * with this server's real establishing effect injected.
 *
 *   - Approvals count by the pipeline-verified document proof (D1.1): the participant requires boundary-verified
 *     approvals and the core effect hands them to the governance guard marked pre-verified. The legacy REST/TSP participant
 *     is a separate participant and still checks a signature over the proposal hash.
 *   - The effect is checked at prepare and applied at commit (D1.3), from `pending_ops`; `reconcile()` finishes prepared
 *     transactions after a restart (run once at boot).
 *   - The establishment is core's `CommunityFoundingEffect` (the real `createVtc`, the crystallization policy, DID to
 *     identity mapping, stub identities); this server supplies the post-commit, queue-backed fan-out.
 *
 * OFF BY DEFAULT. `TRUST_TASKS_CEREMONY_HOST=1` serves the four types on the boundary (the main API's `POST /trust-tasks`
 * and the dedicated listener, when that is on); unset, `0` or empty serves nothing new; any other value is refused at
 * startup, not read as a default. The participant is NOT registered with the coordinator's shared registry: it uses the same
 * operation names as the legacy ceremony participant, so registering it would overlap the dispatch partition and could
 * route a remote `ceremony_*` message to it. It is enlisted by the handlers directly, and recovered by `reconcile()`.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { AcceptedIdStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/accepted-store.js';
import { createCeremonyDocHandlers } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-doc.js';
import type { CeremonyTransactions } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-doc.js';
import type { PipelineHandler } from '@p2p-trust-stack/core/services/trust-tasks/boundary/handlers.js';
import type { ReplayGuard } from '@p2p-trust-stack/core/services/trust-tasks/boundary/runtime.js';
import { CommunityFoundingEffect } from '@p2p-trust-stack/core/services/founding/community-effect.js';
import type { EstablishedCommunity } from '@p2p-trust-stack/core/services/founding/community-effect.js';
import { CeremonyDocParticipant } from '@p2p-trust-stack/core/tx/ceremony-doc-participant.js';
import { tryEnqueueFanout } from './exchange-runtime.js';
import { enqueueFoundingAdminVmcFanout } from './vtc-push-data.js';

export const CEREMONY_HOST_FLAG = 'TRUST_TASKS_CEREMONY_HOST';

/** Read the opt-in flag. A value that is not `1`, `0` or empty is an error (the caller refuses to start). */
export function ceremonyHostRequested(env: Readonly<Record<string, string | undefined>>): boolean {
  const v = env[CEREMONY_HOST_FLAG];
  if (v === undefined || v === '' || v === '0') return false;
  if (v === '1') return true;
  throw new Error(`${CEREMONY_HOST_FLAG} must be 1 or 0 (got "${v}")`);
}

export interface CeremonyHostDeps {
  appDb: DataSource;
  /** The tx-coordinator database the participant keeps its state in. */
  txDb: DataSource;
  txManager: CeremonyTransactions;
  serverId?: string;
  /** Test hook: the post-commit fan-out. Default: the community package, then each founding admin's VMC, through the delivery queue. */
  fanout?: (community: EstablishedCommunity) => Promise<void>;
}

export interface CeremonyHost {
  handlers: PipelineHandler[];
  /** The duplicate record the route must share with the handlers (the handlers attach each transaction id to it). */
  guard: ReplayGuard;
  participant: CeremonyDocParticipant;
  /** Finish the prepared transactions the coordinator decided (boot). */
  reconcile(): Promise<{ committed: string[]; aborted: string[]; failed: string[] }>;
}

/** The legacy participant's fan-out, as the boundary path now does it: after the atomic establishment, the community package then the founding VMCs. */
export async function queueFanout(community: EstablishedCommunity): Promise<void> {
  await tryEnqueueFanout('vtc-membership', { communityUuid: community.communityUuid });
  await enqueueFoundingAdminVmcFanout(community.foundingAdmins);
}

export function createCeremonyHost(deps: CeremonyHostDeps): CeremonyHost {
  const effect = new CommunityFoundingEffect(deps.appDb, { afterEstablished: deps.fanout ?? queueFanout });
  const participant = new CeremonyDocParticipant(`ceremony-doc:${deps.serverId ?? 'us-1'}`, deps.txDb, effect, { requireVerifiedApprovals: true });
  const guard = new AcceptedIdStore(deps.appDb);
  const handlers = createCeremonyDocHandlers({
    txManager: deps.txManager,
    participant,
    attachTx: (id, txId) => guard.attachTx(id, txId),
  });
  return { handlers, guard, participant, reconcile: () => participant.reconcile((txId) => deps.txManager.getOutcome(txId)) };
}
