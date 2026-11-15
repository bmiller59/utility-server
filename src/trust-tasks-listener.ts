// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * The utility server's opt-in Trust Task listener (gate G2 process wiring): the same boundary pipeline
 * as the `POST /trust-tasks` route of the main API, served on its OWN port, Tier 2 by default.
 *
 * DEFAULT OFF. Nothing is bound unless `TRUST_TASKS_LISTENER=1` and `TRUST_TASKS_LISTENER_PORT` are set;
 * the port may not be the API or resolver port; the host defaults to loopback. The listener carries the
 * document surface only (no read routes, no session cookie: the sender is established by the proof inside
 * the document), so it can face a different audience than the administrator API. A bad setting throws and
 * the caller refuses to start; it is not read as a default.
 */
import Fastify from 'fastify';
import type { FastifyInstance } from 'fastify';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { formatBoundaryEvent, isExposedHost, resolveBoundaryListenerSettings } from '@p2p-trust-stack/core/services/trust-tasks/boundary/process-config.js';
import type { BoundaryListenerSettings } from '@p2p-trust-stack/core/services/trust-tasks/boundary/process-config.js';
import { getBoundarySigner } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { registerTrustTaskRoutes } from './routes/layer3-tasks/trust-tasks.js';
import type { TrustTaskRouteOptions } from './routes/layer3-tasks/trust-tasks.js';

export interface UtilityBoundaryListener {
  readonly settings: BoundaryListenerSettings;
  readonly port: number;
  /** Stops accepting, lets requests in flight finish (Fastify close), then returns. */
  close(): Promise<void>;
}

export interface StartUtilityListenerOptions {
  db: DataSource;
  env: Readonly<Record<string, string | undefined>>;
  /** Ports of the other listeners of this process (API, resolver): the boundary may not take them. */
  forbiddenPorts: readonly number[];
  log?: (line: string) => void;
  /** Test hooks. */
  routeOptions?: TrustTaskRouteOptions;
}

export async function startUtilityBoundaryListener(options: StartUtilityListenerOptions): Promise<UtilityBoundaryListener | undefined> {
  const settings = resolveBoundaryListenerSettings(options.env, {}, options.forbiddenPorts);
  if (settings === null) return undefined;
  const log = options.log ?? ((line: string) => console.log(line));
  if (getBoundarySigner() === undefined) {
    throw new Error('Trust Task listener: no boundary signer is installed, so replies could not be signed');
  }
  const app: FastifyInstance = Fastify({ logger: false });
  registerTrustTaskRoutes(app, options.db, { tier: settings.tier, readRoutes: false, ...(options.routeOptions ?? {}) });
  await app.listen({ port: settings.port, host: settings.host });
  const address = app.server.address();
  const port = typeof address === 'object' && address !== null ? address.port : settings.port;
  log(formatBoundaryEvent('listener.started', { host: settings.host, port, tier: settings.tier, signer: getBoundarySigner()?.at === undefined ? 'key-1' : 'dedicated' }));
  if (isExposedHost(settings.host)) log(formatBoundaryEvent('listener.exposed', { host: settings.host, note: 'bound to a non-loopback address' }));
  return {
    settings,
    port,
    close: async () => {
      await app.close();
      log(formatBoundaryEvent('listener.stopped', { port }));
    },
  };
}
