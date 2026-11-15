// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Operator operations for the utility server's dedicated `#key-boundary` key (gate G2): provision,
 * publish, rotate, retire, destroy and status. Library behind `src/scripts/boundary-key.ts`; there is
 * no network or UI route to any of this.
 *
 * Rules (the same as the agent-side `ScidVhAgent` methods and docs/trust-task-boundary-key-runbook.md):
 *  - the key store passphrase is required; there is no default;
 *  - a generation is never overwritten (provision refuses an existing one; publish refuses a key the
 *    document already publishes);
 *  - nothing here returns or prints a secret or a public key: results carry generation, fingerprint
 *    (a hash prefix of the PUBLIC key), versions and notes only;
 *  - fail closed: any problem throws before anything is written. The new log entry is built and
 *    validated in memory (`ScidVhMethod.updateDocument`) and only then appended;
 *  - `execute: false` (the default) validates everything and writes nothing.
 *
 * Publishing goes through the carry-forward document update used on the agent side: an add when
 * `#key-boundary` is absent, a replacement of its key when present, and nothing else in the document
 * can change. The entry is appended to the server's own rotation log in the database through
 * `YugabyteRotationLogStore.appendEntry`, which stores the signed `createdAt` verbatim; the log is not
 * written through `POST /did-documents/:uuid/rotation-log`, so this path does not depend on that route's
 * `createdAt` handling.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';
import type { Ed25519KeyPair } from '@p2p-trust-stack/core/crypto/primitives.js';
import { generateEd25519KeyPairFromSeed } from '@p2p-trust-stack/core/crypto/primitives.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { BOUNDARY_VM_ID } from '@p2p-trust-stack/core/did/document-carry-forward.js';
import { base58btc } from 'multiformats/bases/base58';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { readPersistedSeed } from '@p2p-trust-stack/core/crypto/seed-at-rest.js';
import {
  BoundaryKeyError, boundaryKeyFingerprint, destroyBoundaryKey, loadBoundaryKey, provisionBoundaryKey,
} from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import type { BoundaryKeyStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { YugabyteRotationLogStore } from '../db/yugabyte-rotation-log-store.js';

export type BoundaryAdminCommand = 'provision' | 'publish' | 'rotate' | 'retire' | 'destroy' | 'status';

export interface ServerBoundaryIdentity {
  did: string;
  didDocumentUuid: string;
  /** The did:scid:vh chain's current signing key (derived from `identity.didSeedHex`). */
  identityKeyPair: Ed25519KeyPair;
}

export interface BoundaryAdminContext {
  db: DataSource;
  keystore: BoundaryKeyStore;
  passphrase: string | undefined;
  identity: ServerBoundaryIdentity;
  /** False (default): validate and report, write nothing. */
  execute?: boolean;
  /** Epoch ms for the entry's `createdAt` (default: the clock). */
  now?: number;
}

export interface BoundaryAdminResult {
  command: BoundaryAdminCommand;
  did: string;
  executed: boolean;
  generation?: number;
  /** Hash prefix of the public key of the generation concerned. */
  fingerprint?: string;
  /** Log version of the entry appended (or that would be appended in a dry run). */
  version?: number;
  /** For `status`. */
  published?: { fingerprint: string } | null;
  generationsHeld?: number[];
  note: string;
}

function requirePassphrase(passphrase: string | undefined): string {
  if (passphrase === undefined || passphrase.length === 0) {
    throw new BoundaryKeyError('config', 'TSP_SEED_PASSPHRASE is required; there is no default passphrase');
  }
  return passphrase;
}

function assertGeneration(generation: number): void {
  if (!Number.isInteger(generation) || generation < 1) throw new BoundaryKeyError('config', `generation must be a positive integer, got ${String(generation)}`);
}

/**
 * Locate the server's own identity and the key that signs its chain. Reads `identity.didSeedHex` of the
 * instance config (decrypted with the seed passphrase when stored encrypted). A server without that seed
 * (legacy random identity) is refused: the tool does not guess a signing key.
 */
export async function loadServerBoundaryIdentity(options: { db: DataSource; nodeName: string; configJson: Record<string, unknown>; passphrase: string | undefined }): Promise<ServerBoundaryIdentity> {
  const identity = (await identitiesRepo.findByRole(options.db, 'vta')).find((i) => i.name === options.nodeName);
  if (identity === undefined || identity.did === null) {
    throw new BoundaryKeyError('config', `no server identity named ${options.nodeName} in the database; start the server once first`);
  }
  const doc = await didDocumentsRepo.findPrimaryForIdentity(options.db, identity.uuid);
  if (doc === null) throw new BoundaryKeyError('config', 'the server identity has no primary DID document');
  const seed = await readPersistedSeed((options.configJson.identity as { didSeedHex?: unknown } | undefined)?.didSeedHex, options.passphrase, 'identity.didSeedHex');
  if (seed === undefined) throw new BoundaryKeyError('config', 'config.json holds no identity.didSeedHex; this server\'s chain key cannot be located');
  return { did: identity.did, didDocumentUuid: doc.uuid, identityKeyPair: generateEd25519KeyPairFromSeed(new Uint8Array(Buffer.from(seed.hex, 'hex'))) };
}

function publishedBoundaryKey(doc: DidDocument): Uint8Array | null {
  const vm = doc.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID);
  if (vm === undefined) return null;
  try {
    const raw = base58btc.decode(vm.publicKeyMultibase);
    return raw.length === 34 && raw[0] === 0xed && raw[1] === 0x01 ? raw.slice(2) : null;
  } catch {
    return null;
  }
}

async function currentLog(ctx: BoundaryAdminContext): Promise<RotationLogEntry[]> {
  const log = await new YugabyteRotationLogStore(ctx.db).getLog(ctx.identity.didDocumentUuid);
  if (log.length === 0) throw new BoundaryKeyError('config', 'the server identity has no rotation log entries');
  return log;
}

/** The latest published `#key-boundary` key of the server's own log, or null. */
export async function readPublishedBoundaryKey(db: DataSource, didDocumentUuid: string): Promise<Uint8Array | null> {
  const log = await new YugabyteRotationLogStore(db).getLog(didDocumentUuid);
  const last = log[log.length - 1];
  return last === undefined ? null : publishedBoundaryKey(last.didDocument);
}

/**
 * The server's runtime document with the boundary method taken over from the latest entry of its own
 * rotation log, for the start-up check that the document publishes the key held. Only `#key-boundary` and
 * its `authentication` entry are taken; everything else of `local` is kept. A log that cannot be read, or
 * that lists the method without a usable key, throws: dedicated mode never starts on a guess.
 */
export async function withPublishedBoundaryKey(db: DataSource, didDocumentUuid: string, local: DidDocument): Promise<DidDocument> {
  const log = await new YugabyteRotationLogStore(db).getLog(didDocumentUuid);
  const last = log[log.length - 1];
  if (last === undefined) throw new BoundaryKeyError('notPublished', 'the server\'s rotation log is empty');
  const vm = last.didDocument.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID);
  const doc = structuredClone(local);
  doc.verificationMethod = doc.verificationMethod.filter((v) => v.id !== BOUNDARY_VM_ID);
  doc.authentication = (doc.authentication ?? []).filter((a) => a !== BOUNDARY_VM_ID);
  if (vm !== undefined) {
    doc.verificationMethod.push({ ...vm });
    if (last.didDocument.authentication?.includes(BOUNDARY_VM_ID) === true) doc.authentication = [...doc.authentication, BOUNDARY_VM_ID];
  }
  return doc;
}

async function heldGenerations(ctx: BoundaryAdminContext, passphrase: string, upTo = 16): Promise<number[]> {
  const held: number[] = [];
  for (let g = 1; g <= upTo; g++) {
    try {
      await loadBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, passphrase, generation: g });
      held.push(g);
    } catch (err) {
      if (err instanceof BoundaryKeyError && err.code === 'missing') continue;
      throw err; // corrupt or wrong passphrase: do not pretend the slot is empty
    }
  }
  return held;
}

/** Build the entry that publishes (add or replace) the key of `generation`, validated in memory, not appended. */
async function buildPublishEntry(ctx: BoundaryAdminContext, passphrase: string, generation: number, mode: 'add' | 'replace'): Promise<{ entry: RotationLogEntry; fingerprint: string }> {
  const pair = await loadBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, passphrase, generation });
  const log = await currentLog(ctx);
  const published = publishedBoundaryKey(log[log.length - 1]!.didDocument);
  if (mode === 'add' && published !== null) throw new BoundaryKeyError('exists', `${BOUNDARY_VM_ID} is already published; use rotate to replace it`);
  if (mode === 'replace' && published === null) throw new BoundaryKeyError('notPublished', `${BOUNDARY_VM_ID} is not published yet; use publish for the first publication`);
  if (published !== null && Buffer.compare(Buffer.from(published), Buffer.from(pair.publicKey)) === 0) {
    throw new BoundaryKeyError('exists', `generation ${generation} is already the published key; a generation is never re-published`);
  }
  const method = new ScidVhMethod();
  const params = { currentLog: log, identityKeyPair: ctx.identity.identityKeyPair, boundaryPublicKey: pair.publicKey, ...(ctx.now === undefined ? {} : { now: ctx.now }) };
  const entry = mode === 'add' ? await method.addBoundaryKey(params) : await method.rotateBoundaryKey(params);
  return { entry, fingerprint: boundaryKeyFingerprint(pair.publicKey) };
}

export async function runBoundaryAdmin(command: BoundaryAdminCommand, ctx: BoundaryAdminContext, options: { generation?: number } = {}): Promise<BoundaryAdminResult> {
  const passphrase = requirePassphrase(ctx.passphrase);
  const execute = ctx.execute === true;
  const base = { command, did: ctx.identity.did, executed: execute } as const;
  const generation = options.generation;

  if (command === 'status') {
    const log = await currentLog(ctx);
    const published = publishedBoundaryKey(log[log.length - 1]!.didDocument);
    return {
      ...base, executed: false,
      published: published === null ? null : { fingerprint: boundaryKeyFingerprint(published) },
      generationsHeld: await heldGenerations(ctx, passphrase),
      note: published === null ? 'no #key-boundary published' : '#key-boundary published',
    };
  }

  if (command === 'retire') {
    const log = await currentLog(ctx);
    if (publishedBoundaryKey(log[log.length - 1]!.didDocument) === null) throw new BoundaryKeyError('notPublished', `${BOUNDARY_VM_ID} is not published; nothing to retire`);
    const entry = await new ScidVhMethod().retireBoundaryKey({ currentLog: log, identityKeyPair: ctx.identity.identityKeyPair, ...(ctx.now === undefined ? {} : { now: ctx.now }) });
    if (execute) await new YugabyteRotationLogStore(ctx.db).appendEntry(ctx.identity.didDocumentUuid, entry);
    return { ...base, version: entry.version, note: execute ? 'retired: #key-boundary removed from the document' : 'dry run: would remove #key-boundary (nothing written)' };
  }

  if (generation === undefined) throw new BoundaryKeyError('config', `${command} needs a generation`);
  assertGeneration(generation);

  if (command === 'provision') {
    // Never overwrites: provisionBoundaryKey refuses an existing generation. A dry run probes for absence only.
    if (!execute) {
      try {
        await loadBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, passphrase, generation });
      } catch (err) {
        if (err instanceof BoundaryKeyError && err.code === 'missing') return { ...base, generation, note: `dry run: generation ${generation} is absent and would be provisioned (nothing written)` };
        throw err;
      }
      throw new BoundaryKeyError('exists', `generation ${generation} already exists for ${ctx.identity.did}; it is never overwritten`);
    }
    const out = await provisionBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, passphrase, generation });
    return { ...base, generation, fingerprint: out.fingerprint, note: 'provisioned; publish it next' };
  }

  if (command === 'publish' || command === 'rotate') {
    // publish: first publication (add). rotate: replace the published key with a NEW generation.
    const mode = command === 'publish' ? 'add' : 'replace';
    const { entry, fingerprint } = await buildPublishEntry(ctx, passphrase, generation, mode);
    if (execute) await new YugabyteRotationLogStore(ctx.db).appendEntry(ctx.identity.didDocumentUuid, entry);
    const next = command === 'rotate' ? `; set BOUNDARY_KEY_GENERATION=${generation} and restart` : '; after propagation set TRUST_TASKS_BOUNDARY_KEY=dedicated and BOUNDARY_KEY_CUTOVER_AT, then restart';
    return { ...base, generation, fingerprint, version: entry.version, note: execute ? `published${next}` : 'dry run: entry built and validated, nothing written' };
  }

  // destroy: delete the stored secret of a generation the document does not publish.
  const log = await currentLog(ctx);
  const published = publishedBoundaryKey(log[log.length - 1]!.didDocument);
  const pair = await loadBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, passphrase, generation });
  if (published !== null && Buffer.compare(Buffer.from(published), Buffer.from(pair.publicKey)) === 0) {
    throw new BoundaryKeyError('exists', `generation ${generation} is the key the document publishes; retire or rotate first`);
  }
  if (execute) destroyBoundaryKey({ store: ctx.keystore, vid: ctx.identity.did, generation });
  return { ...base, generation, fingerprint: boundaryKeyFingerprint(pair.publicKey), note: execute ? 'secret destroyed' : 'dry run: would destroy the stored secret (nothing written)' };
}

// ---------------------------------------------------------------------------
// Locations shared by the server start-up and the operator tool
// ---------------------------------------------------------------------------

/** The instance data directory: `UTILITY_DATA_DIR` or `<repo>/data` (the same rule as the setup state). */
export function resolveDataDir(env: Readonly<Record<string, string | undefined>>, defaultDir: string): string {
  const v = env.UTILITY_DATA_DIR;
  return v !== undefined && v !== '' ? v : defaultDir;
}

/** The boundary key store file: `BOUNDARY_KEYSTORE_PATH`, else `boundary-keystore.db` beside config.json. */
export function resolveBoundaryKeystorePath(env: Readonly<Record<string, string | undefined>>, dataDir: string): string {
  const v = env.BOUNDARY_KEYSTORE_PATH;
  return v !== undefined && v !== '' ? v : `${dataDir}/boundary-keystore.db`;
}
