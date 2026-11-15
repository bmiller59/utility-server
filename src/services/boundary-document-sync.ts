// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * K4: one document, three places. After `#key-boundary` is published in the server's own rotation log, the
 * cached `did_documents.document_json` and the document served in the TSP handshake must list the same
 * boundary method as the log head. They cannot be made equal to the head as a whole: `document_json` carries
 * live transport endpoints the log omits (report 69, decision 6), so only the boundary method is compared and
 * taken over; `verificationMethod` entries other than `#key-boundary`, the other `authentication` entries and
 * every other member stay exactly as they are, and no other column of the row is written.
 *
 * Rules:
 *  - the head's chain is validated (`ScidVhMethod.validateEntries`, whole log, bound to the DID) before anything
 *    is taken from it; an invalid chain repairs and overlays nothing;
 *  - dedicated mode fails closed: an unreadable or invalid log, or an unreadable row, throws before the server
 *    serves anything. With the gate off the server keeps serving the document it has and logs a warning, since
 *    nothing signs with the boundary key there;
 *  - the overlay also applies with the gate off once the key is published. Cutover order (runbook): publish and
 *    confirm through the resolver, then set the gate and the cutover time; signing stays `#key-1` until the cutover.
 */
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { DidDocument } from '@p2p-trust-stack/core/did/types.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';
import { ScidVhMethod } from '@p2p-trust-stack/core/did/scid-vh-method.js';
import { BOUNDARY_VM_ID } from '@p2p-trust-stack/core/did/document-carry-forward.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import { BoundaryKeyError } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { YugabyteRotationLogStore } from '../db/yugabyte-rotation-log-store.js';

/**
 * `local` with its boundary method taken over from `head` (the log head's document): the method and its
 * `authentication` entry are replaced, or removed when the head has none. Everything else of `local` is kept.
 */
export function overlayBoundaryKey(local: DidDocument, head: DidDocument): DidDocument {
  const vm = head.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID);
  const doc = structuredClone(local);
  doc.verificationMethod = doc.verificationMethod.filter((v) => v.id !== BOUNDARY_VM_ID);
  doc.authentication = (doc.authentication ?? []).filter((a) => a !== BOUNDARY_VM_ID);
  if (vm !== undefined) {
    doc.verificationMethod.push({ ...vm });
    if (head.authentication?.includes(BOUNDARY_VM_ID) === true) doc.authentication = [...doc.authentication, BOUNDARY_VM_ID];
  }
  return doc;
}

/** Only the boundary method of a document, in a comparable form. */
function boundaryView(doc: DidDocument): string {
  const vm = doc.verificationMethod.find((v) => v.id === BOUNDARY_VM_ID);
  return JSON.stringify({ vm: vm === undefined ? null : { id: vm.id, type: vm.type, controller: vm.controller, publicKeyMultibase: vm.publicKeyMultibase }, auth: (doc.authentication ?? []).includes(BOUNDARY_VM_ID) });
}

export type BoundarySyncAction =
  /** No boundary key is published (or the log is not trusted): nothing changed. */
  | 'noKey'
  /** Row and served document already agree with the head. */
  | 'consistent'
  /** The row was stale and its boundary method was rewritten from the head (merged document; endpoints kept). */
  | 'repaired'
  /** Gate off only: the log or the row could not be trusted or read; nothing overlaid, nothing written. */
  | 'unverified';

export interface BoundarySyncResult {
  /** The document to serve in the handshake. */
  document: DidDocument;
  action: BoundarySyncAction;
}

export interface BoundarySyncOptions {
  didDocumentUuid: string;
  did: string;
  /** The live document loaded at start (from the row). */
  served: DidDocument;
  /** True when the dedicated boundary key mode is on: every problem throws. */
  dedicated: boolean;
  warn?: (message: string) => void;
}

export async function reconcileBoundaryKey(db: DataSource, opts: BoundarySyncOptions): Promise<BoundarySyncResult> {
  const warn = opts.warn ?? ((m: string) => console.warn(`[utility-server] ${m}`));
  const problem = (message: string, code: 'notPublished' | 'corrupt'): BoundarySyncResult => {
    if (opts.dedicated) throw new BoundaryKeyError(code, message);
    warn(`boundary key: ${message}; serving the document as loaded, no repair`);
    return { document: opts.served, action: 'unverified' };
  };

  let log: RotationLogEntry[];
  try {
    log = await new YugabyteRotationLogStore(db).getLog(opts.didDocumentUuid);
  } catch (err) {
    return problem(`the server's rotation log cannot be read (${(err as Error).message})`, 'corrupt');
  }
  const head = log[log.length - 1];
  if (head === undefined) {
    if (opts.dedicated) throw new BoundaryKeyError('notPublished', 'the server\'s rotation log is empty');
    return { document: opts.served, action: 'noKey' };
  }
  const headPublishes = head.didDocument.verificationMethod.some((v) => v.id === BOUNDARY_VM_ID);
  if (!headPublishes) {
    // Dedicated mode: drop whatever the local document lists, so the signer check refuses (as before K4).
    // Gate off: nothing is published, nothing changes.
    return opts.dedicated
      ? { document: overlayBoundaryKey(opts.served, head.didDocument), action: 'noKey' }
      : { document: opts.served, action: 'noKey' };
  }

  if (new ScidVhMethod().validateEntries(log, opts.did).length !== log.length) {
    return problem('the server\'s rotation log chain is not valid, so the published #key-boundary cannot be trusted', 'notPublished');
  }

  const served = overlayBoundaryKey(opts.served, head.didDocument);
  const row = await didDocumentsRepo.findByUuid(db, opts.didDocumentUuid);
  let rowDoc: DidDocument | null = null;
  try {
    rowDoc = row?.documentJson ? (JSON.parse(row.documentJson) as DidDocument) : null;
  } catch { /* handled below */ }
  if (rowDoc === null || !Array.isArray(rowDoc.verificationMethod)) {
    return problem('the cached document_json of the server cannot be read', 'corrupt');
  }

  if (boundaryView(rowDoc) === boundaryView(head.didDocument)) {
    return { document: served, action: 'consistent' };
  }
  const merged = overlayBoundaryKey(rowDoc, head.didDocument);
  // Only document_json changes: no other column of the row is written.
  await db.run('UPDATE did_documents SET document_json = ? WHERE uuid = ?', JSON.stringify(merged), opts.didDocumentUuid);
  return { document: served, action: 'repaired' };
}
