// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * YugabyteDB-backed RotationLogStore for the utility server's own VTA.
 *
 * Mirrors src/did/rotation-log-store.ts (and shares core's packRotationEntry /
 * unpackRotationEntry codec, so the optional ML-DSA-65 signature is persisted and a
 * damaged block fails closed on read) but uses DataSource (YugabyteDB)
 * instead of DatabaseSync (SQLite). The utility server stores its own
 * rotation log entries in the shared `rotation_log` table in YugabyteDB.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { packRotationEntry, parseNextKeyCommitments, unpackRotationEntry } from '@p2p-trust-stack/core/did/rotation-entry-codec.js';
import type { RotationLogEntry } from '@p2p-trust-stack/core/did/rotation-types.js';

interface RotationLogRow {
  uuid: string;
  did_document_uuid: string;
  version: number;
  previous_hash: Buffer | Uint8Array | null;
  new_public_key: Buffer | Uint8Array;
  signed_entry: Buffer | Uint8Array;
  created_at: number | null;
}

// ---------------------------------------------------------------------------
// YugabyteRotationLogStore
// ---------------------------------------------------------------------------

export class YugabyteRotationLogStore {
  private db: DataSource;

  constructor(db: DataSource) {
    this.db = db;
  }

  async appendEntry(didDocumentUuid: string, entry: RotationLogEntry): Promise<void> {
    const packed = packRotationEntry({
      didDocument: entry.didDocument,
      parameters: entry.parameters,
      digest: entry.digest,
      signature: entry.signature,
      mlDsa65Signature: entry.mlDsa65Signature,
    });
    const rowUuid = crypto.randomUUID();

    await this.db.run(
      `INSERT INTO rotation_log
       (did_document_uuid, version, previous_hash,
        new_public_key, signed_entry, uuid, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      didDocumentUuid,
      entry.version,
      entry.prevHash ? Buffer.from(entry.prevHash) : null,
      Buffer.from(JSON.stringify(entry.nextKeyCommitments.map(k => Buffer.from(k).toString('base64')))),
      Buffer.from(packed),
      rowUuid,
      entry.createdAt,
    );
  }

  async getLog(didDocumentUuid: string): Promise<RotationLogEntry[]> {
    const rows = await this.db.all<RotationLogRow>(
      `SELECT * FROM rotation_log WHERE did_document_uuid = ? ORDER BY version ASC`,
      didDocumentUuid,
    );
    return rows.map(r => {
      const unpacked = unpackRotationEntry(new Uint8Array(r.signed_entry));
      return {
        version: r.version,
        parameters: unpacked.parameters,
        didDocument: unpacked.didDocument,
        prevHash: r.previous_hash ? new Uint8Array(r.previous_hash) : null,
        nextKeyCommitments: parseNextKeyCommitments(new Uint8Array(r.new_public_key)),
        createdAt: r.created_at ?? 0,
        digest: unpacked.digest,
        signature: unpacked.signature,
        ...(unpacked.mlDsa65Signature ? { mlDsa65Signature: unpacked.mlDsa65Signature } : {}),
        witnessAttestations: [],
      };
    });
  }
}