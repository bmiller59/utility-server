// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Layer 1 — Infrastructure: /rotation-log + /witness-attestations routes.
 *
 * Read/append surface over the rotation log and its witness attestations.
 * Signature/chain *validation* logic already lives in
 * ../../../../src/did/rotating-did-method.ts — these routes are
 * intentionally dumb storage endpoints; a client (or a future Layer 2
 * relationship-manager integration) is expected to construct and sign
 * entries client-side using that existing code, then POST the resulting
 * bytes here for durable storage.
 */

import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import type { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import * as rotationRepo from '@p2p-trust-stack/core/db/repositories/rotation-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';

interface AppendRotationBody {
  version: number;
  previousHash?: string; // base64
  newPublicKey: string; // base64
  signedEntry: string; // base64
  /**
   * Unix seconds the entry was signed at. The entry digest covers it, so it
   * must be stored verbatim or the entry no longer validates on resolution.
   * Defaults to the insertion time for clients whose entries do not depend on it.
   */
  createdAt?: number;
}

interface AddAttestationBody {
  witnessDidDocumentUuid: string;
  signature: string; // base64
}

export function registerRotationRoutes(app: FastifyInstance, db: DataSource): void {
  app.post(
    '/did-documents/:uuid/rotation-log',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: AppendRotationBody }>, reply: FastifyReply) => {
      const didDocumentUuid = req.params.uuid;
      const body = req.body;
      if (!didDocumentUuid || body?.version === undefined || !body?.newPublicKey || !body?.signedEntry) {
        return reply.code(400).send({ error: { message: 'didDocumentUuid (param), version, newPublicKey, signedEntry are required' } });
      }
      const doc = await didDocumentsRepo.findByUuid(db, didDocumentUuid);
      if (!doc) {
        return reply.code(404).send({ error: { message: `did_document ${didDocumentUuid} not found` } });
      }

      if (body.createdAt !== undefined && !(Number.isSafeInteger(body.createdAt) && body.createdAt >= 0)) {
        return reply.code(400).send({ error: { message: 'createdAt must be a non-negative integer (unix seconds)' } });
      }

      const inserted = await rotationRepo.insertIfAbsent(db, {
        didDocumentUuid: doc.uuid,
        version: body.version,
        previousHash: body.previousHash ? Buffer.from(body.previousHash, 'base64') : undefined,
        newPublicKey: Buffer.from(body.newPublicKey, 'base64'),
        signedEntry: Buffer.from(body.signedEntry, 'base64'),
        createdAt: body.createdAt,
      });
      if (!inserted) {
        return reply.code(409).send({ error: { message: `rotation log version ${body.version} already exists for did_document ${didDocumentUuid}` } });
      }
      const rowUuid = (await rotationRepo.findForDidDocument(db, doc.uuid)).find((r) => r.version === body.version)!.uuid;

      return reply.code(201).send({ uuid: rowUuid });
    },
  );

  app.get(
    '/did-documents/:uuid/rotation-log',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const didDocumentUuid = req.params.uuid;
      const doc = await didDocumentsRepo.findByUuid(db, didDocumentUuid);
      if (!doc) {
        return reply.code(404).send({ error: { message: `did_document ${didDocumentUuid} not found` } });
      }
      return rotationRepo.findForDidDocument(db, doc.uuid);
    },
  );

  app.get(
    '/did-documents/:uuid/rotation-log/latest',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const didDocumentUuid = req.params.uuid;
      const doc = await didDocumentsRepo.findByUuid(db, didDocumentUuid);
      if (!doc) {
        return reply.code(404).send({ error: { message: `did_document ${didDocumentUuid} not found` } });
      }
      const entry = await rotationRepo.findLatestForDidDocument(db, doc.uuid);
      if (!entry) {
        return reply.code(404).send({ error: { message: `no rotation log entries for did_document ${didDocumentUuid}` } });
      }
      return entry;
    },
  );

  app.post(
    '/rotation-log/:uuid/witness-attestations',
    async (req: FastifyRequest<{ Params: { uuid: string }; Body: AddAttestationBody }>, reply: FastifyReply) => {
      const rotationLogUuid = req.params.uuid;
      const body = req.body;
      if (!rotationLogUuid || !body?.witnessDidDocumentUuid || !body?.signature) {
        return reply.code(400).send({ error: { message: 'rotationLogUuid (param), witnessDidDocumentUuid, signature are required' } });
      }
      const witnessDoc = await didDocumentsRepo.findByUuid(db, body.witnessDidDocumentUuid);
      if (!witnessDoc) {
        return reply.code(404).send({ error: { message: `did_document ${body.witnessDidDocumentUuid} not found` } });
      }

      const rowUuid = await rotationRepo.addAttestation(db, {
        rotationLogUuid,
        witnessDidDocumentUuid: witnessDoc.uuid,
        signature: Buffer.from(body.signature, 'base64'),
      });

      return reply.code(201).send({ uuid: rowUuid });
    },
  );

  app.get(
    '/rotation-log/:uuid/witness-attestations',
    async (req: FastifyRequest<{ Params: { uuid: string } }>, reply: FastifyReply) => {
      const rotationLogUuid = req.params.uuid;
      if (!rotationLogUuid) {
        return reply.code(400).send({ error: { message: 'rotationLogUuid (param) is required' } });
      }
      return rotationRepo.findForRotationLog(db, rotationLogUuid);
    },
  );
}
