// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * End-to-end boot of the REAL utility server process with the founding-ceremony host on (`TRUST_TASKS_CEREMONY_HOST=1`),
 * against a private PostgreSQL (initdb, a free port, a temp dir). The server's YugabyteDataSource speaks the same wire
 * protocol as Yugabyte's YSQL, but this is PostgreSQL, not Yugabyte. Checks:
 *   - flag unset, `0` or empty: the four ceremony types are `unsupportedType` on `POST /trust-tasks` and on the listener;
 *   - a bad flag value (`yes`) refuses to start and binds nothing;
 *   - flag `1`: signed ceremony documents (propose and co-sign through the main API, the second co-sign through the
 *     dedicated listener, so both surfaces share one participant) reach the quorum and create exactly one community
 *     with its two founding admins; a replayed co-sign and a restart create no second one;
 *   - the effect itself (`CommunityFoundingEffect` incl. `resolveRealVtaForStub`, which uses `?` placeholders that the
 *     YugabyteDataSource turns into `$n`) runs in this process against the same PostgreSQL database.
 *
 * Skipped (loudly) when no PostgreSQL server binaries (initdb, pg_ctl, createdb) are installed.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/e2e/ceremony-host-boot.test.ts
 */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, connect } from 'node:net';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { ed25519 } from '@noble/curves/ed25519.js';
import { randomUUID } from 'node:crypto';
import * as identitiesRepo from '@p2p-trust-stack/core/db/repositories/identities-repo.js';
import * as didDocumentsRepo from '@p2p-trust-stack/core/db/repositories/did-documents-repo.js';
import * as peerEndpointsRepo from '@p2p-trust-stack/core/db/repositories/peer-endpoints-repo.js';
import * as relationshipsRepo from '@p2p-trust-stack/core/db/repositories/relationships-repo.js';
import * as keysRepo from '@p2p-trust-stack/core/db/repositories/keys-repo.js';
import { CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_RESET_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/ceremony-spec.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { CommunityFoundingEffect } from '@p2p-trust-stack/core/services/founding/community-effect.js';
import type { EstablishedCommunity } from '@p2p-trust-stack/core/services/founding/community-effect.js';
import { SqliteDataSource } from '@p2p-trust-stack/core/db/sqlite-data-source.js';
import { CompensationExecutor, DataSourceLogSink, TransactionCoordinator, TransactionLog, TransactionManager, TX_ADDITIVE_COLUMNS, TX_SCHEMA_SQL } from '@p2p-trust-stack/core/tx/index.js';
import { CEREMONY_APPROVE, CEREMONY_BEGIN, CeremonyDocParticipant } from '@p2p-trust-stack/core/tx/ceremony-doc-participant.js';
import { resolveRealVtaForStub } from '@p2p-trust-stack/core/services/founding/admin-resolution.js';
import { YugabyteDataSource } from '../../src/db/yugabyte-data-source.js';

const ROOT = join(import.meta.dirname, '..', '..');
const LOADER = pathToFileURL(join(ROOT, 'test-loader.mjs')).href;
const PASS = 'e2e-passphrase-not-a-secret';
const TMP_BASE = process.env.TMPDIR ?? '/tmp';

function findPgBin(): string | undefined {
  const dirs = [
    ...(existsSync('/usr/lib/postgresql') ? readdirSync('/usr/lib/postgresql').sort().reverse().map((v) => join('/usr/lib/postgresql', v, 'bin')) : []),
    ...(process.env.PATH ?? '').split(':'),
  ];
  return dirs.find((d) => existsSync(join(d, 'initdb')) && existsSync(join(d, 'pg_ctl')) && existsSync(join(d, 'createdb')));
}
const PGBIN = findPgBin();

async function freePorts(n: number): Promise<number[]> {
  const servers = await Promise.all(Array.from({ length: n }, () => new Promise<ReturnType<typeof createServer>>((resolve) => {
    const s = createServer();
    s.listen(0, '127.0.0.1', () => resolve(s));
  })));
  const ports = servers.map((s) => (s.address() as { port: number }).port);
  await Promise.all(servers.map((s) => new Promise((r) => s.close(r))));
  return ports;
}
const portOpen = (port: number): Promise<boolean> => new Promise((resolve) => {
  const s = connect({ port, host: '127.0.0.1' });
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('error', () => resolve(false));
});

interface Proc { child: ChildProcess; lines: string[]; exited: Promise<number | null>; waitFor(re: RegExp, ms: number): Promise<string>; stop(): Promise<void> }
function run(args: string[], env: Record<string, string>, cwd: string): Proc {
  const child = spawn(process.execPath, ['--experimental-strip-types', '--no-warnings', '--loader', LOADER, ...args], { cwd, env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const lines: string[] = [];
  const waiters: Array<{ re: RegExp; resolve: (l: string) => void }> = [];
  const feed = (chunk: Buffer) => {
    for (const l of chunk.toString('utf8').split('\n')) {
      if (l === '') continue;
      lines.push(l);
      for (const w of [...waiters]) if (w.re.test(l)) { waiters.splice(waiters.indexOf(w), 1); w.resolve(l); }
    }
  };
  child.stdout!.on('data', feed);
  child.stderr!.on('data', feed);
  const exited = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)));
  return {
    child, lines, exited,
    waitFor: (re, ms) => {
      const seen = lines.find((l) => re.test(l));
      if (seen !== undefined) return Promise.resolve(seen);
      return new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`timed out waiting for ${re}; last lines:\n${lines.slice(-15).join('\n')}`)), ms);
        waiters.push({ re, resolve: (l) => { clearTimeout(t); resolve(l); } });
        void exited.then(() => { clearTimeout(t); reject(new Error(`process exited while waiting for ${re}; last lines:\n${lines.slice(-15).join('\n')}`)); });
      });
    },
    stop: async () => {
      if (child.exitCode === null) {
        child.kill('SIGTERM');
        const killer = setTimeout(() => child.kill('SIGKILL'), 15_000);
        await exited;
        clearTimeout(killer);
      }
    },
  };
}

async function exitOrTimeout(p: Proc): Promise<number | null | 'timeout'> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([p.exited, new Promise<'timeout'>((r) => { timer = setTimeout(() => r('timeout'), 120_000); })]);
  } finally { clearTimeout(timer); }
}

let dir = '';
let pgPort = 0;
let env: Record<string, string> = {};
let ports = { http: 0, libp2p: 0, resolver: 0, listener: 0 };
let serverDid = '';

const skip = PGBIN === undefined ? 'PostgreSQL server binaries (initdb, pg_ctl, createdb) are not installed; boot test skipped' : false;

before(async () => {
  if (PGBIN === undefined) return;
  dir = mkdtempSync(join(TMP_BASE, 'boundary-boot-'));
  mkdirSync(join(dir, 'data'));
  const [pg, http, libp2p, resolver, listener] = await freePorts(5);
  pgPort = pg!;
  ports = { http: http!, libp2p: libp2p!, resolver: resolver!, listener: listener! };
  const init = spawnSync(join(PGBIN, 'initdb'), ['-D', join(dir, 'pg'), '-A', 'trust', '-U', 'yugabyte'], { encoding: 'utf8' });
  assert.equal(init.status, 0, init.stderr);
  const start = spawnSync(join(PGBIN, 'pg_ctl'), ['-D', join(dir, 'pg'), '-o', `-p ${pgPort} -c listen_addresses=127.0.0.1 -c unix_socket_directories=${dir}`, '-l', join(dir, 'pg.log'), '-w', '-t', '60', 'start'], { encoding: 'utf8' });
  assert.equal(start.status, 0, start.stderr);
  const created = spawnSync(join(PGBIN, 'createdb'), ['-h', '127.0.0.1', '-p', String(pgPort), '-U', 'yugabyte', 'p2pts'], { encoding: 'utf8' });
  assert.equal(created.status, 0, created.stderr);
  writeFileSync(join(dir, 'data', 'config.json'), JSON.stringify({ setup: { configured: true, network: { advertisedHost: '127.0.0.1', httpPort: ports.http, libp2pPort: ports.libp2p } } }));
  env = {
    TMPDIR: TMP_BASE, UTILITY_DATA_DIR: join(dir, 'data'), YB_HOST: '127.0.0.1', YB_PORT: String(pgPort), YB_USER: 'yugabyte', YB_DATABASE: 'p2pts',
    RESOLVER_PORT: String(ports.resolver), RESOLVER_HOST: '127.0.0.1', TSP_SEED_PASSPHRASE: PASS,
  };
});

after(() => {
  if (PGBIN === undefined || dir === '') return;
  spawnSync(join(PGBIN, 'pg_ctl'), ['-D', join(dir, 'pg'), '-m', 'immediate', '-w', '-t', '30', 'stop'], { encoding: 'utf8' });
  rmSync(dir, { recursive: true, force: true });
});


const server = (extra: Record<string, string> = {}): Proc => run([join(ROOT, 'src', 'index.ts')], { ...env, ...extra }, dir);
const LISTENER = () => ({ TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: String(ports.listener) });

const keyOf = (byte: number) => {
  const secretKey = new Uint8Array(32).fill(byte);
  const did = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
  return createEd25519BoundarySigner({ did, secretKey, fragment: did.slice('did:key:'.length) });
};
const ADMIN_A = keyOf(21);
const ADMIN_B = keyOf(22);
type Signer = ReturnType<typeof keyOf>;

const openDb = () => new YugabyteDataSource({ host: '127.0.0.1', port: pgPort, database: 'p2pts', user: 'yugabyte', password: 'yugabyte', poolMin: 1, poolMax: 2 });
const communitiesNamed = async (name: string): Promise<number> => {
  const ds = openDb();
  try { return Number((await ds.get<{ n: number | string }>("SELECT COUNT(*) AS n FROM identities WHERE role IN ('vtc','vtn') AND name = ?", name))!.n); } finally { await ds.close(); }
};
const countRows = async (table: string): Promise<number> => {
  const ds = openDb();
  try { return Number((await ds.get<{ n: number | string }>(`SELECT COUNT(*) AS n FROM ${table}`))!.n); } finally { await ds.close(); }
};
const opTypes = async (): Promise<string[]> => {
  const ds = openDb();
  try { return (await ds.all<{ op_type: string }>('SELECT DISTINCT op_type FROM pending_agent_deliveries ORDER BY op_type')).map((r) => r.op_type); } finally { await ds.close(); }
};
const foundingAdmins = async (): Promise<number> => {
  const ds = openDb();
  try { return Number((await ds.get<{ n: number | string }>("SELECT COUNT(*) AS n FROM memberships WHERE role = 'founding_admin'"))!.n); } finally { await ds.close(); }
};

async function seedAdmin(ds: YugabyteDataSource, did: string, o: { endpoint?: boolean; method?: string } = {}): Promise<string> {
  const uuid = await identitiesRepo.create(ds, { realDid: did, role: 'vta', subjectKind: 'human', name: did.slice(-8) });
  await didDocumentsRepo.create(ds, { identityUuid: uuid, did, method: o.method ?? 'key', isPrimary: true });
  if (o.endpoint !== false) await peerEndpointsRepo.upsertForIdentity(ds, { identityUuid: uuid, peerId: `peer-${uuid}`, multiaddrs: ['/ip4/127.0.0.1/tcp/1'] });
  return uuid;
}

const stamp = () => Math.floor(Date.now() / 1000) * 1000;
const signedDoc = (who: Signer, type: string, thread: string, payload: Record<string, unknown>) => {
  const nowMs = stamp();
  return signDocument({ id: `urn:uuid:${randomUUID()}`, threadId: thread, type, issuer: who.did, recipient: serverDid, issuedAt: new Date(nowMs).toISOString().replace('.000Z', 'Z'), payload }, who, { created: nowMs });
};
const postTo = async (port: number, body: unknown): Promise<{ status: number; json: { type?: string; payload: { code?: string; details?: { reason?: string }; status?: string; ext?: { quorum?: { required: number; received: number } } } } }> => {
  const res = await fetch(`http://127.0.0.1:${port}/trust-tasks`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  return { status: res.status, json: (await res.json()) as never };
};
const propose = (who: Signer, thread: string, name: string, admins = [ADMIN_A.did, ADMIN_B.did]) =>
  signedDoc(who, CEREMONY_PROPOSE_WIRE_TYPE, thread, { name, kind: 'vtc', threshold: admins.length, adminDids: admins });
const cosign = (who: Signer, thread: string) => signedDoc(who, CEREMONY_CO_SIGN_WIRE_TYPE, thread, {});

let foundedThread = '';
let crashedThread = '';

test('ceremony host boot', { skip, timeout: 900_000 }, async (t) => {
  await t.test('1. flag unset: the server boots, the four ceremony types are unsupportedType on the main API and the listener', async () => {
    const s = server(LISTENER());
    try {
      await s.waitFor(/HTTP API listening/, 120_000);
      await s.waitFor(/"event":"listener\.started"/, 120_000);
      serverDid = /server VTA identity: (\S+)/.exec(s.lines.join('\n'))![1]!;
      assert.equal(s.lines.some((l) => /ceremony documents: served/.test(l)), false);
      const ds = openDb();
      try {
        const a = await seedAdmin(ds, ADMIN_A.did);
        const b = await seedAdmin(ds, ADMIN_B.did);
        // PostgreSQL (not Yugabyte) caps a btree index row at 2704 bytes; the founding community's did:peer:4 DID is longer. Index its hash instead.
        await ds.exec('ALTER TABLE did_documents DROP CONSTRAINT did_documents_did_key');
        await ds.exec('CREATE UNIQUE INDEX did_documents_did_md5 ON did_documents (md5(did))');
        await relationshipsRepo.create(ds, { localIdentityUuid: a, remoteIdentityUuid: b, direction: 'bidirectional', status: 'established' });
      } finally { await ds.close(); }
      for (const type of [CEREMONY_PROPOSE_WIRE_TYPE, CEREMONY_CO_SIGN_WIRE_TYPE, CEREMONY_STATUS_WIRE_TYPE, CEREMONY_RESET_WIRE_TYPE]) {
        const r = await postTo(ports.listener, signedDoc(ADMIN_A, type, `urn:uuid:${randomUUID()}`, { name: 'Off Club', kind: 'vtc', threshold: 2, adminDids: [ADMIN_A.did, ADMIN_B.did] }));
        assert.equal(r.json.payload.code, 'unsupportedType', `${type} on the listener: ${JSON.stringify(r.json)}`);
      }
      // The main API's own session gate sits in front of POST /trust-tasks: no session, no answer from the pipeline at all.
      assert.equal((await postTo(ports.http, propose(ADMIN_A, `urn:uuid:${randomUUID()}`, 'Off Club'))).status, 401);
      assert.equal(await communitiesNamed('Off Club'), 0);
    } finally { await s.stop(); }
  });

  await t.test('1b. flag 0 and flag empty serve nothing either', async () => {
    for (const value of ['0', '']) {
      const s = server({ ...LISTENER(), TRUST_TASKS_CEREMONY_HOST: value });
      try {
        await s.waitFor(/"event":"listener\.started"/, 120_000);
        await s.waitFor(/HTTP API listening/, 120_000);
        const r = await postTo(ports.listener, propose(ADMIN_A, `urn:uuid:${randomUUID()}`, 'Off Club'));
        assert.equal(r.json.payload.code, 'unsupportedType', `flag "${value}"`);
        assert.equal(s.lines.some((l) => /ceremony documents: served/.test(l)), false);
      } finally { await s.stop(); }
    }
    assert.equal(await communitiesNamed('Off Club'), 0);
  });

  await t.test('2. a bad flag value refuses to start and binds nothing', async () => {
    for (const bad of ['yes', 'true', '2']) {
      const s = server({ ...LISTENER(), TRUST_TASKS_CEREMONY_HOST: bad });
      const code = await exitOrTimeout(s);
      await s.stop();
      assert.ok(typeof code === 'number' && code !== 0, `flag "${bad}": ${String(code)}`);
      assert.ok(s.lines.some((l) => /fatal error during startup/.test(l)) && s.lines.some((l) => /TRUST_TASKS_CEREMONY_HOST must be 1 or 0/.test(l)), s.lines.slice(-8).join('\n'));
      assert.equal(s.lines.some((l) => /HTTP API listening|ceremony documents: served/.test(l)), false);
      assert.equal(await portOpen(ports.http), false);
      assert.equal(await portOpen(ports.listener), false);
    }
  });

  await t.test('3. flag 1: a signed founding ceremony (every document through the Tier 2 listener) creates exactly one community', async () => {
    const s = server({ ...LISTENER(), TRUST_TASKS_CEREMONY_HOST: '1' });
    try {
      await s.waitFor(/ceremony documents: served on the Trust Task boundary \(reconciled 0 committed, 0 aborted, 0 failed\)/, 120_000);
      await s.waitFor(/"event":"listener\.started"/, 120_000);
      await s.waitFor(/HTTP API listening/, 120_000);
      const thread = `urn:uuid:${randomUUID()}`;
      foundedThread = thread;
      const opened = await postTo(ports.listener, propose(ADMIN_A, thread, 'Boot Club'));
      assert.equal(opened.status, 200, JSON.stringify(opened.json));
      assert.deepEqual(opened.json.payload.ext?.quorum, { required: 2, received: 0 });
      const first = await postTo(ports.listener, cosign(ADMIN_A, thread));
      assert.equal(first.json.payload.ext?.quorum?.received, 1, JSON.stringify(first.json));
      assert.equal(await communitiesNamed('Boot Club'), 0, 'nothing before the quorum');
      const last = await postTo(ports.listener, cosign(ADMIN_B, thread));
      assert.equal(last.status, 200, JSON.stringify(last.json));
      assert.equal(last.json.payload.status, 'crystallized');
      assert.equal(await communitiesNamed('Boot Club'), 1, 'exactly one community');
      assert.equal(await foundingAdmins(), 2, 'its two founding admins');
      const deliveries = await countRows('pending_agent_deliveries');
      assert.deepEqual(await opTypes(), ['exchange:credential', 'exchange:vtc-membership'], 'both fan-outs: the community package and the founding VMCs');
      assert.ok(deliveries > 0, 'the post-commit fan-out queued deliveries (community package, founding VMCs)');
      // A replay of the completing co-sign and a status read change nothing.
      const replay = await postTo(ports.listener, cosign(ADMIN_B, thread));
      assert.equal(replay.json.payload.code, undefined, JSON.stringify(replay.json));
      const status = await postTo(ports.listener, signedDoc(ADMIN_A, CEREMONY_STATUS_WIRE_TYPE, thread, {}));
      assert.equal(status.json.payload.status, 'crystallized');
      assert.equal(await communitiesNamed('Boot Club'), 1);
      assert.equal(await countRows('pending_agent_deliveries'), deliveries, 'a replay queues nothing more');
      // The same name in a second ceremony is refused (the name is taken) and creates nothing.
      const second = `urn:uuid:${randomUUID()}`;
      await postTo(ports.listener, propose(ADMIN_A, second, 'Boot Club'));
      await postTo(ports.listener, cosign(ADMIN_A, second));
      const taken = await postTo(ports.listener, cosign(ADMIN_B, second));
      assert.equal(taken.json.payload.details?.reason, 'nameTaken', JSON.stringify(taken.json));
      assert.equal(await communitiesNamed('Boot Club'), 1);
      assert.equal(s.lines.some((l) => /fan-out .* failed/.test(l)), false, s.lines.filter((l) => /fan-out/.test(l)).join('\n'));
    } finally { await s.stop(); }
  });

  await t.test('3b. crash recovery: a quorum transaction the coordinator decided commit on but the host never applied is finished by the reconcile at boot', async () => {
    // Before the boot: a ceremony whose completing approval committed in the coordinator, while the apply of the effect died.
    const appDb = openDb();
    const txDb = new SqliteDataSource(join(dir, 'data', 'tx', 'tx-coordinator.db'));
    try {
      txDb.getRawDb().exec(TX_SCHEMA_SQL);
      for (const col of TX_ADDITIVE_COLUMNS) { try { txDb.getRawDb().exec(col.ddl); } catch { /* present */ } }
      const real = new CommunityFoundingEffect(appDb);
      let dead = false;
      const flaky = { checkProposal: real.checkProposal.bind(real), check: real.check.bind(real), apply: async (e: Parameters<typeof real.apply>[0]) => { if (dead) throw new Error('process died before the apply'); await real.apply(e); } };
      const participant = new CeremonyDocParticipant('ceremony-doc:us-1', txDb, flaky, { requireVerifiedApprovals: true });
      const txm = new TransactionManager(new TransactionCoordinator(new TransactionLog(new DataSourceLogSink(txDb))), new CompensationExecutor());
      const nowMs = Date.now();
      const run = (op: string, params: Record<string, unknown>) => txm.run(async (tx) => { tx.enlist(participant, [{ op, params: { ...params, verified: true, nowMs } }]); });
      const id = `urn:uuid:${randomUUID()}`;
      await run(CEREMONY_BEGIN, { ceremonyId: id, proposerDid: ADMIN_A.did, name: 'Crash Club', kind: 'vtc', threshold: 2, adminDids: [ADMIN_A.did, ADMIN_B.did] });
      await run(CEREMONY_APPROVE, { ceremonyId: id, approverDid: ADMIN_A.did, signature: 'proof-a' });
      dead = true;
      const last = await run(CEREMONY_APPROVE, { ceremonyId: id, approverDid: ADMIN_B.did, signature: 'proof-b' });
      assert.equal(last.outcome, 'committed', 'the coordinator decided commit');
      assert.equal(await participant.inquiry(last.txId), 'prepared', 'the host never finished it');
      assert.equal(await communitiesNamed('Crash Club'), 0);
      crashedThread = id;
    } finally { await txDb.close(); await appDb.close(); }

    const s = server({ ...LISTENER(), TRUST_TASKS_CEREMONY_HOST: '1' });
    try {
      await s.waitFor(/ceremony documents: served on the Trust Task boundary \(reconciled 1 committed, 0 aborted, 0 failed\)/, 120_000);
      await s.waitFor(/"event":"listener\.started"/, 120_000);
      assert.equal(await communitiesNamed('Crash Club'), 1, 'the boot finished the establishment, once');
      const status = await postTo(ports.listener, signedDoc(ADMIN_A, CEREMONY_STATUS_WIRE_TYPE, crashedThread, {}));
      assert.equal(status.json.payload.status, 'crystallized', JSON.stringify(status.json));
    } finally { await s.stop(); }
  });

  await t.test('4. restart with the flag on: nothing to reconcile, still one community, the finished ceremony reads crystallized', async () => {
    const s = server({ ...LISTENER(), TRUST_TASKS_CEREMONY_HOST: '1' });
    try {
      await s.waitFor(/ceremony documents: served on the Trust Task boundary \(reconciled 0 committed, 0 aborted, 0 failed\)/, 120_000);
      await s.waitFor(/"event":"listener\.started"/, 120_000);
      await s.waitFor(/HTTP API listening/, 120_000);
      assert.equal(await communitiesNamed('Boot Club'), 1);
      const status = await postTo(ports.listener, signedDoc(ADMIN_A, CEREMONY_STATUS_WIRE_TYPE, foundedThread, {}));
      assert.equal(status.json.payload.status, 'crystallized', JSON.stringify(status.json));
    } finally { await s.stop(); }
  });

  await t.test('5. the effect on this PostgreSQL database: check and apply with a stub admin resolved by key (? placeholders), exactly one community, idempotent apply', async () => {
    const ds = openDb();
    try {
      const real = await seedAdmin(ds, 'did:example:pg-real', { method: 'scid' });
      const a = (await identitiesRepo.findByRealDid(ds, ADMIN_A.did))!.uuid;
      await relationshipsRepo.create(ds, { localIdentityUuid: a, remoteIdentityUuid: real, direction: 'bidirectional', status: 'established' });
      const stub = await seedAdmin(ds, 'did:peer:4zpgstub', { endpoint: false, method: 'peer' });
      const key = Buffer.from(ed25519.getPublicKey(new Uint8Array(32).fill(33)));
      await keysRepo.create(ds, { identityUuid: real, keyType: 'ed25519', publicKey: key });
      await keysRepo.create(ds, { identityUuid: stub, keyType: 'ed25519', publicKey: key });
      assert.equal((await resolveRealVtaForStub(ds, stub))?.uuid, real, 'by shared key');
      assert.equal(await resolveRealVtaForStub(ds, a), null, 'no stub, no match');
      const fanouts: EstablishedCommunity[] = [];
      const effect = new CommunityFoundingEffect(ds, { afterEstablished: async (c) => { fanouts.push(c); } });
      const est = {
        ceremonyId: `urn:uuid:${randomUUID()}`, name: 'Effect PG Club', kind: 'vtc' as const, adminDids: [ADMIN_A.did, 'did:peer:4zpgstub'], threshold: 2,
        parentCommunityDid: null, proposerDid: ADMIN_A.did, proposalHash: 'h', vtcDid: 'did:p2pts:ceremony:pg',
        approvals: [ADMIN_A.did, 'did:peer:4zpgstub'].map((d) => ({ approverDid: d, signature: 'proof', verified: true })),
      };
      await effect.checkProposal({ ceremonyId: est.ceremonyId, proposerDid: est.proposerDid, name: est.name, kind: est.kind, adminDids: est.adminDids, threshold: est.threshold, parentCommunityDid: null });
      await effect.check(est);
      assert.equal(await communitiesNamed('Effect PG Club'), 0, 'check writes nothing');
      // A failure inside the establishment rolls the whole PostgreSQL transaction back (no half-written community).
      await ds.exec(`CREATE FUNCTION boot_test_refuse() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'refused by the test'; END $$ LANGUAGE plpgsql;
        CREATE TRIGGER boot_test_refuse BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION boot_test_refuse()`);
      try {
        await assert.rejects(() => effect.apply(est), /refused by the test/);
        assert.equal(await communitiesNamed('Effect PG Club'), 0, 'rolled back: no community row survives');
      } finally { await ds.exec('DROP TRIGGER boot_test_refuse ON memberships; DROP FUNCTION boot_test_refuse()'); }
      await effect.apply(est);
      await effect.apply(est);
      assert.equal(await communitiesNamed('Effect PG Club'), 1, 'one community after apply and a repeated apply');
      assert.deepEqual(fanouts.map((f) => f.replayed), [false, true]);
      const founders = (await ds.all<{ member_identity_uuid: string }>("SELECT m.member_identity_uuid FROM memberships m JOIN identities c ON c.uuid = m.community_identity_uuid WHERE c.name = ? AND m.role = 'founding_admin'", 'Effect PG Club')).map((r) => r.member_identity_uuid);
      assert.ok(founders.includes(real) && !founders.includes(stub), 'the real VTA, not the stub, founds it');
      await assert.rejects(() => effect.check({ ...est, ceremonyId: `urn:uuid:${randomUUID()}` }), (e: { code?: string; reason?: string }) => /nameTaken|conflict/i.test(JSON.stringify(e) + String(e)), 'a second ceremony for the taken name is refused at the check');
    } finally { await ds.close(); }
  });
});
