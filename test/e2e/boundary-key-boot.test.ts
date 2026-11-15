// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * End-to-end boot of the REAL utility server process with the dedicated boundary key gate on (G2).
 *
 * A private PostgreSQL (initdb, a free port, a temp dir; the server's YugabyteDataSource speaks the same
 * wire protocol) hosts the server's database. The server is started as a child process with its own data
 * directory and free ports; the operator CLI provisions and publishes `#key-boundary` into the server's own
 * rotation log; the server is then started with TRUST_TASKS_BOUNDARY_KEY=dedicated and the opt-in
 * Trust Task listener. Checks:
 *   - the listener starts on its own port and signs with the dedicated key;
 *   - a Tier 2 signed document is accepted and the reply is signed by `<server did>#key-boundary`;
 *   - the reply verifies against the key the server's own log publishes;
 *   - K4: the cached `did_documents.document_json` is repaired from the rotation log head at boot (gate off and
 *     gate on), keeping the live endpoint and every other column of the row; an invalid log chain repairs
 *     nothing, stops a dedicated server and only warns with the gate off;
 *   - with the gate on and the key store gone, or with a mistyped gate value, the server refuses to start
 *     and binds nothing.
 *
 * Skipped (loudly) when no PostgreSQL server binaries (initdb, pg_ctl, createdb) are installed.
 *
 * Run with: node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test test/e2e/boundary-key-boot.test.ts
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
import { POLICY_EVALUATE_WIRE_TYPE } from '@p2p-trust-stack/core/services/trust-tasks/boundary/legacy-evaluate.js';
import { DidProofVerifier } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/verify.js';
import { CompositeKeyResolver, DidKeyResolver, didKeyFromEd25519 } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import type { KeyResolver } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/resolver.js';
import { createEd25519BoundarySigner, signDocument } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/signer.js';
import { YugabyteDataSource } from '../../src/db/yugabyte-data-source.js';
import { readPublishedBoundaryKey } from '../../src/services/boundary-key-admin.js';
import { YugabyteRotationLogStore } from '../../src/db/yugabyte-rotation-log-store.js';

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

const openDb = () => new YugabyteDataSource({ host: '127.0.0.1', port: pgPort, database: 'p2pts', user: 'yugabyte', password: 'yugabyte', poolMin: 1, poolMax: 2 });
interface DocLike { verificationMethod: Array<{ id: string; publicKeyMultibase?: string }>; authentication: string[]; service?: Array<{ id: string }> }
/** The server's primary did_documents row: all columns, and its parsed document. */
async function readRow(): Promise<{ row: Record<string, unknown>; doc: DocLike }> {
  const ds = openDb();
  try {
    const row = (await ds.get<Record<string, unknown>>('SELECT * FROM did_documents WHERE did = ?', serverDid))!;
    return { row, doc: JSON.parse(row.document_json as string) as DocLike };
  } finally { await ds.close(); }
}
async function writeRowDoc(mutate: (d: DocLike) => void): Promise<void> {
  const ds = openDb();
  try {
    const row = (await ds.get<{ document_json: string }>('SELECT document_json FROM did_documents WHERE did = ?', serverDid))!;
    const doc = JSON.parse(row.document_json) as DocLike;
    mutate(doc);
    await ds.run('UPDATE did_documents SET document_json = ? WHERE did = ?', JSON.stringify(doc), serverDid);
  } finally { await ds.close(); }
}
async function headBoundaryMultibase(): Promise<string> {
  const ds = openDb();
  try {
    const row = (await ds.get<{ uuid: string }>('SELECT uuid FROM did_documents WHERE did = ?', serverDid))!;
    const log = await new YugabyteRotationLogStore(ds).getLog(row.uuid);
    return log[log.length - 1]!.didDocument.verificationMethod.find((v) => v.id === '#key-boundary')!.publicKeyMultibase;
  } finally { await ds.close(); }
}
const stripBoundary = (d: DocLike) => { d.verificationMethod = d.verificationMethod.filter((v) => v.id !== '#key-boundary'); d.authentication = d.authentication.filter((a) => a !== '#key-boundary'); };
const LIVE = { id: '#live-transport', type: 'TspTransport', serviceEndpoint: 'https://live.example/tsp' };

const server = (extra: Record<string, string> = {}): Proc => run([join(ROOT, 'src', 'index.ts')], { ...env, ...extra }, dir);
const cli = (args: string[], extra: Record<string, string> = {}): Promise<{ code: number | null; out: string; all: string }> => {
  const p = run([join(ROOT, 'src', 'scripts', 'boundary-key.ts'), ...args], { ...env, ...extra }, dir);
  return p.exited.then((code) => ({ code, out: p.lines.filter((l) => l.startsWith('{')).join('\n'), all: p.lines.join('\n') }));
};

test('boot', { skip, timeout: 600_000 }, async (t) => {
  await t.test('1. default boot (gate off) creates the identity and signs with #key-1', async () => {
    const s = server();
    try {
      await s.waitFor(/HTTP API listening/, 120_000);
      serverDid = /server VTA identity: (\S+)/.exec(s.lines.join('\n'))![1]!;
      assert.ok(s.lines.some((l) => /Trust Task documents: signing as .*\(#key-1\)/.test(l)));
      assert.equal(s.lines.some((l) => /listener\./.test(l)), false, 'no boundary listener unless asked');
    } finally { await s.stop(); }
  });

  await t.test('2. operator CLI: refuses without the passphrase; dry run then provision and publish #key-boundary', async () => {
    const noPass = await cli(['status'], { TSP_SEED_PASSPHRASE: '' });
    assert.equal(noPass.code, 1);
    assert.match(noPass.all, /TSP_SEED_PASSPHRASE is required/);
    assert.equal(JSON.parse((await cli(['status'])).out).published, null);
    assert.equal(JSON.parse((await cli(['provision', '--generation', '1'])).out).executed, false);
    assert.equal(existsSync(join(dir, 'data', 'boundary-keystore.db')), false, 'a dry run provisions nothing');
    const prov = await cli(['provision', '--generation', '1', '--execute']);
    assert.equal(prov.code, 0, prov.all);
    assert.equal((await cli(['provision', '--generation', '1', '--execute'])).code, 1, 'never overwritten');
    assert.equal(JSON.parse((await cli(['publish', '--generation', '1'])).out).executed, false);
    const pub = await cli(['publish', '--generation', '1', '--execute']);
    assert.equal(pub.code, 0, pub.all);
    const status = JSON.parse((await cli(['status'])).out);
    assert.equal(status.published.fingerprint, JSON.parse(prov.out).fingerprint);
    assert.equal(/secret|seed|passphrase/i.test(prov.all + pub.all), false, 'no key material in the output');
  });

  await t.test('2b. K4, gate off: a stale document_json is repaired from the log head at boot; the live endpoint and every other column stay', async () => {
    await writeRowDoc((d) => { d.service = [...(d.service ?? []), LIVE as never]; });
    const before = await readRow();
    assert.equal(before.doc.verificationMethod.some((v) => v.id === '#key-boundary'), false, 'stale: the row has no #key-boundary');
    const s = server();
    try {
      await s.waitFor(/HTTP API listening/, 120_000);
      assert.ok(s.lines.some((l) => /boundary key: document_json repaired/.test(l)), s.lines.slice(-10).join('\n'));
      assert.ok(s.lines.some((l) => /Trust Task documents: signing as .*\(#key-1\)/.test(l)), 'still signs with #key-1 (K7: signing changes only at the cutover)');
    } finally { await s.stop(); }
    const after = await readRow();
    const head = await headBoundaryMultibase();
    assert.equal(after.doc.verificationMethod.find((v) => v.id === '#key-boundary')?.publicKeyMultibase, head);
    assert.ok(after.doc.authentication.includes('#key-boundary'));
    assert.ok(after.doc.service?.some((x) => x.id === LIVE.id), 'live endpoint kept');
    const strip = (r: { row: Record<string, unknown> }) => ({ ...r.row, document_json: null });
    assert.deepEqual(strip(after), strip(before), 'no other column of the row changes');
    const second = server();
    try {
      await second.waitFor(/HTTP API listening/, 120_000);
      assert.equal(second.lines.some((l) => /document_json repaired/.test(l)), false, 'consistent: nothing written at the next boot');
    } finally { await second.stop(); }
    assert.deepEqual((await readRow()).row, after.row);
  });

  await t.test('2c. the row goes stale again (key removed, endpoint kept)', async () => {
    await writeRowDoc(stripBoundary);
    assert.equal((await readRow()).doc.verificationMethod.some((v) => v.id === '#key-boundary'), false);
  });

  await t.test('3. gate on: the listener starts on its own port with the dedicated key; a Tier 2 signed document is accepted; the reply is signed by #key-boundary', async () => {
    const s = server({
      TRUST_TASKS_BOUNDARY_KEY: 'dedicated', BOUNDARY_KEY_CUTOVER_AT: new Date(Date.now() - 3_600_000).toISOString(),
      TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: String(ports.listener),
    });
    try {
      const installed = await s.waitFor(/"event":"signer\.installed"/, 120_000);
      assert.match(installed, /"keyMode":"dedicated"/);
      const started = await s.waitFor(/"event":"listener\.started"/, 120_000);
      assert.match(started, new RegExp(`"port":${ports.listener}`));
      assert.match(started, /"signer":"dedicated"/);
      assert.match(started, /"tier":2/);
      await s.waitFor(/HTTP API listening/, 120_000);
      assert.ok(s.lines.some((l) => /boundary key: document_json repaired/.test(l)), 'K4: repaired from the log head at boot with the gate on');
      assert.notEqual(ports.listener, ports.http);

      const secretKey = new Uint8Array(32).fill(5);
      const peerDid = didKeyFromEd25519(ed25519.getPublicKey(secretKey));
      const peer = createEd25519BoundarySigner({ did: peerDid, secretKey, fragment: peerDid.slice('did:key:'.length) });
      const nowMs = Math.floor(Date.now() / 1000) * 1000;
      const doc = { id: 'urn:uuid:bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', type: POLICY_EVALUATE_WIRE_TYPE, issuer: peerDid, recipient: serverDid, issuedAt: new Date(nowMs).toISOString().replace('.000Z', 'Z'), payload: { action: 'register_name' } };
      const url = `http://127.0.0.1:${ports.listener}/trust-tasks`;
      const post = (body: unknown) => fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

      const unsigned = await post(doc);
      const unsignedReply = (await unsigned.json()) as { payload: { code?: string } };
      assert.equal(unsignedReply.payload.code, 'proofRequired', 'Tier 2: a proof is required');

      const res = await post(signDocument(doc, peer, { created: nowMs }));
      assert.equal(res.status, 200, await res.clone().text());
      const reply = (await res.json()) as { issuer: string; payload: { code?: string }; proof: { verificationMethod: string; proofPurpose: string } };
      assert.equal(reply.payload.code, undefined, 'accepted, not refused');
      assert.equal(reply.issuer, serverDid);
      assert.equal(reply.proof.verificationMethod, `${serverDid}#key-boundary`);
      assert.equal(reply.proof.proofPurpose, 'authentication');

      // The reply verifies against the key the server's own log publishes, and not against #key-1.
      const ds = new YugabyteDataSource({ host: '127.0.0.1', port: pgPort, database: 'p2pts', user: 'yugabyte', password: 'yugabyte', poolMin: 1, poolMax: 2 });
      try {
        const rows = await ds.all<{ uuid: string }>('SELECT uuid FROM did_documents WHERE did = ?', serverDid);
        const published = await readPublishedBoundaryKey(ds, rows[0]!.uuid);
        assert.ok(published);
        const resolver: KeyResolver = { async resolve(did) { return did === serverDid ? { did, source: 'offline', keySetAt: 'latest', keys: [{ fragment: 'key-boundary', publicKey: published, relationships: ['authentication'] }] } : null; } };
        const verdict = await new DidProofVerifier({ resolver: new CompositeKeyResolver([resolver, new DidKeyResolver()]) }).verify(reply, { nowMs: Date.now() });
        assert.equal(verdict.valid, true, verdict.detail);
      } finally { await ds.close(); }

      assert.equal((await fetch(`http://127.0.0.1:${ports.listener}/trust-tasks/threads`)).status, 404, 'document surface only');
      assert.equal(s.lines.some((l) => /secret|passphrase|seed/i.test(l) && /trust-tasks\]/.test(l)), false, 'no key material in the structured logs');
    } finally { await s.stop(); }
    assert.equal(await portOpen(ports.listener), false, 'the listener closes with the process');
  });

  await t.test('4. gate on and the key missing: the server refuses to start and binds nothing', async () => {
    rmSync(join(dir, 'data', 'boundary-keystore.db'));
    const s = server({ TRUST_TASKS_BOUNDARY_KEY: 'dedicated', BOUNDARY_KEY_CUTOVER_AT: new Date(Date.now() - 3_600_000).toISOString(), TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: String(ports.listener) });
    const code = await exitOrTimeout(s);
    await s.stop();
    assert.notEqual(code, 'timeout', 'must exit by itself');
    assert.notEqual(code, 0);
    assert.ok(s.lines.some((l) => /"event":"startup\.refused"/.test(l) && /missing/.test(l)), s.lines.slice(-10).join('\n'));
    assert.equal(s.lines.some((l) => /HTTP API listening|listener\.started|signer\.installed/.test(l)), false);
    assert.equal(await portOpen(ports.listener), false);
    assert.equal(await portOpen(ports.http), false);
  });

  await t.test('5. a mistyped gate value is fatal, not a downgrade to #key-1', async () => {
    const s = server({ TRUST_TASKS_BOUNDARY_KEY: 'dedicatd' });
    const code = await exitOrTimeout(s);
    await s.stop();
    assert.ok(typeof code === 'number' && code !== 0, String(code));
    assert.ok(s.lines.some((l) => /"event":"startup\.refused"/.test(l)));
    assert.equal(s.lines.some((l) => /HTTP API listening/.test(l)), false);
  });
  await t.test('6. K4, invalid log chain: gate on refuses to start and repairs nothing; gate off warns, serves, and repairs nothing', async () => {
    await writeRowDoc(stripBoundary);
    const ds = openDb();
    try {
      await ds.run('UPDATE rotation_log SET created_at = created_at + 1 WHERE version = (SELECT MAX(version) FROM rotation_log)');
    } finally { await ds.close(); }
    const before = await readRow();
    const dedicated = server({ TRUST_TASKS_BOUNDARY_KEY: 'dedicated', BOUNDARY_KEY_CUTOVER_AT: new Date(Date.now() - 3_600_000).toISOString(), TRUST_TASKS_LISTENER: '1', TRUST_TASKS_LISTENER_PORT: String(ports.listener) });
    const code = await exitOrTimeout(dedicated);
    await dedicated.stop();
    assert.ok(typeof code === 'number' && code !== 0, String(code));
    assert.ok(dedicated.lines.some((l) => /"event":"startup\.refused"/.test(l) && /rotation log chain is not valid/.test(l)), dedicated.lines.slice(-10).join('\n'));
    assert.equal(dedicated.lines.some((l) => /HTTP API listening|listener\.started|signer\.installed/.test(l)), false);
    assert.deepEqual((await readRow()).row, before.row, 'nothing repaired');
    const off = server();
    try {
      await off.waitFor(/HTTP API listening/, 120_000);
      assert.ok(off.lines.some((l) => /rotation log chain is not valid/.test(l)), 'a warning names the problem');
    } finally { await off.stop(); }
    assert.deepEqual((await readRow()).row, before.row, 'nothing repaired with the gate off either');
  });
});
