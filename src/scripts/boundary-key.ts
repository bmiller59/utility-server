// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-TrustStackers-Commercial
// Copyright (C) 2026 Trust Stackers

/**
 * Operator CLI for the utility server's dedicated `#key-boundary` key (gate G2).
 *
 *   npm run boundary-key -- <command> [--generation N] [--execute]
 *
 * Commands:
 *   provision --generation N   generate generation N into the key store (never overwrites)
 *   publish   --generation N   first publication of #key-boundary in the server's rotation log
 *   rotate    --generation N   replace the published key with a NEW generation N
 *   retire                     remove #key-boundary from the document (retirement, cutover rollback)
 *   destroy   --generation N   delete the stored secret of a generation the document does not publish
 *   status                     what is published and which generations are held (read-only)
 *
 * Mutating commands are a DRY RUN unless `--execute` is given: everything is validated (the log entry is
 * built and chain-validated in memory) and nothing is written. The key store passphrase is read ONLY from
 * TSP_SEED_PASSPHRASE (never from an argument); without it every command refuses. Output carries
 * generations, fingerprints (a hash prefix of the public key), versions and notes: no key, seed or
 * passphrase is ever printed. Exit status 0 on success, 1 on any refusal. There is no network or UI route.
 *
 * Environment: TSP_SEED_PASSPHRASE (required), BOUNDARY_KEYSTORE_PATH (default <data dir>/boundary-keystore.db),
 * UTILITY_DATA_DIR, NODE_NAME, YB_HOST / YB_PORT / YB_DATABASE / YB_USER / YB_PASSWORD (as the server).
 */
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { DataSource } from '@p2p-trust-stack/core/db/data-source.js';
import { SqliteKeyStore } from '@p2p-trust-stack/core/keystore/sqlite-keystore.js';
import { resolveSeedPassphrase } from '@p2p-trust-stack/core/crypto/seed-at-rest.js';
import type { BoundaryKeyStore } from '@p2p-trust-stack/core/services/trust-tasks/boundary/proof/key-custody.js';
import { loadServerBoundaryIdentity, resolveBoundaryKeystorePath, resolveDataDir, runBoundaryAdmin } from '../services/boundary-key-admin.js';
import type { BoundaryAdminCommand, ServerBoundaryIdentity } from '../services/boundary-key-admin.js';

const COMMANDS: readonly BoundaryAdminCommand[] = ['provision', 'publish', 'rotate', 'retire', 'destroy', 'status'];
const NEEDS_GENERATION = new Set<BoundaryAdminCommand>(['provision', 'publish', 'rotate', 'destroy']);
const USAGE = `usage: boundary-key <${COMMANDS.join('|')}> [--generation N] [--execute]\n(mutating commands are a dry run without --execute; the passphrase comes from TSP_SEED_PASSPHRASE)`;

export interface ParsedArgs { command: BoundaryAdminCommand; generation?: number; execute: boolean }

export function parseArgs(argv: readonly string[]): ParsedArgs {
  const [command, ...rest] = argv;
  if (command === undefined || !(COMMANDS as readonly string[]).includes(command)) throw new Error(`unknown or missing command\n${USAGE}`);
  let generation: number | undefined;
  let execute = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i]!;
    if (a === '--execute') execute = true;
    else if (a === '--generation') {
      const v = rest[++i];
      if (v === undefined || !/^[1-9][0-9]*$/.test(v)) throw new Error('--generation needs a positive integer');
      generation = Number(v);
    } else throw new Error(`unknown argument ${a}\n${USAGE}`);
  }
  const cmd = command as BoundaryAdminCommand;
  if (NEEDS_GENERATION.has(cmd) && generation === undefined) throw new Error(`${cmd} needs --generation N`);
  if (!NEEDS_GENERATION.has(cmd) && generation !== undefined) throw new Error(`${cmd} takes no --generation`);
  return { command: cmd, ...(generation === undefined ? {} : { generation }), execute };
}

export interface CliDeps {
  /** Opens the database (default: the server's YugabyteDB connection). */
  openDb?: () => Promise<{ db: DataSource; close: () => Promise<void> }>;
  keystore?: BoundaryKeyStore & { close(): void };
  configJson?: Record<string, unknown>;
  identity?: ServerBoundaryIdentity;
  now?: number;
}

/** Runs the CLI; returns the exit status. Lines go to `out` (stdout) and `err` (stderr). */
export async function runCli(argv: readonly string[], env: Readonly<Record<string, string | undefined>>, out: (l: string) => void, err: (l: string) => void, deps: CliDeps = {}): Promise<number> {
  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    err((e as Error).message);
    return 1;
  }
  const passphrase = resolveSeedPassphrase(env.TSP_SEED_PASSPHRASE ?? '');
  if (passphrase === undefined) {
    err('refused: TSP_SEED_PASSPHRASE is required; there is no default passphrase');
    return 1;
  }
  let close: (() => Promise<void>) | undefined;
  let keystore: (BoundaryKeyStore & { close(): void }) | undefined;
  try {
    const dataDir = resolveDataDir(env, join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'data'));
    const configJson = deps.configJson ?? (JSON.parse(await readFile(join(dataDir, 'config.json'), 'utf8')) as Record<string, unknown>);
    const opened = deps.openDb !== undefined ? await deps.openDb() : await openServerDb();
    close = opened.close;
    // A read-only run (status, dry run) never creates the key store file: an absent file reads as empty.
    const keystorePath = resolveBoundaryKeystorePath(env, dataDir);
    keystore = deps.keystore ?? new SqliteKeyStore(parsed.execute || existsSync(keystorePath) ? keystorePath : ':memory:');
    const identity = deps.identity ?? await loadServerBoundaryIdentity({ db: opened.db, nodeName: env.NODE_NAME ?? 'utility-server', configJson, passphrase });
    const result = await runBoundaryAdmin(parsed.command, {
      db: opened.db, keystore, passphrase, identity, execute: parsed.execute, ...(deps.now === undefined ? {} : { now: deps.now }),
    }, parsed.generation === undefined ? {} : { generation: parsed.generation });
    out(JSON.stringify(result));
    return 0;
  } catch (e) {
    err(`refused: ${(e as Error).message}`);
    return 1;
  } finally {
    keystore?.close();
    if (close !== undefined) await close();
  }
}

async function openServerDb(): Promise<{ db: DataSource; close: () => Promise<void> }> {
  const { loadConfig } = await import('../config.js');
  const { YugabyteDataSource } = await import('../db/yugabyte-data-source.js');
  const config = loadConfig();
  const ds = new YugabyteDataSource({
    host: config.ybHost, port: config.ybPort, database: config.ybDatabase, user: config.ybUser, password: config.ybPassword, poolMin: 1, poolMax: 2,
  });
  return { db: ds, close: async () => { await (ds as unknown as { close?: () => Promise<void> }).close?.(); } };
}

if (process.argv[1] !== undefined && fileURLToPath(import.meta.url) === process.argv[1]) {
  runCli(process.argv.slice(2), process.env, (l) => console.log(l), (l) => console.error(l)).then((code) => process.exit(code));
}
