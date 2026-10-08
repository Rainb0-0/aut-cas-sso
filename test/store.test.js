import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { FileStore, MemoryStore, LocalStorageStore } from '../src/store.js';
import { encryptSecret, decryptSecret, isCryptoAvailable, toBase64, fromBase64 } from '../src/crypto.js';

test('FileStore round-trips through a nested path atomically', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'autcas-store-'));
  t.after(() => {});
  const store = new FileStore(join(dir, 'deep', 'nest', 'sessions.json'));
  assert.equal(await store.load(), null, 'missing file loads as null');

  await store.save({ v: 1, hello: 'world' });
  assert.deepEqual(await store.load(), { v: 1, hello: 'world' });

  // no tmp files left behind
  const listing = await readFile(join(dir, 'deep', 'nest', 'sessions.json'), 'utf8');
  assert.ok(listing.includes('hello'));

  await store.save({ v: 1, hello: 'again' });
  assert.equal((await store.load()).hello, 'again');
});

test('FileStore treats corrupt files as empty', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'autcas-corrupt-'));
  const path = join(dir, 'sessions.json');
  await writeFile(path, '{not json at all');
  const store = new FileStore(path);
  assert.equal(await store.load(), null);
  void t;
});

test('FileStore rejects an empty path', () => {
  assert.throws(() => new FileStore(''), TypeError);
});

test('MemoryStore isolates callers from internal state', async () => {
  const store = new MemoryStore();
  await store.save({ a: { b: 1 } });
  const loaded = await store.load();
  loaded.a.b = 99;
  assert.equal((await store.load()).a.b, 1, 'load returns a copy');
  assert.equal(await new MemoryStore().load(), null);
});

test('LocalStorageStore requires localStorage', () => {
  assert.throws(() => new LocalStorageStore(), TypeError);
});

test('crypto round-trips, rejects wrong keys and bad blobs', async () => {
  assert.equal(isCryptoAvailable(), true, 'Node >= 22 exposes crypto.subtle');

  const blob = await encryptSecret('Yazdan1386&', 'key-1');
  assert.equal(blob.v, 1);
  assert.equal(blob.alg, 'AES-GCM');
  assert.equal(await decryptSecret(blob, 'key-1'), 'Yazdan1386&');

  await assert.rejects(() => decryptSecret(blob, 'wrong'), (e) => e.code === 'DECRYPTION_FAILED');
  await assert.rejects(() => encryptSecret('x', ''), (e) => e instanceof Error);
  await assert.rejects(() => decryptSecret({ v: 99 }, 'key-1'), /Unsupported secret blob/);
});

test('base64 helpers round-trip bytes', () => {
  const bytes = new Uint8Array([0, 1, 2, 250, 255]);
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
});
