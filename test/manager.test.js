import test from 'node:test';
import assert from 'node:assert/strict';

import { SessionManager } from '../src/manager.js';
import { MemoryStore, FileStore } from '../src/store.js';
import { ConfigurationError, ReauthenticationRequiredError } from '../src/errors.js';
import { mockFetch } from './helpers/mock.js';

/* ------------------------------------------------------------------ */
/* fakes                                                               */
/* ------------------------------------------------------------------ */

function fakeService(id = 'fake') {
  const stats = { redeem: 0, probe: 0, ttlMs: null, probeResult: true, probeError: null };
  const adapter = {
    id,
    title: `fake ${id}`,
    requiresCas: true,
    serviceUrl: `https://${id}.test/login`,
    async redeem({ ticket }) {
      stats.redeem++;
      stats.lastTicket = ticket;
      return {
        cookies: {
          sess: { value: 'v', domain: `${id}.test`, hostOnly: true, path: '/', secure: true, expiresAt: null },
        },
        expiresAt: stats.ttlMs != null ? Date.now() + stats.ttlMs : null,
        lastValidatedAt: Date.now(),
        meta: { ticket },
      };
    },
    async probe() {
      stats.probe++;
      if (stats.probeError) throw stats.probeError;
      return stats.probeResult;
    },
    toCredential(state) {
      return {
        type: 'cookie',
        cookies: { sess: 'v' },
        token: null,
        header: null,
        expiresAt: state.expiresAt ?? null,
        obtainedAt: state.lastValidatedAt,
      };
    },
  };
  return { adapter, stats };
}

function casRoutes() {
  return [
    {
      method: 'POST',
      match: (u) => u.pathname === '/cas/v1/tickets',
      respond: () => ({ status: 201, headers: { location: 'http://cas.test/cas/v1/tickets/TGT-1' } }),
    },
    {
      method: 'POST',
      match: (u) => u.pathname.includes('/tickets/TGT-'),
      respond: () => ({ status: 200, body: 'ST-minted' }),
    },
  ];
}

function spyLogger() {
  const records = { debug: [], info: [], warn: [], error: [] };
  const logger = {};
  for (const lvl of Object.keys(records)) {
    logger[lvl] = (message, meta) => records[lvl].push({ message, meta });
  }
  return { logger, records };
}

function makeManager({ services, accounts, store = new MemoryStore(), key, logger, ...rest } = {}) {
  const { fetch, calls } = mockFetch(casRoutes());
  const mgr = new SessionManager({
    accounts: accounts || [{ id: 'a', username: 'user', password: 'pass' }],
    store,
    fetchImpl: fetch,
    services,
    encryptionKey: key,
    logger,
    ...rest,
  });
  return { mgr, calls };
}

/* ------------------------------------------------------------------ */
/* API misuse                                                          */
/* ------------------------------------------------------------------ */

test('accountId is always required', async () => {
  const { mgr } = makeManager({ services: { fake: fakeService().adapter } });
  await assert.rejects(() => mgr.getCredential('fake'), (err) => err instanceof ConfigurationError && /accountId/.test(err.message));
  await assert.rejects(() => mgr.getCredential('fake', ''), (err) => err instanceof ConfigurationError);
});

test('unknown account and unknown service produce helpful errors', async () => {
  const { mgr } = makeManager({ services: { fake: fakeService().adapter } });
  await assert.rejects(() => mgr.getCredential('fake', 'ghost'), (err) => /Unknown account "ghost"/.test(err.message));
  await assert.rejects(() => mgr.getCredential('nope', 'a'), (err) => /Unknown service "nope" \(known: fake\)/.test(err.message));
});

test('bad constructor options fail fast', () => {
  assert.throws(() => new SessionManager({ store: null }), (e) => e instanceof ConfigurationError);
  assert.throws(() => new SessionManager({ fetchImpl: null }), (e) => e instanceof ConfigurationError);
});

test('listAccounts never exposes passwords', async () => {
  const { mgr } = makeManager({ services: { fake: fakeService().adapter } });
  await mgr.getCredential('fake', 'a');
  assert.deepEqual(mgr.listAccounts(), [{ id: 'a', username: 'user' }]);
});

/* ------------------------------------------------------------------ */
/* fetch / probe / refresh policy                                      */
/* ------------------------------------------------------------------ */

test('first call fetches, later calls reuse the cached session without network', async () => {
  const { adapter, stats } = fakeService();
  const { mgr, calls } = makeManager({ services: { fake: adapter } });

  const cred = await mgr.getCredential('fake', 'a');
  assert.equal(cred.service, 'fake');
  assert.equal(cred.accountId, 'a');
  assert.equal(cred.type, 'cookie');
  assert.equal(cred.remainingMs, null, 'unknown expiry => null remaining');
  assert.equal(stats.redeem, 1);
  const callsAfterFirst = calls.length;

  const again = await mgr.getCredential('fake', 'a');
  assert.equal(again.cookies.sess, 'v');
  assert.equal(stats.redeem, 1, 'no second redeem');
  assert.equal(calls.length, callsAfterFirst, 'no network on the fast path');
});

test('concurrent getCredential calls share one redeem and one CAS login', async () => {
  const { adapter, stats } = fakeService();
  const { mgr, calls } = makeManager({ services: { fake: adapter } });

  const creds = await Promise.all([
    mgr.getCredential('fake', 'a'),
    mgr.getCredential('fake', 'a'),
    mgr.getCredential('fake', 'a'),
    mgr.getCredential('fake', 'a'),
  ]);
  assert.equal(stats.redeem, 1, 'single-flighted redeem');
  assert.equal(calls.filter((c) => c.url.endsWith('/cas/v1/tickets')).length, 1, 'one CAS login');
  assert.equal(calls.filter((c) => c.url.includes('/tickets/TGT-')).length, 1, 'one ticket mint');
  for (const c of creds) assert.equal(c.cookies.sess, 'v');
});

test('stale session is probed; healthy probe avoids refetch', async () => {
  const { adapter, stats } = fakeService();
  const { mgr } = makeManager({ services: { fake: adapter }, probeIntervalMs: 0 });

  await mgr.getCredential('fake', 'a');
  assert.equal(stats.probe, 0, 'not stale on first fetch');

  await mgr.getCredential('fake', 'a');
  assert.equal(stats.probe, 1, 'probed once stale');
  assert.equal(stats.redeem, 1, 'healthy probe => no refetch');
});

test('probe reporting dead triggers a refresh', async () => {
  const { adapter, stats } = fakeService();
  stats.probeResult = false;
  const { mgr } = makeManager({ services: { fake: adapter }, probeIntervalMs: 0 });

  await mgr.getCredential('fake', 'a');
  await mgr.getCredential('fake', 'a');
  assert.equal(stats.probe, 1);
  assert.equal(stats.redeem, 2, 'dead probe => refetched');
});

test('probe transport failure keeps serving the cached session', async () => {
  const { adapter, stats } = fakeService();
  stats.probeError = new Error('network unreachable');
  const { logger, records } = spyLogger();
  const { mgr } = makeManager({ services: { fake: adapter }, probeIntervalMs: 0, logger });

  await mgr.getCredential('fake', 'a');
  const cred = await mgr.getCredential('fake', 'a');
  assert.equal(cred.cookies.sess, 'v', 'cached credential still served');
  assert.equal(stats.redeem, 1, 'not refreshed on unknown');
  assert.ok(records.warn.some((r) => /probe unavailable/.test(r.message)));
});

test('hard expiry refreshes without probing', async () => {
  const { adapter, stats } = fakeService();
  stats.ttlMs = 40;
  const { mgr } = makeManager({ services: { fake: adapter }, expirySafetyMs: 0, probeIntervalMs: 60_000 });

  await mgr.getCredential('fake', 'a');
  assert.equal(stats.redeem, 1);
  const firstExpiry = (await mgr.getSessionInfo('fake', 'a')).expiresAt;
  assert.ok(firstExpiry > Date.now());

  await new Promise((r) => setTimeout(r, 60));
  const cred = await mgr.getCredential('fake', 'a');
  assert.ok(cred.expiresAt > firstExpiry, 'refreshed state has a fresh expiry');
  assert.equal(stats.redeem, 2, 'expired => refetched');
  assert.equal(stats.probe, 0, 'expiry known locally, no probe needed');
});

test('invalidate() forces the next call to refetch', async () => {
  const { adapter, stats } = fakeService();
  const { mgr, records } = makeManager({ services: { fake: adapter }, logger: undefined });
  void records;

  await mgr.getCredential('fake', 'a');
  assert.equal(mgr.getSessionInfo('fake', 'a').present, true);
  mgr.invalidate('fake', 'a');
  assert.equal(mgr.getSessionInfo('fake', 'a'), null);
  await mgr.getCredential('fake', 'a');
  assert.equal(stats.redeem, 2);
});

/* ------------------------------------------------------------------ */
/* CAS handling                                                        */
/* ------------------------------------------------------------------ */

test('multiple services on one account share a single CAS TGT login', async () => {
  const one = fakeService('s1');
  const two = fakeService('s2');
  const { mgr, calls } = makeManager({ services: { s1: one.adapter, s2: two.adapter } });

  await Promise.all([mgr.getCredential('s1', 'a'), mgr.getCredential('s2', 'a')]);
  const logins = calls.filter((c) => c.url.endsWith('/cas/v1/tickets'));
  assert.equal(logins.length, 1, 'one TGT for the account');
  assert.equal(one.stats.redeem, 1);
  assert.equal(two.stats.redeem, 1);
});

test('dead TGT mid-flight triggers exactly one re-login retry', async () => {
  const { adapter, stats } = fakeService();
  let ticketCalls = 0;
  const routes = [
    {
      method: 'POST',
      match: (u) => u.pathname === '/cas/v1/tickets',
      respond: () => ({ status: 201, headers: { location: 'http://cas.test/cas/v1/tickets/TGT-1' } }),
    },
    {
      method: 'POST',
      match: (u) => u.pathname.includes('/tickets/TGT-'),
      respond: () => {
        ticketCalls++;
        if (ticketCalls === 1) return { status: 404, body: '{"errors":["gone"]}' };
        return { status: 200, body: 'ST-after-relogin' };
      },
    },
  ];
  const { fetch, calls } = mockFetch(routes);
  const mgr = new SessionManager({
    accounts: [{ id: 'a', username: 'u', password: 'p' }],
    store: new MemoryStore(),
    fetchImpl: fetch,
    services: { fake: adapter },
  });

  const cred = await mgr.getCredential('fake', 'a');
  assert.equal(stats.redeem, 1);
  assert.equal(stats.lastTicket, 'ST-after-relogin');
  assert.equal(calls.filter((c) => c.url.endsWith('/cas/v1/tickets')).length, 2, 'original login + re-login');
  assert.equal(cred.cookies.sess, 'v');
});

/* ------------------------------------------------------------------ */
/* persistence & encryption                                            */
/* ------------------------------------------------------------------ */

test('sessions persist and are reused after a restart without any network', async () => {
  const store = new MemoryStore();
  const first = fakeService();
  const one = makeManager({ services: { fake: first.adapter }, store, key: 'k1' });
  await one.mgr.getCredential('fake', 'a');
  await one.mgr.flush();
  assert.equal(first.stats.redeem, 1);

  // "restart": new manager over the same store, fresh adapter
  const second = fakeService();
  const { mgr, calls } = makeManager({ services: { fake: second.adapter }, store, key: 'k1', accounts: [] });
  const cred = await mgr.getCredential('fake', 'a');
  assert.equal(second.stats.redeem, 0, 'session restored from disk, no refetch');
  assert.equal(calls.length, 0, 'no CAS traffic after restart');
  assert.equal(cred.cookies.sess, 'v');
});

test('passwords are encrypted at rest when a key is configured', async () => {
  const store = new MemoryStore();
  const { mgr } = makeManager({ services: { fake: fakeService().adapter }, store, key: 'sekret' });
  await mgr.getCredential('fake', 'a');
  await mgr.flush();

  const raw = await store.load();
  assert.equal(raw.accounts.a.username, 'user');
  assert.equal(raw.accounts.a.password.alg, 'AES-GCM', 'password stored as AES-GCM blob');
  assert.ok(!JSON.stringify(raw).includes('pass"') || raw.accounts.a.password.ct, 'no plaintext password field');
  assert.ok(raw.sessions['fake::a'], 'session persisted');
});

test('without a key, passwords are skipped with a warning and refresh later fails as REAUTH_REQUIRED', async () => {
  const store = new MemoryStore();
  const { logger, records } = spyLogger();
  const withKey = makeManager({ services: { fake: fakeService().adapter }, store, key: 'sekret', logger });
  await withKey.mgr.getCredential('fake', 'a');
  await withKey.mgr.flush();

  // restart WITHOUT the key and without a session for another service
  const { logger: l2, records: r2 } = spyLogger();
  const other = fakeService('other');
  const { mgr, calls } = makeManager({
    services: { other: other.adapter },
    store,
    accounts: [],
    logger: l2,
  });
  await mgr.start();

  await assert.rejects(
    () => mgr.getCredential('other', 'a'),
    (err) => err instanceof ReauthenticationRequiredError && err.code === 'REAUTH_REQUIRED',
  );
  assert.ok(r2.warn.some((w) => /cannot be decrypted/.test(w.message)), 'warns about the missing key');
  assert.equal(calls.length, 0, 'no pointless CAS attempt without a password');
  void records;
});

test('sessions and tgts are isolated per account; removeAccount cleans up', async () => {
  const { adapter, stats } = fakeService();
  const { mgr, calls } = makeManager({
    services: { fake: adapter },
    accounts: [
      { id: 'a', username: 'u1', password: 'p1' },
      { id: 'b', username: 'u2', password: 'p2' },
    ],
  });

  await mgr.getCredential('fake', 'a');
  await mgr.getCredential('fake', 'b');
  assert.equal(stats.redeem, 2, 'one session per account');
  const logins = calls.filter((c) => c.url.endsWith('/cas/v1/tickets'));
  assert.equal(logins.length, 2, 'one TGT per account');
  assert.deepEqual(
    new Set(logins.map((c) => c.body)),
    new Set(['username=u1&password=p1', 'username=u2&password=p2']),
  );

  mgr.removeAccount('b');
  assert.equal(mgr.getSessionInfo('fake', 'b'), null, "b's session dropped");
  assert.deepEqual(mgr.listAccounts(), [{ id: 'a', username: 'u1' }]);
});

test('default store is a cwd-relative FileStore', () => {
  const mgr = new SessionManager({ accounts: [{ id: 'x', username: 'u', password: 'p' }] });
  assert.ok(mgr.store instanceof FileStore);
  assert.ok(mgr.store.path.endsWith('.aut-cas-sessions.json'));
});
