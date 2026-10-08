import test from 'node:test';
import assert from 'node:assert/strict';

import { CasClient, upgradeToHttps } from '../src/cas.js';
import { InvalidCredentialsError, TgtInvalidError, AutCasError } from '../src/errors.js';
import { mockFetch } from './helpers/mock.js';

const TGT_LOCATION = 'http://cas.test/cas/v1/tickets/TGT-1-abc';

function casClient(routes) {
  const { fetch, calls } = mockFetch(routes);
  const client = new CasClient({ baseUrl: 'https://cas.test/cas', fetchImpl: fetch });
  return { client, calls };
}

test('requestTgt upgrades the http Location to https', async () => {
  const { client, calls } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname === '/cas/v1/tickets',
      respond: () => ({ status: 201, headers: { location: TGT_LOCATION } }),
    },
  ]);
  const tgt = await client.requestTgt('user', 'pass');
  assert.equal(tgt.url, 'https://cas.test/cas/v1/tickets/TGT-1-abc');
  assert.ok(tgt.expiresAt > tgt.createdAt);
  assert.equal(calls[0].body, 'username=user&password=pass');
});

test('requestTgt rejects bad credentials with extracted CAS detail', async () => {
  const { client } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname === '/cas/v1/tickets',
      respond: () => ({
        status: 401,
        body: JSON.stringify({
          '@class': 'java.util.HashMap',
          authentication_exceptions: ['java.util.ArrayList', ['FailedLoginException: nope']],
        }),
      }),
    },
  ]);
  await assert.rejects(
    () => client.requestTgt('user', 'bad'),
    (err) => err instanceof InvalidCredentialsError && err.code === 'INVALID_CREDENTIALS' && err.message.includes('nope'),
  );
});

test('requestTgt surfaces 5xx as CAS_LOGIN_FAILED', async () => {
  const { client } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname === '/cas/v1/tickets',
      respond: () => ({ status: 503, body: 'unavailable' }),
    },
  ]);
  await assert.rejects(
    () => client.requestTgt('user', 'pass'),
    (err) => err instanceof AutCasError && err.code === 'CAS_LOGIN_FAILED' && err.status === 503,
  );
});

test('serviceTicket returns the ST body and posts the service field', async () => {
  const { client, calls } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname.includes('/tickets/TGT-'),
      respond: () => ({ status: 200, body: 'ST-1-xyz\n' }),
    },
  ]);
  const tgt = { url: 'https://cas.test/cas/v1/tickets/TGT-1-abc', createdAt: Date.now(), expiresAt: Date.now() + 1000 };
  const ticket = await client.serviceTicket(tgt, 'https://svc.test/login');
  assert.equal(ticket, 'ST-1-xyz');
  assert.equal(calls[0].body, 'service=https%3A%2F%2Fsvc.test%2Flogin');
});

test('serviceTicket maps 404 to TgtInvalidError so the manager re-logs-in', async () => {
  const { client } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname.includes('/tickets/'),
      respond: () => ({ status: 404, body: '{"errors":["Ticket does not exist"]}' }),
    },
  ]);
  const tgt = { url: 'https://cas.test/cas/v1/tickets/TGT-dead', createdAt: 0, expiresAt: Date.now() + 1000 };
  await assert.rejects(
    () => client.serviceTicket(tgt, 'https://svc.test/'),
    (err) => err instanceof TgtInvalidError && err.code === 'TGT_INVALID' && err.message.includes('does not exist'),
  );
});

test('serviceTicket rejects non-ticket bodies', async () => {
  const { client } = casClient([
    {
      method: 'POST',
      match: (url) => url.pathname.includes('/tickets/'),
      respond: () => ({ status: 200, body: '<html>weird</html>' }),
    },
  ]);
  const tgt = { url: 'https://cas.test/cas/v1/tickets/TGT-1', createdAt: 0, expiresAt: Date.now() + 1000 };
  await assert.rejects(
    () => client.serviceTicket(tgt, 'https://svc.test/'),
    (err) => err.code === 'CAS_TICKET_MALFORMED',
  );
});

test('ensureTgtAndTicket refuses locally expired TGTs without a request', async () => {
  const { client, calls } = casClient([]);
  await assert.rejects(
    () => client.ensureTgtAndTicket({ url: 'https://cas.test/t', createdAt: 0, expiresAt: Date.now() - 1 }, 'https://s/'),
    (err) => err instanceof TgtInvalidError,
  );
  assert.equal(calls.length, 0);
});

test('upgradeToHttps only rewrites plain http', () => {
  assert.equal(upgradeToHttps('http://a.test/x'), 'https://a.test/x');
  assert.equal(upgradeToHttps('https://a.test/x'), 'https://a.test/x');
});
