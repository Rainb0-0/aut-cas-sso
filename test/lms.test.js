import test from 'node:test';
import assert from 'node:assert/strict';

import { lmsService, LMS_U5AUTH } from '../src/services/lms.js';
import { UnsupportedEnvironmentError, ServiceLoginError } from '../src/errors.js';
import { CookieJar } from '../src/http.js';
import { mockFetch, ddpWebSocket } from './helpers/mock.js';

const silent = { debug() {}, info() {}, warn() {}, error() {} };

const COMPLETION_HTML = `
<html><body>
  <div id="config">{"setCredentialToken":true,"credentialToken":"STATE1","credentialSecret":"sekret-abc"}</div>
</body></html>`;

function moodleJar() {
  const jar = new CookieJar();
  jar.setFromResponse('https://courses.aut.ac.ir/', 'MoodleSession=m1; Path=/; Secure');
  return jar.toJSON();
}

function oauthFetch() {
  return mockFetch([
    {
      match: (u) => u.hostname === 'courses.aut.ac.ir' && u.pathname.endsWith('/local/oauth/login.php'),
      respond: (u) => ({
        status: 302,
        headers: {
          location: `https://lms.aut.ac.ir/api/_oauth/u5auth?code=thecode&state=${u.searchParams.get('state')}`,
        },
      }),
    },
    {
      match: (u) => u.pathname === '/api/_oauth/u5auth',
      respond: () => ({ status: 200, body: COMPLETION_HTML }),
    },
  ]);
}

function ddpAcceptingOauth() {
  return ddpWebSocket((frame) => {
    if (frame.msg === 'connect') return { msg: 'connected', session: 's1' };
    if (frame.msg === 'method' && frame.method === 'login') {
      const arg = frame.params[0];
      if (arg.oauth) {
        assert.equal(arg.oauth.credentialToken.length, 32, 'random state used as credential token');
        assert.equal(arg.oauth.credentialSecret, 'sekret-abc');
        return {
          msg: 'result',
          id: frame.id,
          result: { id: 'USER1', token: 'TOK123', tokenExpires: { $date: 4102444800000 }, type: 'u5auth' },
        };
      }
      if (arg.resume) {
        if (arg.resume === 'TOK123') {
          return { msg: 'result', id: frame.id, result: { id: 'USER1', token: 'TOK123', tokenExpires: { $date: 4102444800000 } } };
        }
        return { msg: 'result', id: frame.id, error: { error: 403, reason: 'You have been logged out', errorType: 'Meteor.Error' } };
      }
    }
    return null;
  });
}

const ensureSession = async (id) => {
  assert.equal(id, 'courses', 'lms must ask for a Moodle session first');
  return { cookies: moodleJar(), expiresAt: null, lastValidatedAt: Date.now() };
};

test('lms redeem walks moodle -> oauth code -> completion secret -> DDP login', async () => {
  const { fetch, calls } = oauthFetch();
  const WebSocketImpl = ddpAcceptingOauth();

  const state = await lmsService.redeem({ ensureSession, fetchImpl: fetch, logger: silent, WebSocketImpl });

  assert.equal(state.token, 'TOK123');
  assert.equal(state.expiresAt, 4102444800000, 'expiry read from tokenExpires.$date');
  assert.equal(state.meta.userId, 'USER1');
  assert.equal(state.meta.loginType, 'u5auth');

  const authorize = calls.find((c) => c.url.includes('/local/oauth/login.php'));
  assert.ok(authorize, 'authorize called on the Moodle issuer');
  const parsed = new URL(authorize.url);
  assert.equal(parsed.searchParams.get('client_id'), LMS_U5AUTH.clientId);
  assert.equal(parsed.searchParams.get('redirect_uri'), LMS_U5AUTH.redirectUri);
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  // the moodle session cookie must ride along
  assert.match(authorize.headers.cookie || '', /MoodleSession=m1/);
});

test('lms throws UnsupportedEnvironmentError when WebSocket is missing', async () => {
  await assert.rejects(
    () => lmsService.redeem({ ensureSession, fetchImpl: () => {}, logger: silent, WebSocketImpl: null }),
    (err) => err instanceof UnsupportedEnvironmentError && err.code === 'UNSUPPORTED_ENVIRONMENT',
  );
});

test('lms redeem surfaces authorize failures as ServiceLoginError', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname.endsWith('/login.php'),
      respond: () => ({ status: 400, body: JSON.stringify({ error: 'redirect_uri_mismatch' }) }),
    },
  ]);
  await assert.rejects(
    () => lmsService.redeem({ ensureSession, fetchImpl: fetch, logger: silent, WebSocketImpl: ddpAcceptingOauth() }),
    (err) => err instanceof ServiceLoginError && err.service === 'lms',
  );
});

test('lms redeem fails cleanly when the completion page has no secret', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname.endsWith('/login.php'),
      respond: () => ({ status: 302, headers: { location: 'https://lms.aut.ac.ir/api/_oauth/u5auth?code=c&state=s' } }),
    },
    { match: (u) => u.pathname === '/api/_oauth/u5auth', respond: () => ({ status: 200, body: '<html>error</html>' }) },
  ]);
  await assert.rejects(
    () => lmsService.redeem({ ensureSession, fetchImpl: fetch, logger: silent, WebSocketImpl: ddpAcceptingOauth() }),
    (err) => err instanceof ServiceLoginError && /credentialSecret/.test(err.message),
  );
});

test('lms probe accepts a live resume token and rejects a dead one', async () => {
  const WebSocketImpl = ddpAcceptingOauth();
  assert.equal(
    await lmsService.probe({ state: { token: 'TOK123' }, logger: silent, WebSocketImpl }),
    true,
  );
  assert.equal(
    await lmsService.probe({ state: { token: 'DEAD' }, logger: silent, WebSocketImpl }),
    false,
    'DDP login error => definitive false',
  );
  assert.equal(await lmsService.probe({ state: { token: null }, logger: silent, WebSocketImpl }), false);
});

test('lms toCredential exposes a token-type credential with expiry', () => {
  const cred = lmsService.toCredential({ token: 'T', expiresAt: 4102444800000, lastValidatedAt: 123 });
  assert.equal(cred.type, 'token');
  assert.equal(cred.token, 'T');
  assert.equal(cred.cookies, null);
  assert.equal(cred.header, null, 'Meteor resume tokens are not HTTP Authorization headers');
  assert.equal(cred.expiresAt, 4102444800000);
});
