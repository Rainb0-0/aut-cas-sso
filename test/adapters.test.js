import test from 'node:test';
import assert from 'node:assert/strict';

import { coursesService, moodleLooksAuthenticated, COURSES_SERVICE_URL } from '../src/services/courses.js';
import { lmshomeService, LMSHOME_SERVICE_URL } from '../src/services/lmshome.js';
import { samadService, samadLooksAuthenticated, SAMAD_SERVICE_URL } from '../src/services/samad.js';
import { foodService, foodLooksAuthenticated, FOOD_SERVICE_URL } from '../src/services/food.js';
import { ServiceLoginError } from '../src/errors.js';
import { CookieJar } from '../src/http.js';
import { mockFetch } from './helpers/mock.js';

const silent = { debug() {}, info() {}, warn() {}, error() {} };

/* ------------------------------------------------------------------ */
/* courses / Moodle                                                    */
/* ------------------------------------------------------------------ */

test('moodleLooksAuthenticated classifies responses', () => {
  assert.equal(moodleLooksAuthenticated({ url: 'https://courses.aut.ac.ir/my/', status: 200 }), true);
  assert.equal(
    moodleLooksAuthenticated({ url: 'https://courses.aut.ac.ir/login/index.php?testsession=141', status: 200 }),
    true,
  );
  assert.equal(moodleLooksAuthenticated({ url: 'https://courses.aut.ac.ir/login/index.php', status: 200 }), false);
  assert.equal(
    moodleLooksAuthenticated({
      url: 'https://accounts.aut.ac.ir/cas/login?service=x',
      status: 200,
    }),
    false,
    'bounced to CAS',
  );
  assert.equal(moodleLooksAuthenticated({ url: 'https://courses.aut.ac.ir/my/', status: 500 }), false);
  assert.equal(moodleLooksAuthenticated({ url: 'https://courses.aut.ac.ir/my/', status: 302 }), false, '3xx is never success');
});

test('courses redeem follows the CAS redirect chain and captures cookies', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (u) => u.hostname === 'courses.aut.ac.ir' && u.searchParams.has('ticket'),
      respond: () => ({
        status: 302,
        headers: {
          location: 'https://courses.aut.ac.ir/login/index.php?testsession=141',
          'set-cookie': 'MoodleSession=abc; path=/; secure',
        },
      }),
    },
    {
      match: (u) => u.searchParams.has('testsession'),
      respond: () => ({
        status: 302,
        headers: {
          location: 'https://courses.aut.ac.ir/my/',
          'set-cookie': ['MOODLEID1_=tok; expires=' + new Date(Date.now() + 86400000).toUTCString() + '; path=/; secure', 'HAX=x; path=/; HttpOnly; Secure'],
        },
      }),
    },
    { match: (u) => u.pathname === '/my/', respond: () => ({ status: 200, body: '<title>dashboard</title>' }) },
  ]);

  const state = await coursesService.redeem({ ticket: 'ST-1', fetchImpl: fetch, logger: silent });
  assert.equal(state.expiresAt, null, 'Moodle never discloses expiry');
  assert.ok(state.cookies.MoodleSession, 'MoodleSession captured');
  assert.ok(state.cookies.MOODLEID1_, 'remember-me captured');
  assert.equal(state.meta.finalUrl, 'https://courses.aut.ac.ir/my/');
  assert.ok(calls[0].url.includes(`ticket=ST-1`), 'ticket redeemed on the registered service URL');
});

test('courses redeem fails with ServiceLoginError when bounced to CAS', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.searchParams.has('ticket'),
      respond: () => ({
        status: 302,
        headers: { location: 'https://accounts.aut.ac.ir/cas/login?service=x' },
      }),
    },
    {
      match: (u) => u.hostname === 'accounts.aut.ac.ir',
      respond: () => ({ status: 200, body: '<form id="fm1">' }),
    },
  ]);

  await assert.rejects(
    () => coursesService.redeem({ ticket: 'ST-bad', fetchImpl: fetch, logger: silent }),
    (err) => err instanceof ServiceLoginError && err.service === 'courses',
  );
});

test('courses redeem replays the remember-me cookie without spending the ticket', async () => {
  const jar = new CookieJar();
  jar.setFromResponse('https://courses.aut.ac.ir/', `MOODLEID1_=tok; Expires=${new Date(Date.now() + 86400000).toUTCString()}; Path=/; Secure`);

  const { fetch, calls } = mockFetch([
    {
      match: (u) => u.pathname === '/my/',
      respond: () => ({ status: 200, body: '<title>dashboard</title>' }),
    },
    { match: (u) => u.searchParams.has('ticket'), respond: () => ({ status: 500, body: 'should not happen' }) },
  ]);

  const state = await coursesService.redeem({ ticket: 'ST-not-needed', jar, fetchImpl: fetch, logger: silent });
  assert.equal(state.meta.finalUrl, 'https://courses.aut.ac.ir/my/');
  assert.ok(
    calls.every((c) => !c.url.includes('ticket=')),
    'no CAS ticket request was made',
  );
});

test('courses probe: live jar true, empty jar false', async () => {
  const live = new CookieJar();
  live.setFromResponse('https://courses.aut.ac.ir/', 'MoodleSession=1; Path=/; Secure');
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname === '/my/',
      respond: (u, init) => {
        const hasCookie = String(init.headers?.cookie || '').includes('MoodleSession=1');
        if (hasCookie) return { status: 200, body: 'ok' };
        return { status: 302, headers: { location: 'https://courses.aut.ac.ir/login/index.php' } };
      },
    },
    {
      match: (u) => u.pathname.startsWith('/login/'),
      respond: () => ({ status: 200, body: '<form action="login">' }),
    },
  ]);

  assert.equal(await coursesService.probe({ state: { cookies: live.toJSON() }, fetchImpl: fetch, logger: silent }), true);
  assert.equal(await coursesService.probe({ state: { cookies: {} }, fetchImpl: fetch, logger: silent }), false);
});

/* ------------------------------------------------------------------ */
/* lmshome / Fararoom                                                  */
/* ------------------------------------------------------------------ */

test('lmshome redeem parses the callback and the 12h session expiry', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (u) => u.pathname === '/api/v1/auth/sso/callback/',
      respond: () => ({
        status: 200,
        headers: {
          'set-cookie': [
            `csrftoken=csrf; Max-Age=31449600; Path=/; SameSite=Lax; Secure`,
            `sessionid=sess123; Max-Age=43200; Path=/; SameSite=Lax; Secure`,
          ],
        },
        body: JSON.stringify({ data: { user: { username: 'yazdanrezaie' } } }),
      }),
    },
  ]);

  const state = await lmshomeService.redeem({ ticket: 'ST-9', fetchImpl: fetch, logger: silent });
  const drift = state.expiresAt - (Date.now() + 43200 * 1000);
  assert.ok(Math.abs(drift) < 5000, `expiresAt tracks sessionid Max-Age (drift ${drift}ms)`);
  assert.equal(state.cookies.sessionid.value, 'sess123');
  assert.equal(state.meta.username, 'yazdanrezaie');
  assert.ok(calls[0].url.includes('ticket=ST-9'));
  assert.equal(lmshomeService.serviceUrl, LMSHOME_SERVICE_URL);
});

test('lmshome redeem rejects error payloads and missing sessionid', async () => {
  const a = mockFetch([
    {
      match: (u) => u.pathname.includes('/callback'),
      respond: () => ({ status: 400, body: JSON.stringify({ error: { code: 'cas_invalid' } }) }),
    },
  ]);
  await assert.rejects(
    () => lmshomeService.redeem({ ticket: 'ST-x', fetchImpl: a.fetch, logger: silent }),
    (err) => err instanceof ServiceLoginError && err.detail === 'cas_invalid',
  );

  const b = mockFetch([
    {
      match: (u) => u.pathname.includes('/callback'),
      respond: () => ({ status: 200, body: JSON.stringify({ data: {} }) }),
    },
  ]);
  await assert.rejects(
    () => lmshomeService.redeem({ ticket: 'ST-x', fetchImpl: b.fetch, logger: silent }),
    (err) => err instanceof ServiceLoginError && /session cookie/.test(err.message),
  );
});

test('lmshome probe uses /auth/me/', async () => {
  const ok = mockFetch([
    {
      match: (u) => u.pathname === '/api/v1/auth/me/',
      respond: () => ({ status: 200, body: JSON.stringify({ data: { username: 'u' } }) }),
    },
  ]);
  assert.equal(await lmshomeService.probe({ state: { cookies: {} }, fetchImpl: ok.fetch, logger: silent }), true);

  const dead = mockFetch([
    { match: (u) => u.pathname === '/api/v1/auth/me/', respond: () => ({ status: 401, body: '{}' }) },
  ]);
  assert.equal(await lmshomeService.probe({ state: { cookies: {} }, fetchImpl: dead.fetch, logger: silent }), false);
});

/* ------------------------------------------------------------------ */
/* samad                                                               */
/* ------------------------------------------------------------------ */

test('samadLooksAuthenticated classifies responses', () => {
  assert.equal(
    samadLooksAuthenticated({ url: 'https://samad.aut.ac.ir/index/index.rose', status: 200, text: '<div>خروج</div>' }),
    true,
  );
  assert.equal(
    samadLooksAuthenticated({ url: 'https://samad.aut.ac.ir/index/index.rose', status: 200, text: '<form action="/j_security_check">' }),
    false,
    'login page served inline',
  );
  assert.equal(samadLooksAuthenticated({ url: 'https://samad.aut.ac.ir/loginpage.rose', status: 200, text: 'x' }), false);
  assert.equal(samadLooksAuthenticated({ url: 'https://samad.aut.ac.ir/', status: 503, text: '' }), false);
  assert.equal(samadLooksAuthenticated({ url: 'https://samad.aut.ac.ir/home.rose', status: 302, text: '' }), false, '3xx is never success');
});

test('samad redeem upgrades insecure redirect targets and needs the marker', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (u) => u.pathname === '/login/cas',
      respond: () => ({
        status: 302,
        headers: {
          location: 'http://samad.aut.ac.ir/',
          'set-cookie': ['JSESSIONID=J1; Path=/; HttpOnly', 'HASH_JSESSIONID=H1; Path=/; HttpOnly'],
        },
      }),
    },
    {
      match: (u) => u.pathname === '/',
      respond: () => ({ status: 302, headers: { location: 'http://samad.aut.ac.ir/index/index.rose' } }),
    },
    {
      match: (u) => u.pathname === '/index/index.rose',
      respond: () => ({ status: 200, body: '<a href="/logout.rose">خروج</a>' }),
    },
  ]);

  const state = await samadService.redeem({ ticket: 'ST-s', fetchImpl: fetch, logger: silent });
  assert.ok(state.cookies.JSESSIONID);
  assert.ok(state.cookies.HASH_JSESSIONID);
  // both redirect hops must have been upgraded to https
  assert.ok(calls.every((c) => c.url.startsWith('https://samad.aut.ac.ir')), JSON.stringify(calls.map((c) => c.url)));
  assert.equal(state.expiresAt, null);

  // registered service URL must stay the http one CAS knows
  assert.equal(samadService.serviceUrl, SAMAD_SERVICE_URL);
  assert.equal(SAMAD_SERVICE_URL, 'http://samad.aut.ac.ir/login/cas');
});

test('samad redeem fails when the landing page is the login form', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname === '/login/cas',
      respond: () => ({ status: 302, headers: { location: 'http://samad.aut.ac.ir/index/index.rose' } }),
    },
    {
      match: (u) => u.pathname === '/index/index.rose',
      respond: () => ({ status: 200, body: '<form action="/j_security_check">' }),
    },
  ]);
  await assert.rejects(
    () => samadService.redeem({ ticket: 'ST-s', fetchImpl: fetch, logger: silent }),
    (err) => err instanceof ServiceLoginError && err.service === 'samad',
  );
});

test('samad probe: dashboard true, login form false', async () => {
  const dash = mockFetch([
    {
      match: (u) => u.pathname === '/index/index.rose',
      respond: () => ({ status: 200, body: 'خروج' }),
    },
  ]);
  assert.equal(await samadService.probe({ state: { cookies: {} }, fetchImpl: dash.fetch, logger: silent }), true);

  const login = mockFetch([
    {
      match: (u) => u.pathname === '/index/index.rose',
      respond: () => ({ status: 200, body: 'name="_csrf" action="/j_security_check"' }),
    },
  ]);
  assert.equal(await samadService.probe({ state: { cookies: {} }, fetchImpl: login.fetch, logger: silent }), false);
});

test('adapter metadata matches the discovered routes', () => {
  assert.equal(coursesService.serviceUrl, COURSES_SERVICE_URL);
  assert.equal(coursesService.requiresCas, true);
  assert.equal(lmshomeService.requiresCas, true);
  assert.equal(samadService.requiresCas, true);
  assert.equal(foodService.requiresCas, true);
  assert.equal(foodService.serviceUrl, FOOD_SERVICE_URL);
  assert.equal(FOOD_SERVICE_URL, 'https://food.aut.ac.ir/Account/CasLogin');
});

/* ------------------------------------------------------------------ */
/* food / سامانه تغذیه                                                   */
/* ------------------------------------------------------------------ */

test('foodLooksAuthenticated only accepts 2xx responses on the food host', () => {
  assert.equal(foodLooksAuthenticated({ url: 'https://food.aut.ac.ir/UserHome/Index2?bypass=True', status: 200 }), true);
  assert.equal(
    foodLooksAuthenticated({ url: 'https://accounts.aut.ac.ir/cas/login?service=https%3A%2F%2Ffood.aut.ac.ir%2F', status: 200 }),
    false,
    'CAS bounce means the session is dead',
  );
  assert.equal(foodLooksAuthenticated({ url: 'https://food.aut.ac.ir/Home/index', status: 302 }), false);
});

test('food redeem walks CasLogin -> Home/index -> UserHome -> dashboard', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (u) => u.pathname === '/Account/CasLogin' && u.searchParams.has('ticket'),
      respond: () => ({
        status: 302,
        headers: {
          location: '/Home/index',
          'set-cookie': [
            'ASP.NET_SessionId=abc123; path=/; HttpOnly; SameSite=Lax; secure',
            'DGAUTH=D00D; path=/; HttpOnly; SameSite=Lax; secure',
            'fn=hs=tok&exp=10/8/2026 1:25:18 PM&IdTokenForOAuth2=; path=/; SameSite=None; secure',
            'ASP.NET_SessionId=; path=/; SameSite=None; secure',
            '.AspNet.ApplicationCookie=IDENT; path=/; secure; HttpOnly; SameSite=None; secure',
          ],
        },
      }),
    },
    { match: (u) => u.pathname === '/Home/index', respond: () => ({ status: 302, headers: { location: '/UserHome' } }) },
    {
      match: (u) => u.pathname === '/UserHome',
      respond: () => ({ status: 302, headers: { location: '/UserHome/Index2?bypass=True' } }),
    },
    {
      match: (u) => u.pathname === '/UserHome/Index2',
      respond: () => ({ status: 200, body: '<title>صفحه اصلی - سامانه تغذیه</title>' }),
    },
  ]);

  const state = await foodService.redeem({ ticket: 'ST-food', fetchImpl: fetch, logger: silent });
  assert.equal(state.expiresAt, null, 'server-authoritative lifetime');
  assert.equal(state.cookies['.AspNet.ApplicationCookie'].value, 'IDENT');
  assert.equal(state.cookies.DGAUTH.value, 'D00D');
  assert.match(state.cookies.fn.value, /^hs=tok&exp=/, 'fn value keeps its =/& payload');
  assert.equal(
    state.cookies['ASP.NET_SessionId']?.value ?? null,
    '',
    'the later clear wins: session id ends up empty (session cookie unused)',
  );
  assert.equal(state.meta.finalUrl, 'https://food.aut.ac.ir/UserHome/Index2?bypass=True');
  assert.ok(calls[0].url.includes('ticket=ST-food'));
});

test('food redeem rejects the 200 error page a replayed ticket produces', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname === '/Account/CasLogin',
      respond: () => ({ status: 200, body: '<title>سامانه تغذیه-خطا</title>' }),
    },
  ]);
  await assert.rejects(
    () => foodService.redeem({ ticket: 'ST-used', fetchImpl: fetch, logger: silent }),
    (err) =>
      err instanceof ServiceLoginError &&
      err.service === 'food' &&
      err.hasIdentity === false &&
      /did not establish a session/.test(err.message),
    'a 200 error page without .AspNet.ApplicationCookie must not count as success',
  );
});

test('food redeem rejects a bounce into CAS', async () => {
  const { fetch } = mockFetch([
    {
      match: (u) => u.pathname === '/Account/CasLogin',
      respond: () => ({ status: 302, headers: { location: 'https://accounts.aut.ac.ir/cas/login?service=x' } }),
    },
    { match: (u) => u.hostname === 'accounts.aut.ac.ir', respond: () => ({ status: 200, body: '<form id="fm1">' }) },
  ]);
  await assert.rejects(
    () => foodService.redeem({ ticket: 'ST-bad', fetchImpl: fetch, logger: silent }),
    (err) => err instanceof ServiceLoginError && err.service === 'food',
  );
});

test('food probe: dashboard true, CAS bounce false', async () => {
  const live = mockFetch([
    {
      match: (u) => u.pathname === '/Home/index',
      respond: () => ({ status: 302, headers: { location: '/UserHome' } }),
    },
    { match: (u) => u.pathname === '/UserHome', respond: () => ({ status: 302, headers: { location: '/UserHome/Index2?bypass=True' } }) },
    { match: (u) => u.pathname === '/UserHome/Index2', respond: () => ({ status: 200, body: 'dashboard' }) },
  ]);
  assert.equal(await foodService.probe({ state: { cookies: {} }, fetchImpl: live.fetch, logger: silent }), true);

  const dead = mockFetch([
    {
      match: (u) => u.pathname === '/Home/index',
      respond: () => ({ status: 302, headers: { location: '/Account/Login?ReturnUrl=%2f' } }),
    },
    { match: (u) => u.pathname === '/Account/Login', respond: () => ({ status: 302, headers: { location: 'https://accounts.aut.ac.ir/cas/login?service=x' } }) },
    { match: (u) => u.hostname === 'accounts.aut.ac.ir', respond: () => ({ status: 200, body: 'cas login' }) },
  ]);
  assert.equal(await foodService.probe({ state: { cookies: {} }, fetchImpl: dead.fetch, logger: silent }), false);
});
