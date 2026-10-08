import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';

import { CookieJar, request, get, postForm } from '../src/http.js';
import { mockFetch } from './helpers/mock.js';

test('CookieJar parses attributes, honours expiry and secure', () => {
  const jar = new CookieJar();
  const base = 'https://courses.aut.ac.ir/my/page';

  jar.setFromResponse(base, 'a=1; Path=/; HttpOnly');
  jar.setFromResponse(base, 'b=2; path=/dir; secure');
  jar.setFromResponse(base, 'gone=0; Max-Age=0; path=/');
  jar.setFromResponse(base, 'short=3; Max-Age=1; path=/');

  assert.equal(jar.getCookie('a', base), '1');
  assert.equal(jar.getCookie('b', 'https://courses.aut.ac.ir/dir/page'), '2');
  assert.equal(jar.getCookie('b', base), null, 'path=/dir cookie not sent to /my/page');
  assert.equal(jar.getCookie('gone', base), null, 'Max-Age=0 deletes');

  // `a` is a plain host cookie -> sent over http; `b` is Secure -> only https
  assert.match(jar.get('http://courses.aut.ac.ir/dir/x'), /\ba=1\b/);
  assert.doesNotMatch(jar.get('http://courses.aut.ac.ir/dir/x'), /\bb=2\b/);
  assert.match(jar.get('https://courses.aut.ac.ir/dir/x'), /\bb=2\b/);
});

test('CookieJar secure cookies only go over https', () => {
  const jar = new CookieJar();
  jar.setFromResponse('https://x.test/', 's=1; Secure; Path=/');
  assert.equal(jar.get('https://x.test/'), 's=1');
  assert.equal(jar.get('http://x.test/'), '');
});

test('CookieJar serializes and restores', () => {
  const jar = new CookieJar();
  jar.setFromResponse('https://x.test/a/b', 'keep=9; Path=/; Expires=' + new Date(Date.now() + 60_000).toUTCString());
  const json = jar.toJSON();
  const restored = CookieJar.fromJSON(json);
  assert.equal(restored.getCookie('keep', 'https://x.test/'), '9');
  assert.equal(restored.getCookie('keep', 'https://other.test/'), null, 'host-only cookie');
  assert.equal(CookieJar.fromJSON(null).get('https://x.test/'), '', 'null restores to empty jar');
});

test('CookieJar prunes expired cookies from serialization', async () => {
  const jar = new CookieJar();
  jar.setFromResponse('https://x.test/', 'dying=1; Max-Age=1; path=/');
  await new Promise((r) => setTimeout(r, 1100));
  assert.deepEqual(jar.toJSON(), {});
  assert.ok(jar.isEmpty);
});

test('request follows redirects, collects cookies on intermediate hops', async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === '/start') {
      res.writeHead(302, { location: '/mid', 'set-cookie': 'first=1; Path=/' });
      res.end();
    } else if (req.url === '/mid') {
      res.writeHead(302, { location: '/end', 'set-cookie': 'second=2; Path=/' });
      res.end();
    } else {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, cookie: req.headers.cookie || null }));
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => server.close());

  const jar = new CookieJar();
  const res = await get(`${base}/start`, null, { jar });
  assert.equal(res.status, 200);
  assert.equal(res.redirects.length, 2);
  assert.deepEqual(res.json(), { ok: true, cookie: 'first=1; second=2' });
  assert.equal(jar.getCookie('first', base), '1');
  assert.equal(jar.getCookie('second', base), '2');
});

test('request guards against redirect loops', async (t) => {
  const server = http.createServer((req, res) => {
    res.writeHead(302, { location: '/loop' });
    res.end();
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => server.close());

  await assert.rejects(() => get(`${base}/loop`, null, { maxRedirects: 5 }), /Too many redirects/);
});

test('request upgrades insecure same-host redirect targets when asked', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (url) => url.toString() === 'https://app.test/login/cas',
      respond: () => ({ status: 302, headers: { location: 'http://app.test/' } }),
    },
    {
      match: (url) => url.toString() === 'https://app.test/',
      respond: () => ({ status: 200, body: 'home' }),
    },
  ]);

  const res = await request('https://app.test/login/cas', { fetchImpl: fetch, upgradeInsecure: true });
  assert.equal(res.status, 200);
  assert.equal(res.text, 'home');
  assert.deepEqual(calls.map((c) => c.url), ['https://app.test/login/cas', 'https://app.test/']);
});

test('without upgradeInsecure the http redirect target is followed as-is', async () => {
  const { fetch, calls } = mockFetch([
    {
      match: (url) => url.protocol === 'https:',
      respond: () => ({ status: 302, headers: { location: 'http://app.test/' } }),
    },
    { match: (url) => url.protocol === 'http:', respond: () => ({ status: 200, body: 'ok' }) },
  ]);
  const res = await request('https://app.test/x', { fetchImpl: fetch });
  assert.equal(res.status, 200);
  assert.equal(calls[1].url, 'http://app.test/');
});

test('postForm sends urlencoded body and follows POST->GET on 302', async (t) => {
  let seen = null;
  const server = http.createServer((req, res) => {
    if (req.url === '/submit') {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seen = { method: req.method, body };
        res.writeHead(303, { location: '/done' });
        res.end();
      });
    } else {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('arrived');
    }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => server.close());

  const res = await postForm(`${base}/submit`, { a: '1', b: 'x y' });
  assert.equal(res.text, 'arrived');
  assert.deepEqual(seen, { method: 'POST', body: 'a=1&b=x+y' });
  assert.equal(res.redirects.length, 1);
});

test('request surfaces non-2xx statuses without throwing', async (t) => {
  const server = http.createServer((req, res) => {
    res.writeHead(418, { 'content-type': 'text/plain' });
    res.end('teapot');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(() => server.close());

  const res = await request(`${base}/`);
  assert.equal(res.status, 418);
  assert.equal(res.ok, false);
  assert.equal(res.text, 'teapot');
});
