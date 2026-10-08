/**
 * Live end-to-end smoke test against the real AUT services.
 *
 * Opt-in: needs credentials in the environment and hits the network.
 *
 *   AUT_CAS_USER=... AUT_CAS_PASS=... npm run smoke
 *
 * What it proves: CAS login -> service ticket -> session for each of
 * courses/lmshome/samad/lms/food, an authenticated request with every
 * returned credential, probing, and persistence across a manager restart.
 * Secrets are never printed (only prefixes/lengths).
 */

import { SessionManager, createLogger, request, FileStore, AutCasError } from 'aut-cas-sso';

const USER = process.env.AUT_CAS_USER;
const PASS = process.env.AUT_CAS_PASS;
if (!USER || !PASS) {
  console.error('Set AUT_CAS_USER and AUT_CAS_PASS first, e.g.');
  console.error('  AUT_CAS_USER=mylogin AUT_CAS_PASS=mypassword npm run smoke');
  process.exit(2);
}

const STORE_PATH = process.env.AUT_CAS_SMOKE_STORE || './.aut-cas-sessions.json';
const logger = createLogger({ level: process.env.AUT_CAS_SMOKE_DEBUG ? 'debug' : 'info' });
let failures = 0;
const ok = (label, pass, detail = '') => {
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${label}${detail ? ` — ${detail}` : ''}`);
};

function summarizeCred(cred) {
  if (cred.type === 'token') return `token(${cred.token.length} chars)`;
  return `cookies(${Object.keys(cred.cookies).join(', ')})`;
}

async function main() {
  const manager = new SessionManager({
    accounts: [{ id: 'smoke', username: USER, password: PASS }],
    store: new FileStore(STORE_PATH),
    logger,
    encryptionKey: process.env.AUT_CAS_SESSION_KEY,
  });

  const startedFresh = !((await manager.store.load())?.sessions?.['courses::smoke']);
  console.log(`store: ${STORE_PATH} (${startedFresh ? 'cold start' : 'existing sessions'})\n`);

  /* 1. credentials for all four services */
  const creds = {};
  for (const service of ['courses', 'lmshome', 'samad', 'lms', 'food']) {
    try {
      creds[service] = await manager.getCredential(service, 'smoke');
      ok(`${service}: getCredential`, true, summarizeCred(creds[service]));
    } catch (err) {
      ok(`${service}: getCredential`, false, `${err.code || err.name}: ${err.message}`);
      if (err instanceof AutCasError && err.code === 'INVALID_CREDENTIALS') throw err;
    }
  }

  /* 2. use each credential against the real service */
  try {
    const jarHeader = Object.entries(creds.courses.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    const res = await request('https://courses.aut.ac.ir/my/', {
      headers: { cookie: jarHeader },
      maxRedirects: 6,
    });
    const title = /<title>([^<]+)<\/title>/.exec(res.text)?.[1] ?? '';
    ok('courses: authenticated GET /my/', res.ok && !res.url.includes('/login/'), `title="${title}"`);
  } catch (err) {
    ok('courses: authenticated GET /my/', false, err.message);
  }

  try {
    const cookie = Object.entries(creds.lmshome.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    const res = await request('https://lmshome.aut.ac.ir/api/v1/auth/me/', { headers: { cookie } });
    const username = res.json().data?.username;
    ok('lmshome: authenticated GET /auth/me/', res.ok, `username=${username}`);
  } catch (err) {
    ok('lmshome: authenticated GET /auth/me/', false, err.message);
  }

  try {
    const cookie = Object.entries(creds.samad.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    const res = await request('https://samad.aut.ac.ir/index/index.rose', {
      headers: { cookie },
      upgradeInsecure: true,
    });
    const loggedIn = !res.text.includes('j_security_check');
    ok('samad: authenticated GET dashboard', loggedIn, `${res.text.length} bytes`);
  } catch (err) {
    ok('samad: authenticated GET dashboard', false, err.message);
  }

  try {
    const cookie = Object.entries(creds.food.cookies)
      .map(([k, v]) => `${k}=${v}`)
      .join('; ');
    const res = await request('https://food.aut.ac.ir/Home/index', {
      headers: { cookie },
      maxRedirects: 8,
    });
    const landedOnApp = res.ok && new URL(res.url).hostname === 'food.aut.ac.ir';
    const title = /<title>([^<]+)<\/title>/.exec(res.text)?.[1] ?? '';
    ok('food: authenticated GET /Home/index', landedOnApp, `final=${res.url} title="${title}"`);
  } catch (err) {
    ok('food: authenticated GET /Home/index', false, err.message);
  }

  try {
    const probe = await manager.probe('lms', 'smoke');
    ok('lms: DDP resume-token probe', probe);
  } catch (err) {
    ok('lms: DDP resume-token probe', false, err.message);
  }

  /* 3. probes for the cookie services */
  for (const service of ['courses', 'lmshome', 'samad', 'food']) {
    try {
      ok(`${service}: probe`, await manager.probe(service, 'smoke'));
    } catch (err) {
      ok(`${service}: probe`, false, err.message);
    }
  }

  /* 4. fast path + persistence across restart */
  const t0 = Date.now();
  await manager.getCredential('courses', 'smoke');
  console.log(`\nfast path (cached session): ${Date.now() - t0}ms`);

  await manager.stop();

  const restarted = new SessionManager({
    store: new FileStore(STORE_PATH),
    logger,
    encryptionKey: process.env.AUT_CAS_SESSION_KEY,
  });
  const t1 = Date.now();
  try {
    const restored = await restarted.getCredential('courses', 'smoke');
    ok('restart: session restored from disk', restored.type === 'cookie', `${Date.now() - t1}ms`);
  } catch (err) {
    ok('restart: session restored from disk', false, err.message);
  }
  await restarted.stop();

  if (failures > 0) {
    console.error(`\n${failures} check(s) FAILED`);
    process.exitCode = 1;
  } else {
    console.log('\nall checks passed');
  }
}

main().catch((err) => {
  console.error('\nSMOKE FAILED:', err);
  process.exit(1);
});
