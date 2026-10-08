/**
 * lmshome.aut.ac.ir — "Fararoom", a Next.js app with its own auth API that
 * delegates to CAS.
 *
 * Redeem: GET `/api/v1/auth/sso/callback/?ticket=ST-...`
 *   -> `200 {data: {user, ...}}` + `sessionid` (Max-Age=43200 => 12h) and
 *      `csrftoken` cookies. Unlike the other services, Fararoom discloses the
 *      session lifetime, so expiry can be tracked exactly.
 *
 * Probe: GET `/api/v1/auth/me/` -> 200 JSON means alive, 401 means dead.
 */

import { CookieJar, request } from '../http.js';
import { ServiceLoginError } from '../errors.js';
import { plainCookies } from './courses.js';

export const LMSHOME_ORIGIN = 'https://lmshome.aut.ac.ir';
/** Exact service URL registered with CAS for Fararoom. */
export const LMSHOME_SERVICE_URL = `${LMSHOME_ORIGIN}/api/v1/auth/sso/callback/`;
const ME_URL = `${LMSHOME_ORIGIN}/api/v1/auth/me/`;

/** @type {import('./types.js').ServiceAdapter} */
export const lmshomeService = {
  id: 'lmshome',
  title: 'Fararoom — lmshome.aut.ac.ir',
  requiresCas: true,
  serviceUrl: LMSHOME_SERVICE_URL,

  /**
   * @param {object} ctx
   * @param {string} ctx.ticket
   * @param {typeof fetch} ctx.fetchImpl
   * @param {object} ctx.logger
   */
  async redeem({ ticket, fetchImpl, logger }) {
    const jar = new CookieJar();
    const res = await request(
      `${LMSHOME_SERVICE_URL}?ticket=${encodeURIComponent(ticket)}`,
      { jar, fetchImpl, timeoutMs: 30_000 },
    );

    if (!res.ok) {
      let detail = '';
      try {
        detail = res.json()?.error?.code || res.json()?.error?.message || '';
      } catch {
        /* not JSON */
      }
      logger.warn('lmshome: callback rejected ticket', { status: res.status, detail });
      throw new ServiceLoginError(`Fararoom rejected the CAS ticket (HTTP ${res.status})`, {
        service: 'lmshome',
        status: res.status,
        detail,
      });
    }

    if (!jar.getCookie('sessionid', LMSHOME_ORIGIN)) {
      logger.warn('lmshome: callback returned no sessionid cookie', { finalUrl: res.url });
      throw new ServiceLoginError('Fararoom did not issue a session cookie', { service: 'lmshome' });
    }

    let username = null;
    try {
      username = res.json()?.data?.user?.username ?? null;
    } catch {
      /* ignore */
    }

    const expiresAt = jar.earliestExpiry(); // sessionid Max-Age wins over csrftoken
    logger.info('lmshome: session established', { username, expiresAt });
    return {
      cookies: jar.toJSON(),
      expiresAt,
      lastValidatedAt: Date.now(),
      meta: { username },
    };
  },

  async probe({ state, fetchImpl, logger }) {
    const jar = CookieJar.fromJSON(state?.cookies);
    const res = await request(ME_URL, { jar, fetchImpl, timeoutMs: 20_000 });
    const ok = res.ok && Boolean(res.json?.().data?.username);
    logger.debug('lmshome: probe', { ok, status: res.status });
    return ok;
  },

  toCredential(state) {
    return {
      type: 'cookie',
      cookies: plainCookies(state.cookies),
      token: null,
      header: null,
      expiresAt: state.expiresAt ?? null,
      obtainedAt: state.lastValidatedAt ?? Date.now(),
    };
  },
};
