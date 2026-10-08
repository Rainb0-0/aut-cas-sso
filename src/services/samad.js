/**
 * samad.aut.ac.ir — "SAMAD" student-affairs portal (Java/Spring, Dadekavan).
 *
 * The login page offers "ورود با احراز هویت مرکزی" which redirects to
 * `https://accounts.aut.ac.ir/cas/login?service=http://samad.aut.ac.ir/login/cas`
 * — note the service is registered over plain **http** while the site is
 * served over https, and the app itself emits `http://` Location headers
 * behind an https load balancer. Blind redirect following loops forever, so
 * every request here uses `upgradeInsecure`.
 *
 * Redeem: GET `https://samad.aut.ac.ir/login/cas?ticket=ST-...` sets
 * `JSESSIONID` + `HASH_JSESSIONID`, then bounces through `/` -> `index.rose`
 * -> `home.rose` -> `index/index.rose`.
 *
 * Anonymous vs authenticated is decided by the login-page marker
 * `j_security_check`: the authenticated dashboard is ~50KB and has no such
 * form; the anonymous response is the ~21KB login page.
 */

import { CookieJar, request } from '../http.js';
import { ServiceLoginError } from '../errors.js';
import { plainCookies } from './courses.js';

export const SAMAD_ORIGIN = 'https://samad.aut.ac.ir';
/** Exact (http) service URL registered with CAS for samad. */
export const SAMAD_SERVICE_URL = 'http://samad.aut.ac.ir/login/cas';
const DASHBOARD_URL = `${SAMAD_ORIGIN}/index/index.rose`;
const LOGIN_MARKER = 'j_security_check';

/** @type {import('./types.js').ServiceAdapter} */
export const samadService = {
  id: 'samad',
  title: 'SAMAD — samad.aut.ac.ir',
  requiresCas: true,
  serviceUrl: SAMAD_SERVICE_URL,

  /**
   * @param {object} ctx
   * @param {string} ctx.ticket
   * @param {typeof fetch} ctx.fetchImpl
   * @param {object} ctx.logger
   */
  async redeem({ ticket, fetchImpl, logger }) {
    const jar = new CookieJar();
    // Redeem over https even though CAS issued the ticket for the http
    // service URL: samad validates the ticket server-side against its own
    // configured service URL, so the transport scheme does not matter.
    const res = await request(`${SAMAD_ORIGIN}/login/cas?ticket=${encodeURIComponent(ticket)}`, {
      jar,
      fetchImpl,
      timeoutMs: 45_000,
      maxRedirects: 12,
      upgradeInsecure: true,
    });

    if (!samadLooksAuthenticated(res)) {
      logger.warn('samad: ticket redemption did not yield a session', {
        status: res.status,
        finalUrl: res.url,
      });
      throw new ServiceLoginError('SAMAD did not establish a session from the CAS ticket', {
        service: 'samad',
        status: res.status,
        finalUrl: res.url,
      });
    }

    logger.info('samad: session established', { url: res.url });
    return {
      cookies: jar.toJSON(),
      // JSESSIONID lifetime is server-side only: probe-based validity.
      expiresAt: null,
      lastValidatedAt: Date.now(),
      meta: { finalUrl: res.url },
    };
  },

  async probe({ state, fetchImpl, logger }) {
    const jar = CookieJar.fromJSON(state?.cookies);
    const res = await request(DASHBOARD_URL, {
      jar,
      fetchImpl,
      timeoutMs: 30_000,
      maxRedirects: 8,
      upgradeInsecure: true,
    });
    const ok = samadLooksAuthenticated(res);
    logger.debug('samad: probe', { ok, finalUrl: res.url });
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

/**
 * @param {{url: string, status: number, text: string}} res
 * @returns {boolean}
 */
export function samadLooksAuthenticated(res) {
  if (res.status < 200 || res.status >= 400) return false;
  if (res.url.includes('loginpage.rose')) return false;
  // Anonymous responses embed the container login form; the dashboard does not.
  if (res.text && res.text.includes(LOGIN_MARKER)) return false;
  return true;
}
