/**
 * food.aut.ac.ir — AUT food/restaurant system ("سامانه تغذیه"), an ASP.NET
 * MVC app.
 *
 * Every path passes an authorization filter that 302s to
 * `/Account/Login?ReturnUrl=…`, which in turn redirects to CAS with the
 * service URL `https://food.aut.ac.ir/Account/CasLogin`.
 *
 * Redeem: GET `/Account/CasLogin?ticket=ST-...`
 *   -> 302 `/Home/index` -> 302 `/UserHome` -> 302
 *      `/UserHome/Index2?bypass=True` (dashboard), setting the identity
 *      cookie `.AspNet.ApplicationCookie` plus `DGAUTH`, `fn` and an
 *      `ASP.NET_SessionId` that the same response immediately clears.
 *
 * A rejected/replayed ticket does NOT bounce to CAS: the app renders its
 * own 200 error page ("سامانه تغذیه-خطا") at the CasLogin URL without
 * issuing `.AspNet.ApplicationCookie`. Success therefore requires (a)
 * actually leaving CasLogin into the app, (b) landing on the food host and
 * (c) the identity cookie being present.
 *
 * Probe: GET `/Home/index` — authenticated sessions end back on
 * `food.aut.ac.ir` (dashboard), dead ones walk the login filter into CAS
 * and end on `accounts.aut.ac.ir`.
 *
 * All auth cookies are server-side/session cookies with no disclosed
 * lifetime, so validity is probe-based (`expiresAt: null`).
 */

import { CookieJar, request } from '../http.js';
import { ServiceLoginError } from '../errors.js';
import { plainCookies } from './courses.js';

export const FOOD_ORIGIN = 'https://food.aut.ac.ir';
/** Exact service URL registered with CAS for the food system. */
export const FOOD_SERVICE_URL = `${FOOD_ORIGIN}/Account/CasLogin`;
const HOME_URL = `${FOOD_ORIGIN}/Home/index`;
const IDENTITY_COOKIE = '.AspNet.ApplicationCookie';

/**
 * Generic liveness classifier used by the probe: did we end up back on the
 * food host (2xx), or were we bounced into CAS?
 * @param {{url: string, status: number}} res
 * @returns {boolean}
 */
export function foodLooksAuthenticated(res) {
  if (res.status < 200 || res.status >= 300) return false;
  try {
    return new URL(res.url).hostname === 'food.aut.ac.ir';
  } catch {
    return false;
  }
}

/** @type {import('./types.js').ServiceAdapter} */
export const foodService = {
  id: 'food',
  title: 'Food system — food.aut.ac.ir',
  requiresCas: true,
  serviceUrl: FOOD_SERVICE_URL,

  /**
   * @param {object} ctx
   * @param {string} ctx.ticket
   * @param {typeof fetch} ctx.fetchImpl
   * @param {object} ctx.logger
   */
  async redeem({ ticket, fetchImpl, logger }) {
    const jar = new CookieJar();
    const res = await request(`${FOOD_SERVICE_URL}?ticket=${encodeURIComponent(ticket)}`, {
      jar,
      fetchImpl,
      timeoutMs: 45_000,
      maxRedirects: 10,
    });

    const stuckOnCasLogin = res.url.startsWith(`${FOOD_SERVICE_URL}?`);
    const hasIdentity = Boolean(jar.getCookie(IDENTITY_COOKIE, FOOD_ORIGIN));
    const ok = res.ok && !stuckOnCasLogin && foodLooksAuthenticated(res) && hasIdentity;

    if (!ok) {
      logger.warn('food: ticket redemption did not yield a session', {
        status: res.status,
        finalUrl: res.url,
        hasIdentity,
        stuckOnCasLogin,
      });
      throw new ServiceLoginError('Food system did not establish a session from the CAS ticket', {
        service: 'food',
        status: res.status,
        finalUrl: res.url,
        hasIdentity,
      });
    }

    logger.info('food: session established', { url: res.url });
    return {
      cookies: jar.toJSON(),
      // Session/identity cookies carry no disclosed lifetime: probe-based.
      expiresAt: null,
      lastValidatedAt: Date.now(),
      meta: { finalUrl: res.url },
    };
  },

  async probe({ state, fetchImpl, logger }) {
    const jar = CookieJar.fromJSON(state?.cookies);
    const res = await request(HOME_URL, {
      jar,
      fetchImpl,
      timeoutMs: 30_000,
      maxRedirects: 8,
    });
    const ok = foodLooksAuthenticated(res);
    logger.debug('food: probe', { ok, finalUrl: res.url });
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
