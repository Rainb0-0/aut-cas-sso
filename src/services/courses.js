/**
 * courses.aut.ac.ir — Moodle with CAS SSO (auth_casattras plugin).
 *
 * Redeem: GET `login/index.php?authCASattras=CASattras&ticket=ST-...`
 * Moodle validates the ticket with CAS and lands on `/my/`, setting
 * `MoodleSession` (server-side session) and `MOODLEID1_` (60-day remember-me
 * token, sodium-encoded).
 *
 * Session lifetime is server-authoritative (no expiry is disclosed), so
 * validity is determined by probing `/my/`.
 */

import { CookieJar, request } from '../http.js';
import { ServiceLoginError } from '../errors.js';

export const COURSES_ORIGIN = 'https://courses.aut.ac.ir';
/** Exact service URL registered with CAS for Moodle. */
export const COURSES_SERVICE_URL = `${COURSES_ORIGIN}/login/index.php?authCASattras=CASattras`;

/**
 * Decide whether a final response represents a logged-in Moodle session.
 * @param {{url: string, status: number}} res
 * @returns {boolean}
 */
export function moodleLooksAuthenticated(res) {
  if (res.status < 200 || res.status >= 300) return false;
  let u;
  try {
    u = new URL(res.url);
  } catch {
    return false;
  }
  if (u.hostname !== 'courses.aut.ac.ir') return false; // bounced to CAS login
  // `/login/index.php?testsession=<id>` only appears once authenticated.
  if (u.searchParams.has('testsession')) return true;
  if (u.pathname.startsWith('/login/')) return false; // sitting on the login page
  return true;
}

/** @type {import('./types.js').ServiceAdapter} */
export const coursesService = {
  id: 'courses',
  title: 'Moodle — courses.aut.ac.ir',
  requiresCas: true,
  serviceUrl: COURSES_SERVICE_URL,

  /**
   * @param {object} ctx
   * @param {string} ctx.ticket single-use CAS service ticket
   * @param {CookieJar} [ctx.jar] cookies from the previous session (remember-me)
   * @param {typeof fetch} ctx.fetchImpl
   * @param {object} ctx.logger
   * @returns {Promise<{cookies: object, expiresAt: number|null, lastValidatedAt: number, meta: object}>}
   */
  async redeem({ ticket, jar, fetchImpl, logger }) {
    const cookies = jar || new CookieJar();

    // Fast path: the 60-day MOODLEID1_ remember token can restore the
    // session without spending the (single-use) CAS ticket.
    if (cookies.getCookie('MOODLEID1_', COURSES_ORIGIN)) {
      const replay = await request(`${COURSES_ORIGIN}/my/`, {
        jar: cookies,
        fetchImpl,
        timeoutMs: 30_000,
      });
      if (moodleLooksAuthenticated(replay)) {
        logger.debug('courses: session restored via remember-me cookie', { url: replay.url });
        return stateFrom(cookies, replay);
      }
      logger.debug('courses: remember-me replay failed, falling back to CAS ticket');
    }

    const res = await request(`${COURSES_SERVICE_URL}&ticket=${encodeURIComponent(ticket)}`, {
      jar: cookies,
      fetchImpl,
      timeoutMs: 45_000,
      maxRedirects: 12,
    });

    if (!moodleLooksAuthenticated(res)) {
      logger.warn('courses: ticket redemption did not yield a session', {
        status: res.status,
        finalUrl: res.url,
      });
      throw new ServiceLoginError('Moodle did not establish a session from the CAS ticket', {
        service: 'courses',
        status: res.status,
        finalUrl: res.url,
      });
    }

    logger.info('courses: Moodle session established', { url: res.url });
    return stateFrom(cookies, res);
  },

  /**
   * @param {object} ctx
   * @param {{cookies: object}} ctx.state
   * @param {typeof fetch} ctx.fetchImpl
   * @returns {Promise<boolean>}
   */
  async probe({ state, fetchImpl, logger }) {
    const cookies = CookieJar.fromJSON(state?.cookies);
    const res = await request(`${COURSES_ORIGIN}/my/`, {
      jar: cookies,
      fetchImpl,
      timeoutMs: 30_000,
      maxRedirects: 12,
    });
    const ok = moodleLooksAuthenticated(res);
    logger.debug('courses: probe', { ok, finalUrl: res.url });
    return ok;
  },

  /** @param {{cookies: object, expiresAt: number|null, lastValidatedAt: number}} state */
  toCredential(state) {
    const cookies = plainCookies(state.cookies);
    return {
      type: 'cookie',
      cookies,
      token: null,
      header: null,
      expiresAt: state.expiresAt ?? null,
      obtainedAt: state.lastValidatedAt ?? Date.now(),
    };
  },
};

function stateFrom(jar, res) {
  return {
    cookies: jar.toJSON(),
    // Moodle never discloses session expiry: server-authoritative, probe-based.
    expiresAt: null,
    lastValidatedAt: Date.now(),
    meta: { finalUrl: res.url },
  };
}

/** `{name: {value,...}}` -> `{name: value}` for consumers. */
export function plainCookies(cookieJson) {
  const out = {};
  for (const [name, entry] of Object.entries(cookieJson || {})) {
    out[name] = entry && typeof entry === 'object' ? entry.value : String(entry);
  }
  return out;
}
