/**
 * lms.aut.ac.ir — the "Nima" Meteor/Angular app.
 *
 * It has no direct CAS integration; the live deployment reports
 * `settings.auth === "moodle"` and logs in through a custom OAuth provider
 * ("u5auth") that Moodle itself hosts:
 *
 *   issuer:   https://courses.aut.ac.ir/local/oauth   (client_id "nima")
 *   redirect: https://lms.aut.ac.ir/api/_oauth/u5auth
 *
 * So the full headless login is:
 *
 * 1. hold a Moodle session (the courses adapter provides one — CAS SSO),
 * 2. GET `local/oauth/login.php?client_id=nima&...` with the Moodle cookies
 *      -> 302 with a single-use authorization `code` (no re-auth needed),
 * 3. GET `https://lms.aut.ac.ir/api/_oauth/u5auth?code=...&state=...`
 *      -> HTML page whose `#config` div carries `credentialSecret`
 *      (the Meteor server exchanges the code server-side; the secret is the
 *       client half of the credential),
 * 4. DDP `login` with `{oauth: {credentialToken: state, credentialSecret}}`
 *      -> `{id, token, tokenExpires}` — a resume token that doubles as the
 *      session bearer and has a server-disclosed expiry.
 *
 * Steps 3/4 need a WebSocket (DDP); where none exists the adapter throws
 * UnsupportedEnvironmentError while every other service keeps working.
 */

import { CookieJar, request } from '../http.js';
import { ServiceLoginError, UnsupportedEnvironmentError } from '../errors.js';
import { DdpClient } from '../ddp.js';

export const LMS_ORIGIN = 'https://lms.aut.ac.ir';
export const LMS_U5AUTH = Object.freeze({
  clientId: 'nima',
  issuer: 'https://courses.aut.ac.ir/local/oauth',
  redirectUri: `${LMS_ORIGIN}/api/_oauth/u5auth`,
  scope: 'user_info',
});
export const LMS_DDP_URL = 'wss://lms.aut.ac.ir/api/websocket';

/** Safety margin: refresh the resume token this long before its expiry. */
const EXPIRY_SAFETY_MS = 5 * 60 * 1000;

/** @type {import('./types.js').ServiceAdapter} */
export const lmsService = {
  id: 'lms',
  title: 'Nima LMS — lms.aut.ac.ir',
  // No direct CAS ticket: rides on the Moodle session (via ensureSession).
  requiresCas: false,
  serviceUrl: null,

  /**
   * @param {object} ctx
   * @param {(serviceId: string) => Promise<import('./types.js').SessionState>} ctx.ensureSession
   * @param {typeof fetch} ctx.fetchImpl
   * @param {object} ctx.logger
   * @param {typeof WebSocket} [ctx.WebSocketImpl]
   */
  async redeem({ ensureSession, fetchImpl, logger, WebSocketImpl }) {
    if (!DdpClient.isSupported(WebSocketImpl)) {
      throw new UnsupportedEnvironmentError(
        'The lms service needs a WebSocket implementation for its Meteor DDP login; none is available in this environment',
      );
    }

    // 1. A live Moodle session is the identity provider for u5auth.
    const moodleState = await ensureSession('courses');
    const jar = CookieJar.fromJSON(moodleState.cookies);

    // 2. Ask Moodle's OAuth server for an authorization code.
    const state = randomState();
    const authorizeUrl = new URL(`${LMS_U5AUTH.issuer}/login.php`);
    authorizeUrl.searchParams.set('client_id', LMS_U5AUTH.clientId);
    authorizeUrl.searchParams.set('scope', LMS_U5AUTH.scope);
    authorizeUrl.searchParams.set('response_type', 'code');
    authorizeUrl.searchParams.set('redirect_uri', LMS_U5AUTH.redirectUri);
    authorizeUrl.searchParams.set('state', state);

    const authRes = await request(authorizeUrl.toString(), {
      jar,
      fetchImpl,
      timeoutMs: 30_000,
      redirect: 'manual',
    });

    if (authRes.status < 300 || authRes.status >= 400 || !authRes.headers.location) {
      logger.warn('lms: OAuth authorize did not redirect', { status: authRes.status, body: authRes.text.slice(0, 200) });
      throw new ServiceLoginError(
        `Moodle OAuth did not issue an authorization code (HTTP ${authRes.status})`,
        { service: 'lms', status: authRes.status, detail: authRes.text.slice(0, 300) },
      );
    }
    const codeUrl = new URL(authRes.headers.location, LMS_ORIGIN);

    // 3. Meteor completes the OAuth dance server-side and hands us the
    //    credential secret in a hidden #config div.
    const done = await request(codeUrl.toString(), { fetchImpl, timeoutMs: 30_000, redirect: 'manual' });
    const secret = /"credentialSecret"\s*:\s*"([^"]+)"/.exec(done.text)?.[1];
    if (!done.ok || !secret) {
      logger.warn('lms: OAuth completion did not yield a credential secret', { status: done.status });
      throw new ServiceLoginError('lms OAuth completion failed (no credentialSecret)', {
        service: 'lms',
        status: done.status,
      });
    }

    // 4. Exchange the credential for a Meteor resume token over DDP.
    const login = await DdpClient.withClient({ url: LMS_DDP_URL, WebSocketImpl, logger }, (client) =>
      client.call('login', [{ oauth: { credentialToken: state, credentialSecret: secret } }]),
    );

    const expiresAt = toEpochMs(login?.tokenExpires);
    logger.info('lms: Meteor login established', {
      userId: login?.id,
      type: login?.type,
      expiresAt,
    });

    return {
      cookies: null,
      token: login.token,
      expiresAt,
      lastValidatedAt: Date.now(),
      meta: { userId: login.id, loginType: login.type },
    };
  },

  async probe({ state, logger, WebSocketImpl }) {
    if (!state?.token) return false;
    if (!DdpClient.isSupported(WebSocketImpl)) {
      throw new UnsupportedEnvironmentError('lms probe requires a WebSocket implementation');
    }
    try {
      const result = await DdpClient.withClient({ url: LMS_DDP_URL, WebSocketImpl, logger }, (client) =>
        client.call('login', [{ resume: state.token }]),
      );
      const ok = Boolean(result?.id && result?.token);
      logger.debug('lms: probe', { ok });
      return ok;
    } catch (err) {
      if (err?.code === 'DDP_METHOD_FAILED') {
        logger.debug('lms: probe rejected resume token', { reason: err.message });
        return false;
      }
      // Transport problems are not proof the session died.
      throw err;
    }
  },

  toCredential(state) {
    return {
      type: 'token',
      cookies: null,
      token: state.token ?? null,
      header: null,
      expiresAt: state.expiresAt ?? null,
      obtainedAt: state.lastValidatedAt ?? Date.now(),
    };
  },

  /** Convenience for consumers: is this token close to expiring? */
  isExpiringSoon(state, marginMs = EXPIRY_SAFETY_MS) {
    return state?.expiresAt != null && state.expiresAt - Date.now() < marginMs;
  },
};

function randomState() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function toEpochMs(tokenExpires) {
  if (tokenExpires == null) return null;
  if (typeof tokenExpires === 'number') return tokenExpires;
  if (typeof tokenExpires.$date === 'number') return tokenExpires.$date;
  const parsed = Date.parse(tokenExpires);
  return Number.isFinite(parsed) ? parsed : null;
}
