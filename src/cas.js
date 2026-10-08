/**
 * CAS core over the CAS REST protocol — raw HTTP, no browser, no HTML forms.
 *
 * Flow (verified against accounts.aut.ac.ir):
 *
 * 1. `POST {cas}/v1/tickets` with `username`/`password`
 *      -> `201 Created` + `Location: http://.../cas/v1/tickets/TGT-...`
 *         (the Location ships as plain `http://`; it must be upgraded to
 *          https or the follow-up POST gets a 301 from the LB)
 * 2. `POST {TGT url}` with `service=<service url>`
 *      -> `200 text/plain` body is a single-use `ST-...` service ticket
 * 3. The service redeems `?ticket=ST-...` itself (see src/services/*).
 *
 * TGTs live in memory only for the account that owns them; the manager
 * re-requests one when it expires or when ticket minting starts failing.
 */

import { InvalidCredentialsError, TgtInvalidError, AutCasError } from './errors.js';
import { request, postForm } from './http.js';

/** Default CAS base URL for AUT. */
export const CAS_BASE_URL = 'https://accounts.aut.ac.ir/cas';

/** Conservative default TGT lifetime; failures still trigger re-login. */
export const DEFAULT_TGT_TTL_MS = 8 * 60 * 60 * 1000;

/**
 * @typedef {object} Tgt
 * @property {string} url absolute (https) TGT URL
 * @property {number} createdAt epoch ms
 * @property {number} expiresAt epoch ms (local estimate)
 */

export class CasClient {
  /**
   * @param {object} [options]
   * @param {string} [options.baseUrl]
   * @param {typeof fetch} [options.fetchImpl]
   * @param {object} [options.logger]
   * @param {number} [options.timeoutMs]
   * @param {number} [options.tgtTtlMs]
   * @param {string} [options.userAgent]
   */
  constructor(options = {}) {
    const {
      baseUrl = CAS_BASE_URL,
      fetchImpl = globalThis.fetch,
      logger = { debug() {}, info() {}, warn() {}, error() {} },
      timeoutMs = 30_000,
      tgtTtlMs = DEFAULT_TGT_TTL_MS,
      userAgent = undefined,
    } = options;

    if (typeof fetchImpl !== 'function') {
      throw new TypeError('CasClient requires a fetch implementation (global fetch missing?)');
    }

    this.baseUrl = String(baseUrl).replace(/\/+$/, '');
    this.fetchImpl = fetchImpl;
    this.logger = logger;
    this.timeoutMs = timeoutMs;
    this.tgtTtlMs = tgtTtlMs;
    this.userAgent = userAgent;
  }

  /**
   * Exchange username/password for a ticket-granting ticket.
   *
   * @param {string} username
   * @param {string} password
   * @returns {Promise<Tgt>}
   * @throws {InvalidCredentialsError} CAS said no
   */
  async requestTgt(username, password) {
    if (!username || !password) throw new InvalidCredentialsError('username and password are required');

    const started = Date.now();
    const res = await postForm(
      `${this.baseUrl}/v1/tickets`,
      { username, password },
      { fetchImpl: this.fetchImpl, timeoutMs: this.timeoutMs, userAgent: this.userAgent },
    );

    if (res.status === 201 && res.headers.location) {
      const url = upgradeToHttps(new URL(res.headers.location, `${this.baseUrl}/`).toString());
      const tgt = { url, createdAt: Date.now(), expiresAt: Date.now() + this.tgtTtlMs };
      this.logger.debug('CAS TGT granted', { tookMs: Date.now() - started, tgt: truncate(tgt.url) });
      return tgt;
    }

    if (res.status === 401 || res.status === 403) {
      const detail = extractCasErrors(res.text);
      this.logger.warn('CAS rejected credentials', { status: res.status, detail });
      throw new InvalidCredentialsError(detail || 'CAS rejected the credentials', { status: res.status });
    }

    this.logger.error('CAS login failed unexpectedly', { status: res.status, body: truncate(res.text) });
    throw new AutCasError('CAS_LOGIN_FAILED', `CAS login failed with HTTP ${res.status}`, {
      status: res.status,
      body: truncate(res.text),
    });
  }

  /**
   * Mint a single-use service ticket for `serviceUrl` from a TGT.
   *
   * @param {Tgt} tgt
   * @param {string} serviceUrl exact service URL the CAS client will be sent to
   * @returns {Promise<string>} `ST-...`
   * @throws {TgtInvalidError} the TGT expired or was revoked
   */
  async serviceTicket(tgt, serviceUrl) {
    if (!tgt || !tgt.url) throw new TgtInvalidError('No TGT available');

    const started = Date.now();
    const res = await postForm(
      tgt.url,
      { service: serviceUrl },
      { fetchImpl: this.fetchImpl, timeoutMs: this.timeoutMs, userAgent: this.userAgent },
    );

    if (res.status === 200) {
      const ticket = res.text.trim();
      if (!ticket.startsWith('ST-')) {
        this.logger.error('CAS returned a non-ticket body', { status: res.status, body: truncate(ticket) });
        throw new AutCasError('CAS_TICKET_MALFORMED', 'CAS did not return a service ticket', {
          status: res.status,
          body: truncate(ticket),
        });
      }
      this.logger.debug('CAS service ticket minted', {
        service: serviceUrl,
        tookMs: Date.now() - started,
        ticket: `${ticket.slice(0, 16)}...`,
      });
      return ticket;
    }

    if (res.status >= 400 && res.status < 500) {
      const detail = extractCasErrors(res.text);
      this.logger.debug('CAS TGT rejected while minting ticket', { status: res.status, detail });
      throw new TgtInvalidError(detail || `CAS rejected the TGT (HTTP ${res.status})`, {
        status: res.status,
        service: serviceUrl,
      });
    }

    this.logger.error('CAS ticket endpoint error', { status: res.status, body: truncate(res.text) });
    throw new AutCasError('CAS_TICKET_FAILED', `CAS ticket request failed with HTTP ${res.status}`, {
      status: res.status,
      service: serviceUrl,
    });
  }

  /**
   * Convenience: ensure `tgt` is usable (locally fresh) and mint a ticket.
   * Does NOT retry with a new TGT — the manager owns that policy.
   *
   * @param {Tgt|null} tgt
   * @param {string} serviceUrl
   * @returns {Promise<{ticket: string, tgt: Tgt}>}
   */
  async ensureTgtAndTicket(tgt, serviceUrl) {
    let active = tgt;
    if (!active || active.expiresAt <= Date.now()) {
      throw new TgtInvalidError('TGT missing or past its local expiry');
    }
    const ticket = await this.serviceTicket(active, serviceUrl);
    return { ticket, tgt: active };
  }
}

/** `http://host/...` -> `https://host/...` (CAS LB emits http Locations). */
export function upgradeToHttps(url) {
  return url.replace(/^http:\/\//i, 'https://');
}

/** Pull `errors`/`authentication_exceptions` out of CAS error bodies. */
function extractCasErrors(text) {
  if (!text) return '';
  try {
    const data = JSON.parse(text);
    if (Array.isArray(data?.authentication_exceptions)) {
      const msgs = data.authentication_exceptions
        .flat(Infinity)
        .filter((x) => typeof x === 'string' && !x.includes('@class') && x !== 'java.util.ArrayList');
      if (msgs.length) return msgs.join('; ');
    }
    if (Array.isArray(data?.errors)) return data.errors.join('; ');
    if (typeof data?.error_description === 'string') return data.error_description;
  } catch {
    // not JSON — fall through
  }
  return '';
}

function truncate(s, max = 160) {
  const str = String(s ?? '');
  return str.length > max ? `${str.slice(0, max)}…` : str;
}
