/**
 * Cookie- and redirect-aware HTTP transport built on global `fetch`.
 *
 * Why not just `fetch(..., { redirect: 'follow' })`?
 *
 * 1. Cookie visibility: with automatic redirects the intermediate `Set-Cookie`
 *    headers are lost, and in several flows the session cookie is only set on
 *    an intermediate hop (Moodle redirects through CAS; samad bounces through
 *    several URLs). We therefore follow redirects manually and feed every
 *    `Set-Cookie` into a {@link CookieJar}.
 * 2. Redirect quirks: samad's app emits `http://` Location headers behind an
 *    https load balancer, which produces a redirect loop unless the scheme is
 *    upgraded. The `upgradeInsecure` option does that for such services.
 *
 * The module has no Node-specific imports so it also runs in browsers
 * (with the usual caveat that `Set-Cookie` is not readable there unless a
 * proxy surfaces it).
 */

export const DEFAULT_TIMEOUT_MS = 30_000;
export const DEFAULT_USER_AGENT = 'aut-cas-sso/0.1 (+https://github.com/aut-cas-sso)';

/* ------------------------------------------------------------------ */
/* Cookie jar                                                          */
/* ------------------------------------------------------------------ */

/**
 * Minimal RFC-6265-flavoured cookie jar, serializable to a plain object.
 * Only the attributes the AUT services actually use are honoured: Domain,
 * Path, Secure, Expires/Max-Age.
 */
export class CookieJar {
  constructor() {
    /** @type {Map<string, {value: string, domain: string, hostOnly: boolean, path: string, secure: boolean, expiresAt: number|null}>} */
    this._entries = new Map();
  }

  /**
   * Parse a single `Set-Cookie` header value in the context of `requestUrl`.
   * Returns null when the cookie is already expired (deletion marker).
   *
   * @param {string} setCookie
   * @param {string} requestUrl
   * @returns {{name: string, value: string, domain: string, hostOnly: boolean, path: string, secure: boolean, expiresAt: number|null}|null}
   */
  static parseSetCookie(setCookie, requestUrl) {
    const url = new URL(requestUrl);
    const parts = String(setCookie).split(';');
    const first = parts.shift();
    const eq = first.indexOf('=');
    if (eq <= 0) return null;
    const name = first.slice(0, eq).trim();
    const value = first.slice(eq + 1).trim();
    if (!name) return null;

    let domain = url.hostname.toLowerCase();
    let hostOnly = true;
    let path = defaultPath(url.pathname);
    let secure = false;
    let expiresAt = null;

    for (const attr of parts) {
      const i = attr.indexOf('=');
      const k = (i === -1 ? attr : attr.slice(0, i)).trim().toLowerCase();
      const v = i === -1 ? '' : attr.slice(i + 1).trim();
      if (k === 'domain' && v) {
        domain = v.replace(/^\./, '').toLowerCase();
        hostOnly = false;
      } else if (k === 'path' && v) {
        path = v.startsWith('/') ? v : defaultPath(url.pathname);
      } else if (k === 'secure') {
        secure = true;
      } else if (k === 'max-age') {
        const secs = Number(v);
        if (Number.isFinite(secs)) expiresAt = secs <= 0 ? 0 : Date.now() + secs * 1000;
      } else if (k === 'expires' && expiresAt === null) {
        const t = Date.parse(v);
        if (Number.isFinite(t)) expiresAt = t;
      }
    }

    if (expiresAt === 0) return { name, value: '', domain, hostOnly, path, secure, expiresAt: 0 };
    return { name, value, domain, hostOnly, path, secure, expiresAt };
  }

  /**
   * Store one `Set-Cookie` value (or several) for `requestUrl`.
   * Expired cookies remove the entry, matching browser behaviour.
   *
   * @param {string} requestUrl
   * @param {string|string[]} setCookieValues
   */
  setFromResponse(requestUrl, setCookieValues) {
    const values = Array.isArray(setCookieValues) ? setCookieValues : [setCookieValues];
    for (const raw of values) {
      if (!raw) continue;
      const parsed = CookieJar.parseSetCookie(raw, requestUrl);
      if (!parsed) continue;
      const key = `${parsed.domain}|${parsed.path}|${parsed.name}`;
      if (parsed.expiresAt === 0 || (parsed.expiresAt !== null && parsed.expiresAt <= Date.now())) {
        this._entries.delete(key);
        // Also drop host-only variants under the same name for simplicity.
        for (const k of [...this._entries.keys()]) {
          if (k.endsWith(`|${parsed.name}`) && this._entries.get(k).domain === parsed.domain) this._entries.delete(k);
        }
      } else {
        this._entries.set(key, parsed);
      }
    }
  }

  /**
   * Cookie request header value for `requestUrl` ('' when nothing matches).
   * @param {string} requestUrl
   * @returns {string}
   */
  get(requestUrl) {
    const url = new URL(requestUrl);
    const now = Date.now();
    const pairs = [];
    for (const [key, e] of [...this._entries]) {
      if (e.expiresAt !== null && e.expiresAt <= now) {
        this._entries.delete(key);
        continue;
      }
      if (!hostMatches(url.hostname, e)) continue;
      if (!pathMatches(url.pathname, e.path)) continue;
      if (e.secure && url.protocol !== 'https:') continue;
      pairs.push(`${e.name}=${e.value}`);
    }
    return pairs.join('; ');
  }

  /**
   * @param {string} name
   * @param {string} [forUrl] restrict lookup to cookies valid for this URL
   * @returns {string|null}
   */
  getCookie(name, forUrl) {
    if (forUrl) {
      const header = this.get(forUrl);
      for (const pair of header.split('; ')) {
        const [n, ...rest] = pair.split('=');
        if (n === name) return rest.join('=');
      }
      return null;
    }
    for (const e of this._entries.values()) if (e.name === name) return e.value;
    return null;
  }

  /** True when no (unexpired) cookies are stored. */
  get isEmpty() {
    const now = Date.now();
    for (const [key, e] of [...this._entries]) {
      if (e.expiresAt !== null && e.expiresAt <= now) this._entries.delete(key);
      else return false;
    }
    return true;
  }

  /** Earliest expiry among stored cookies, or null if none is bounded. */
  earliestExpiry() {
    let min = null;
    const now = Date.now();
    for (const e of this._entries.values()) {
      if (e.expiresAt !== null && e.expiresAt <= now) continue;
      if (e.expiresAt !== null && (min === null || e.expiresAt < min)) min = e.expiresAt;
    }
    return min;
  }

  /** Remove every cookie. */
  clear() {
    this._entries.clear();
  }

  /**
   * JSON-safe snapshot of the jar (used as persisted session state).
   * Expired cookies are pruned first.
   * @returns {object}
   */
  toJSON() {
    const now = Date.now();
    const out = {};
    for (const [key, e] of [...this._entries]) {
      if (e.expiresAt !== null && e.expiresAt <= now) {
        this._entries.delete(key);
        continue;
      }
      out[e.name] = {
        value: e.value,
        domain: e.domain,
        hostOnly: e.hostOnly,
        path: e.path,
        secure: e.secure,
        expiresAt: e.expiresAt,
      };
    }
    return out;
  }

  /**
   * Restore a jar from {@link CookieJar.toJSON} output.
   * @param {object|null|undefined} data
   * @returns {CookieJar}
   */
  static fromJSON(data) {
    const jar = new CookieJar();
    if (data && typeof data === 'object') {
      for (const [name, e] of Object.entries(data)) {
        if (!e || typeof e !== 'object') continue;
        const expiresAt = e.expiresAt ?? null;
        if (expiresAt !== null && expiresAt <= Date.now()) continue;
        jar._entries.set(`${e.domain ?? ''}|${e.path ?? '/'}|${name}`, {
          name,
          value: String(e.value ?? ''),
          domain: String(e.domain ?? '').toLowerCase(),
          hostOnly: e.hostOnly !== false,
          path: e.path ?? '/',
          secure: Boolean(e.secure),
          expiresAt,
        });
      }
    }
    return jar;
  }
}

function defaultPath(pathname) {
  if (!pathname || !pathname.startsWith('/')) return '/';
  const idx = pathname.lastIndexOf('/');
  return idx <= 0 ? '/' : pathname.slice(0, idx);
}

function hostMatches(hostname, entry) {
  const h = hostname.toLowerCase();
  if (entry.hostOnly) return h === entry.domain;
  return h === entry.domain || h.endsWith(`.${entry.domain}`);
}

function pathMatches(pathname, cookiePath) {
  if (cookiePath === '/') return true;
  if (pathname === cookiePath) return true;
  if (!pathname.startsWith(cookiePath)) return false;
  return cookiePath.endsWith('/') || pathname[cookiePath.length] === '/';
}

/* ------------------------------------------------------------------ */
/* Request                                                             */
/* ------------------------------------------------------------------ */

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

/**
 * @typedef {object} RequestResult
 * @property {string} url final URL after redirects
 * @property {number} status
 * @property {boolean} ok `200 <= status < 300`
 * @property {Record<string, string>} headers lower-cased response headers
 * @property {string[]} setCookies all `Set-Cookie` values seen on the final hop
 * @property {string} text raw response body
 * @property {{url: string, status: number, location: string}[]} redirects hop history
 * @property {() => any} json parse body as JSON (throws SyntaxError on bad body)
 */

/**
 * Perform an HTTP request, following redirects manually and feeding every
 * `Set-Cookie` into the supplied {@link CookieJar}.
 *
 * @param {string} url
 * @param {object} [options]
 * @param {string} [options.method='GET']
 * @param {Record<string, string>} [options.headers]
 * @param {string|Uint8Array} [options.body]
 * @param {CookieJar|null} [options.jar] jar to read from / write into
 * @param {'follow'|'manual'} [options.redirect='follow']
 * @param {number} [options.maxRedirects=10]
 * @param {number} [options.timeoutMs]
 * @param {boolean} [options.upgradeInsecure=false] rewrite http redirect
 *   targets to https (needed for samad's http Location headers)
 * @param {typeof fetch} [options.fetchImpl]
 * @param {string} [options.userAgent]
 * @param {AbortSignal} [options.signal]
 * @returns {Promise<RequestResult>}
 */
export async function request(url, options = {}) {
  const {
    method = 'GET',
    headers = {},
    body = undefined,
    jar = null,
    redirect = 'follow',
    maxRedirects = 10,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    upgradeInsecure = false,
    fetchImpl = globalThis.fetch,
    userAgent = DEFAULT_USER_AGENT,
    signal = undefined,
  } = options;

  if (typeof fetchImpl !== 'function') {
    throw new TypeError('No fetch implementation available; pass options.fetchImpl');
  }

  let currentUrl = String(url);
  let currentMethod = method.toUpperCase();
  let currentBody = body;
  const redirects = [];
  const baseHeaders = { 'user-agent': userAgent, ...normalizeHeaders(headers) };
  if (currentBody !== undefined && !baseHeaders['content-type'] && typeof currentBody === 'string') {
    baseHeaders['content-type'] = 'application/x-www-form-urlencoded';
  }

  for (let hop = 0; ; hop++) {
    const sendHeaders = { ...baseHeaders };
    if (jar) {
      const cookieHeader = jar.get(currentUrl);
      if (cookieHeader) sendHeaders.cookie = cookieHeader;
    }

    const timeoutSignal = AbortSignal.timeout(timeoutMs);
    const signalArg = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

    const res = await fetchImpl(currentUrl, {
      method: currentMethod,
      headers: sendHeaders,
      body: currentMethod === 'GET' || currentMethod === 'HEAD' ? undefined : currentBody,
      redirect: 'manual',
      signal: signalArg,
    });

    const setCookies = getSetCookies(res);
    if (jar) for (const sc of setCookies) jar.setFromResponse(currentUrl, sc);

    const status = res.status;
    const location = res.headers.get('location');

    if (redirect === 'follow' && REDIRECT_CODES.has(status) && location) {
      if (hop >= maxRedirects) {
        throw new Error(`Too many redirects (>${maxRedirects}) at ${currentUrl}`);
      }
      const next = new URL(location, currentUrl);
      if (upgradeInsecure && next.protocol === 'http:' && next.hostname === new URL(currentUrl).hostname) {
        next.protocol = 'https:';
      }
      redirects.push({ url: currentUrl, status, location: next.toString() });

      // Browser-compatible method rewriting on redirect.
      if (status === 303 || ((status === 301 || status === 302) && currentMethod === 'POST')) {
        currentMethod = 'GET';
        currentBody = undefined;
      }
      currentUrl = next.toString();
      continue;
    }

    const text = status === 204 || status === 205 ? '' : await res.text();
    const headerObj = {};
    for (const [k, v] of res.headers.entries()) headerObj[k] = v;

    return {
      url: currentUrl,
      status,
      ok: status >= 200 && status < 300,
      headers: headerObj,
      setCookies,
      text,
      redirects,
      json() {
        return JSON.parse(text);
      },
    };
  }
}

function normalizeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (v !== undefined && v !== null) out[String(k).toLowerCase()] = String(v);
  }
  return out;
}

function getSetCookies(res) {
  if (typeof res.headers.getSetCookie === 'function') return res.headers.getSetCookie();
  const single = res.headers.get('set-cookie');
  return single ? [single] : [];
}

/**
 * Convenience: GET `url` with query parameters.
 * @param {string} url
 * @param {Record<string, string|number|undefined|null>} params
 * @param {object} [options] forwarded to {@link request}
 */
export function get(url, params, options) {
  const u = new URL(url);
  for (const [k, v] of Object.entries(params || {})) {
    if (v !== undefined && v !== null) u.searchParams.set(k, String(v));
  }
  return request(u.toString(), { ...options, method: 'GET' });
}

/**
 * Convenience: POST `application/x-www-form-urlencoded` body.
 * @param {string} url
 * @param {Record<string, string|number|undefined|null>} fields
 * @param {object} [options] forwarded to {@link request}
 */
export function postForm(url, fields, options = {}) {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(fields || {})) {
    if (v !== undefined && v !== null) body.append(k, String(v));
  }
  return request(url, {
    ...options,
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', ...(options.headers || {}) },
    body: body.toString(),
  });
}
