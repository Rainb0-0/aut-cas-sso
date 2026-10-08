/**
 * SessionManager — the public façade of aut-cas-sso.
 *
 * Responsibilities:
 *
 * - **Multi-account**: hold N accounts; every operation names the account
 *   explicitly (`getCredential(service, accountId)`), and per-(service,
 *   account) work is single-flighted so concurrent callers share one fetch.
 * - **Credential on demand**: return a valid session credential for a
 *   service, fetching one when none exists, probing when the local copy is
 *   stale, and re-fetching when the current one turns out to be invalid.
 * - **Validation strategy** (the chosen "expiry tracking + probe + retry"):
 *   1. hard expiry (`expiresAt`, when the service discloses it) with a
 *      safety margin -> refresh without asking the network,
 *   2. staleness (`probeIntervalMs`) -> adapter probe; definitive `false`
 *      triggers refresh,
 *   3. transport-level probe failure -> NOT treated as death; the cached
 *      session keeps being served (logged),
 *   4. callers that receive a 401 from a service call `invalidate()` and
 *      the next `getCredential()` refetches.
 * - **Persistence**: accounts + sessions are always written to a store
 *   (default: `./.aut-cas-sessions.json` in cwd). Passwords are stored
 *   encrypted (AES-256-GCM) when an encryption key is configured — via the
 *   `encryptionKey` option or the `AUT_CAS_SESSION_KEY` env var — otherwise
 *   they are skipped with a logged warning and sessions stop self-healing
 *   once they die.
 * - **Logging**: everything is reported through the injected logger.
 */

import { ConfigurationError, ReauthenticationRequiredError, TgtInvalidError, AutCasError } from './errors.js';
import { CookieJar } from './http.js';
import { CasClient, CAS_BASE_URL } from './cas.js';
import { FileStore, MemoryStore } from './store.js';
import { encryptSecret, decryptSecret } from './crypto.js';
import { normalizeLogger, silentLogger } from './logger.js';
import { defaultServices } from './services/index.js';

const STATE_VERSION = 1;
const DEFAULT_PROBE_INTERVAL_MS = 5 * 60 * 1000;
const DEFAULT_EXPIRY_SAFETY_MS = 60 * 1000;

export class SessionManager {
  /**
   * @param {object} [options]
   * @param {{id: string, username: string, password: string}[]} [options.accounts]
   *   Accounts to register (can also be added later via {@link addAccount}).
   * @param {object} [options.cas] `CasClient` options (`baseUrl`, `tgtTtlMs`, ...)
   * @param {object} [options.store] persistence store; defaults to
   *   `new FileStore()` (`./.aut-cas-sessions.json` in cwd). Pass
   *   `new MemoryStore()` for ephemeral state.
   * @param {object} [options.logger] injectable logger (silent by default)
   * @param {string} [options.encryptionKey] passphrase for stored passwords;
   *   falls back to `process.env.AUT_CAS_SESSION_KEY` when present
   * @param {Record<string, object>} [options.services] adapter registry
   *   (defaults to courses/lmshome/samad/lms)
   * @param {typeof fetch} [options.fetchImpl]
   * @param {typeof WebSocket} [options.WebSocketImpl]
   * @param {number} [options.probeIntervalMs=300000] re-probe healthy sessions
   *   at least this often
   * @param {number} [options.expirySafetyMs=60000] refresh this long before a
   *   known `expiresAt`
   * @param {number} [options.timeoutMs] per-request timeout for CAS calls
   */
  constructor(options = {}) {
    const {
      accounts = [],
      cas = {},
      store = new FileStore(),
      logger = null,
      encryptionKey = undefined,
      services = defaultServices(),
      fetchImpl = globalThis.fetch,
      WebSocketImpl = globalThis.WebSocket,
      probeIntervalMs = DEFAULT_PROBE_INTERVAL_MS,
      expirySafetyMs = DEFAULT_EXPIRY_SAFETY_MS,
      timeoutMs = undefined,
    } = options;

    if (store == null || typeof store.load !== 'function' || typeof store.save !== 'function') {
      throw new ConfigurationError('options.store must implement load() and save()');
    }
    if (!services || typeof services !== 'object') {
      throw new ConfigurationError('options.services must be an object map of adapters');
    }
    if (typeof fetchImpl !== 'function') {
      throw new ConfigurationError('No fetch implementation available; pass options.fetchImpl');
    }

    this.logger = normalizeLogger(logger);
    this.store = store;
    this.fetchImpl = fetchImpl;
    this.WebSocketImpl = WebSocketImpl;
    this.probeIntervalMs = probeIntervalMs;
    this.expirySafetyMs = expirySafetyMs;
    this.services = services;
    this.encryptionKey = resolveEncryptionKey(encryptionKey);
    this._warnedNoKey = false;

    this.cas = new CasClient({ ...cas, fetchImpl, logger: this.logger, ...(timeoutMs ? { timeoutMs } : {}) });

    /** @type {Map<string, {id: string, username: string, password: string|null, passwordEnc: object|null}>} */
    this._accounts = new Map();
    /** @type {Map<string, object>} key: `${service}::${accountId}` */
    this._sessions = new Map();
    /** @type {Map<string, {url: string, createdAt: number, expiresAt: number}>} CAS TGTs, memory-only */
    this._tgts = new Map();
    /** @type {Map<string, Promise<any>>} single-flight guards */
    this._flights = new Map();

    this._readyPromise = null;
    this._saveChain = Promise.resolve();
    this._savePending = null;
    this._stopped = false;

    for (const acc of accounts) this.addAccount(acc);
  }

  /* ---------------------------------------------------------------- */
  /* Lifecycle                                                         */
  /* ---------------------------------------------------------------- */

  /**
   * Load persisted state. Idempotent; also invoked automatically by the
   * first operation, so explicit `start()` is only needed when you want to
   * fail fast or await hydration.
   * @returns {Promise<void>}
   */
  start() {
    if (!this._readyPromise) this._readyPromise = this._load();
    return this._readyPromise;
  }

  async _load() {
    const state = await this.store.load();
    if (state && typeof state === 'object') {
      for (const [id, acc] of Object.entries(state.accounts || {})) {
        if (!acc || typeof acc !== 'object') continue;
        if (this._accounts.has(id)) {
          // Explicitly registered account wins, but keep the stored blob so a
          // password supplied earlier still round-trips if unchanged.
          const cur = this._accounts.get(id);
          if (!cur.password && acc.password) cur.passwordEnc = acc.password;
          continue;
        }
        this._accounts.set(id, {
          id,
          username: String(acc.username ?? ''),
          password: null,
          passwordEnc: acc.password && typeof acc.password === 'object' ? acc.password : null,
        });
      }
      let sessionCount = 0;
      for (const [key, sess] of Object.entries(state.sessions || {})) {
        if (sess && typeof sess === 'object') {
          this._sessions.set(key, sess);
          sessionCount++;
        }
      }
      this.logger.info('state loaded from store', {
        accounts: this._accounts.size,
        sessions: sessionCount,
      });
    } else {
      this.logger.debug('store empty, starting fresh');
    }
  }

  /** Flush pending persistence and stop accepting new work. */
  async stop() {
    await this.flush();
    this._stopped = true;
  }

  /** Await any queued persistence. */
  async flush() {
    await this.start();
    if (this._savePending) await this._savePending;
  }

  /* ---------------------------------------------------------------- */
  /* Accounts                                                          */
  /* ---------------------------------------------------------------- */

  /**
   * Register (or replace) an account. Synchronous; persistence happens in
   * the background — `await flush()`/`stop()` to guarantee it landed.
   *
   * @param {{id: string, username: string, password: string}} account
   */
  addAccount({ id, username, password } = {}) {
    if (typeof id !== 'string' || !id.trim()) throw new ConfigurationError('account id must be a non-empty string');
    if (typeof username !== 'string' || !username) throw new ConfigurationError(`account "${id}": username required`);
    if (typeof password !== 'string' || !password) throw new ConfigurationError(`account "${id}": password required`);

    this._accounts.set(id, { id, username, password, passwordEnc: null });
    this._tgts.delete(id);
    this.logger.debug('account registered', { id, username });
    this._scheduleSave();
  }

  /**
   * Remove an account and all of its sessions/tickets.
   * @param {string} id
   */
  removeAccount(id) {
    const existed = this._accounts.delete(id);
    this._tgts.delete(id);
    for (const key of [...this._sessions.keys()]) {
      if (key.endsWith(`::${id}`)) this._sessions.delete(key);
    }
    if (existed) {
      this.logger.info('account removed', { id });
      this._scheduleSave();
    }
  }

  /**
   * Accounts currently known (never exposes passwords).
   * @returns {{id: string, username: string}[]}
   */
  listAccounts() {
    return [...this._accounts.values()].map(({ id, username }) => ({ id, username }));
  }

  /* ---------------------------------------------------------------- */
  /* Credentials                                                       */
  /* ---------------------------------------------------------------- */

  /**
   * Obtain a valid session credential for `serviceId` on behalf of
   * `accountId` — fetching, probing and refreshing as needed.
   *
   * @param {string} serviceId `courses` | `lmshome` | `samad` | `lms` | custom
   * @param {string} accountId required — the account to use
   * @returns {Promise<object>} credential (see services/types.js)
   */
  async getCredential(serviceId, accountId) {
    const state = await this._ensureState(serviceId, accountId);
    return this._toCredential(serviceId, accountId, state);
  }

  /**
   * Force a liveness probe against the service.
   *
   * @param {string} serviceId
   * @param {string} accountId
   * @returns {Promise<boolean>} `false` only on a definitive "not authenticated"
   */
  async probe(serviceId, accountId) {
    const adapter = this._adapter(serviceId);
    this._requireAccount(accountId);
    const state = this._sessions.get(key(serviceId, accountId));
    if (!state) return false;

    const alive = await this._runProbe(adapter, accountId, state);
    if (alive) {
      state.lastValidatedAt = Date.now();
      this._scheduleSave();
    }
    return alive;
  }

  /**
   * Report the current session as invalid (e.g. the service answered 401).
   * The next `getCredential()` re-fetches it.
   *
   * @param {string} serviceId
   * @param {string} accountId
   */
  invalidate(serviceId, accountId) {
    this._adapter(serviceId);
    this._requireAccount(accountId);
    const k = key(serviceId, accountId);
    if (this._sessions.delete(k)) {
      this.logger.info('session invalidated by caller', { service: serviceId, account: accountId });
      this._scheduleSave();
    }
  }

  /**
   * Synchronous snapshot of stored session metadata (no probe, no fetch).
   * @param {string} serviceId
   * @param {string} accountId
   * @returns {{present: boolean, expiresAt: number|null, lastValidatedAt: number|null, ageMs: number|null}|null}
   */
  getSessionInfo(serviceId, accountId) {
    const state = this._sessions.get(key(serviceId, accountId));
    if (!state) return null;
    return {
      present: true,
      expiresAt: state.expiresAt ?? null,
      lastValidatedAt: state.lastValidatedAt ?? null,
      ageMs: state.lastValidatedAt ? Date.now() - state.lastValidatedAt : null,
      meta: state.meta ? { ...state.meta } : undefined,
    };
  }

  /* ---------------------------------------------------------------- */
  /* Internals                                                         */
  /* ---------------------------------------------------------------- */

  _adapter(serviceId) {
    const adapter = this.services[serviceId];
    if (!adapter) {
      throw new ConfigurationError(
        `Unknown service "${serviceId}" (known: ${Object.keys(this.services).join(', ')})`,
        { serviceId },
      );
    }
    return adapter;
  }

  _requireAccount(accountId) {
    if (typeof accountId !== 'string' || !accountId) {
      throw new ConfigurationError('accountId is required — this library never picks an account for you');
    }
    const acc = this._accounts.get(accountId);
    if (!acc) {
      throw new ConfigurationError(
        `Unknown account "${accountId}" (registered: ${[...this._accounts.keys()].join(', ') || 'none'})`,
        { accountId },
      );
    }
    return acc;
  }

  /**
   * Ensure a live session state exists for (serviceId, accountId),
   * applying expiry tracking, probe and refresh. Single-flighted per key.
   * @returns {Promise<object>}
   */
  async _ensureState(serviceId, accountId) {
    await this.start();
    if (this._stopped) throw new ConfigurationError('SessionManager has been stopped');
    const adapter = this._adapter(serviceId);
    this._requireAccount(accountId);

    const k = key(serviceId, accountId);
    const flight = this._flights.get(k);
    if (flight) return flight;

    const promise = this._ensureStateUncached(serviceId, accountId, adapter).finally(() => {
      this._flights.delete(k);
    });
    this._flights.set(k, promise);
    return promise;
  }

  async _ensureStateUncached(serviceId, accountId, adapter) {
    const k = key(serviceId, accountId);
    const state = this._sessions.get(k);
    const now = Date.now();
    const expired =
      state?.expiresAt != null && state.expiresAt - this.expirySafetyMs <= now;
    const stale = !state || now - (state.lastValidatedAt ?? 0) >= this.probeIntervalMs;

    if (state && !expired) {
      if (!stale) return state; // fast path: no network at all

      try {
        const alive = await this._runProbe(adapter, accountId, state);
        if (alive) {
          state.lastValidatedAt = Date.now();
          this._scheduleSave();
          return state;
        }
        this.logger.info('probe reported session dead; refreshing', {
          service: serviceId,
          account: accountId,
        });
      } catch (err) {
        // Transport failure is not proof of death: keep serving the cached
        // session (it may be fine) and surface the problem in the log.
        this.logger.warn('probe unavailable; serving cached session', {
          service: serviceId,
          account: accountId,
          error: err?.message,
        });
        return state;
      }
    } else if (state && expired) {
      this.logger.debug('session past known expiry; refreshing', {
        service: serviceId,
        account: accountId,
        expiresAt: state.expiresAt,
      });
    }

    return this._refresh(serviceId, accountId, adapter);
  }

  /** Fetch a brand-new session state for (service, account). */
  async _refresh(serviceId, accountId, adapter) {
    const k = key(serviceId, accountId);
    const account = this._requireAccount(accountId);
    const previous = this._sessions.get(k);

    const password = await this._resolvePassword(account);
    if (!password) {
      throw new ReauthenticationRequiredError(
        `No stored password available for account "${accountId}" — call addAccount() with the password to re-authenticate`,
        { accountId, service: serviceId },
      );
    }

    this.logger.info('fetching new session', { service: serviceId, account: accountId });

    const ctx = {
      fetchImpl: this.fetchImpl,
      logger: this.logger,
      WebSocketImpl: this.WebSocketImpl,
      jar: previous?.cookies ? CookieJar.fromJSON(previous.cookies) : undefined,
      // Dependency hook: lms asks the manager for a live Moodle state.
      ensureSession: (depServiceId) => this._ensureState(depServiceId, accountId),
    };

    if (adapter.requiresCas) {
      ctx.ticket = await this._mintTicket(accountId, account, adapter.serviceUrl);
    }

    const next = await adapter.redeem(ctx);
    this._sessions.set(k, next);
    this._scheduleSave();
    this.logger.debug('session stored', {
      service: serviceId,
      account: accountId,
      expiresAt: next.expiresAt ?? null,
    });
    return next;
  }

  /**
   * Mint a service ticket from the account's TGT, re-logging in once when
   * CAS reports the TGT dead or missing.
   */
  async _mintTicket(accountId, account, serviceUrl) {
    if (!serviceUrl) {
      throw new ConfigurationError(`Service adapter did not provide a serviceUrl`, { accountId });
    }
    const flightKey = `tgt::${accountId}`;
    const flight = this._flights.get(flightKey);
    if (flight) {
      const tgt = await flight;
      return this.cas.serviceTicket(tgt, serviceUrl);
    }
    const promise = this._ensureTgt(accountId, account).finally(() => this._flights.delete(flightKey));
    this._flights.set(flightKey, promise);
    const tgt = await promise;
    try {
      return await this.cas.serviceTicket(tgt, serviceUrl);
    } catch (err) {
      if (!(err instanceof TgtInvalidError)) throw err;
      this.logger.warn('TGT rejected while minting ticket; re-authenticating with CAS', { accountId });
      this._tgts.delete(accountId);
      const fresh = await this._ensureTgt(accountId, account, true);
      return this.cas.serviceTicket(fresh, serviceUrl);
    }
  }

  async _ensureTgt(accountId, account, force = false) {
    const existing = this._tgts.get(accountId);
    if (!force && existing && existing.expiresAt > Date.now()) return existing;
    const password = await this._resolvePassword(account);
    if (!password) {
      throw new ReauthenticationRequiredError(
        `No stored password available for account "${accountId}" to authenticate with CAS`,
        { accountId },
      );
    }
    const tgt = await this.cas.requestTgt(account.username, password);
    this._tgts.set(accountId, tgt);
    return tgt;
  }

  async _runProbe(adapter, accountId, state) {
    return adapter.probe({
      state,
      fetchImpl: this.fetchImpl,
      logger: this.logger,
      WebSocketImpl: this.WebSocketImpl,
      accountId,
    });
  }

  _toCredential(serviceId, accountId, state) {
    const base = this.services[serviceId].toCredential(state);
    const expiresAt = base.expiresAt ?? null;
    return {
      service: serviceId,
      accountId,
      ...base,
      remainingMs: expiresAt != null ? Math.max(0, expiresAt - Date.now()) : null,
    };
  }

  /**
   * Password for an account: in-memory first, then the decrypted blob.
   * @returns {Promise<string|null>}
   */
  async _resolvePassword(account) {
    if (account.password) return account.password;
    if (!account.passwordEnc) return null;
    if (!this.encryptionKey) {
      if (!this._warnedNoKey) {
        this._warnedNoKey = true;
        this.logger.warn(
          'stored password for an account cannot be decrypted: no encryptionKey/AUT_CAS_SESSION_KEY configured; session refresh will fail once the current session dies',
          { accountId: account.id },
        );
      }
      return null;
    }
    try {
      const password = await decryptSecret(account.passwordEnc, this.encryptionKey);
      account.password = password; // cache for the process lifetime
      return password;
    } catch (err) {
      this.logger.error('failed to decrypt stored password', { accountId: account.id, error: err.message });
      return null;
    }
  }

  /* ---------------------------------------------------------------- */
  /* Persistence                                                       */
  /* ---------------------------------------------------------------- */

  /** Serialize and queue a store write (writes are chained, latest state wins). */
  _scheduleSave() {
    if (this._stopped) return;
    this._savePending = this._saveChain = this._saveChain.then(() => this._saveNow().catch((err) => {
      this.logger.error('failed to persist state', { error: err?.message });
    }));
  }

  async _saveNow() {
    const accounts = {};
    for (const [id, acc] of this._accounts) {
      let blob = acc.passwordEnc ?? null;
      if (acc.password && !blob) {
        if (this.encryptionKey) {
          blob = await encryptSecret(acc.password, this.encryptionKey);
          acc.passwordEnc = blob;
        } else if (!this._warnedNoKey) {
          this._warnedNoKey = true;
          this.logger.warn(
            'no encryptionKey/AUT_CAS_SESSION_KEY configured: sessions persist, but this account password will not be written to disk',
            { accountId: id },
          );
        }
      }
      accounts[id] = { username: acc.username, password: blob };
    }

    const sessions = {};
    for (const [k, state] of this._sessions) sessions[k] = state;

    await this.store.save({ v: STATE_VERSION, accounts, sessions });
    this.logger.debug('state persisted', {
      accounts: Object.keys(accounts).length,
      sessions: Object.keys(sessions).length,
    });
  }
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function key(serviceId, accountId) {
  return `${serviceId}::${accountId}`;
}

function resolveEncryptionKey(option) {
  if (option != null && option !== '') return option;
  if (typeof process !== 'undefined' && process.env?.AUT_CAS_SESSION_KEY) return process.env.AUT_CAS_SESSION_KEY;
  return null;
}

export { silentLogger, AutCasError };
