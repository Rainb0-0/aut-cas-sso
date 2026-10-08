/**
 * Minimal DDP (Meteor Distributed Data Protocol) client over WebSocket.
 *
 * The Nima lms frontend is a Meteor app: logging in (and therefore
 * validating a resume token) only exists as a DDP `login` method — there is
 * no HTTP endpoint for it. This client speaks just enough DDP for that:
 * connect -> hello/connected -> method call -> result.
 *
 * It uses the platform's global `WebSocket` (Node >= 22 and browsers), so
 * the package stays dependency-free. When no WebSocket exists, callers get
 * {@link UnsupportedEnvironmentError} instead of a confusing crash.
 */

import { AutCasError, UnsupportedEnvironmentError } from './errors.js';

export const DEFAULT_DDP_URL = 'wss://lms.aut.ac.ir/api/websocket';

/** Thrown when a DDP method returns an error result. */
export class DdpError extends AutCasError {
  /** @param {object} error DDP error object from the server */
  constructor(error) {
    super('DDP_METHOD_FAILED', error?.reason || error?.message || 'DDP method failed', {
      ddpError: error,
      errorType: error?.errorType,
      status: typeof error?.error === 'number' ? error.error : undefined,
    });
  }
}

export class DdpClient {
  /**
   * @param {object} [options]
   * @param {string} [options.url]
   * @param {typeof WebSocket} [options.WebSocketImpl]
   * @param {number} [options.timeoutMs=20000]
   * @param {object} [options.logger]
   */
  constructor(options = {}) {
    const { url = DEFAULT_DDP_URL, WebSocketImpl = globalThis.WebSocket, timeoutMs = 20_000, logger = {} } = options;
    this.url = url;
    this.WebSocketImpl = WebSocketImpl;
    this.timeoutMs = timeoutMs;
    this.logger = {
      debug: logger.debug || (() => {}),
      warn: logger.warn || (() => {}),
    };
    this._ws = null;
    this._nextId = 1;
    this._pending = new Map();
    this._connectPromise = null;
  }

  /** True when a WebSocket implementation exists in this environment. */
  static isSupported(WebSocketImpl = globalThis.WebSocket) {
    return typeof WebSocketImpl === 'function';
  }

  /** Establish the connection and complete the DDP handshake. */
  async connect() {
    if (this._ws && this._ready) return;
    if (this._connectPromise) return this._connectPromise;

    if (!DdpClient.isSupported(this.WebSocketImpl)) {
      throw new UnsupportedEnvironmentError(
        'The lms service requires a WebSocket implementation (globalThis.WebSocket), which is unavailable here',
      );
    }

    this._connectPromise = new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new AutCasError('DDP_TIMEOUT', `DDP connection to ${this.url} timed out`));
        try {
          this.WebSocketImpl?.close?.();
        } catch {
          /* ignore */
        }
      }, this.timeoutMs);

      const ws = new this.WebSocketImpl(this.url);
      this._ws = ws;

      const fail = (err) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this._connectPromise = null;
        this._rejectAll(err);
        reject(err);
      };

      ws.addEventListener('open', () => {
        ws.send(JSON.stringify({ msg: 'connect', version: '1', support: ['1', 'pre2', 'pre1'] }));
      });

      ws.addEventListener('message', (event) => {
        let msg;
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }

        if (msg.msg === 'connected' && !settled) {
          settled = true;
          this._ready = true;
          clearTimeout(timer);
          resolve();
          return;
        }
        if (msg.msg === 'failed' && !settled) {
          fail(new AutCasError('DDP_HANDSHAKE_FAILED', `DDP handshake failed: ${msg.version || 'unknown'}`));
          return;
        }
        if (msg.msg === 'ping') {
          try {
            ws.send(JSON.stringify({ msg: 'pong', id: msg.id }));
          } catch {
            /* ignore */
          }
          return;
        }
        if (msg.msg === 'result' && msg.id != null) {
          const entry = this._pending.get(msg.id);
          if (!entry) return;
          this._pending.delete(msg.id);
          clearTimeout(entry.timer);
          if (msg.error) entry.reject(new DdpError(msg.error));
          else entry.resolve(msg.result);
          return;
        }
        // subscriptions/updated/notified are irrelevant for this library
      });

      ws.addEventListener('error', () => {
        fail(new AutCasError('DDP_CONNECTION', `Could not connect to DDP endpoint ${this.url}`));
      });

      ws.addEventListener('close', (event) => {
        this._ready = false;
        this._connectPromise = null;
        this._ws = null;
        this._rejectAll(new AutCasError('DDP_CLOSED', `DDP connection closed (code ${event?.code ?? '?'})`));
        if (!settled) fail(new AutCasError('DDP_CLOSED', 'DDP connection closed during handshake'));
      });
    });

    return this._connectPromise;
  }

  /**
   * Call a DDP method and resolve with its result.
   * @param {string} method
   * @param {any[]} [params]
   * @returns {Promise<any>}
   */
  async call(method, params = []) {
    await this.connect();
    const id = String(this._nextId++);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pending.delete(id);
        reject(new AutCasError('DDP_TIMEOUT', `DDP method "${method}" timed out`));
      }, this.timeoutMs);
      this._pending.set(id, { resolve, reject, timer });
      try {
        this._ws.send(JSON.stringify({ msg: 'method', method, params, id }));
      } catch (err) {
        this._pending.delete(id);
        clearTimeout(timer);
        reject(new AutCasError('DDP_SEND_FAILED', `Could not send DDP method "${method}": ${err.message}`));
      }
    });
  }

  _rejectAll(err) {
    for (const [, entry] of this._pending) {
      clearTimeout(entry.timer);
      entry.reject(err);
    }
    this._pending.clear();
  }

  /** Close the socket if open (idempotent). */
  close() {
    try {
      this._ws?.close();
    } catch {
      /* ignore */
    }
    this._ws = null;
    this._ready = false;
    this._connectPromise = null;
  }

  /**
   * Open a client, run `fn`, always close afterwards.
   * @template T
   * @param {object} options constructor options
   * @param {(client: DdpClient) => Promise<T>} fn
   * @returns {Promise<T>}
   */
  static async withClient(options, fn) {
    const client = new DdpClient(options);
    try {
      return await fn(client);
    } finally {
      client.close();
    }
  }
}
