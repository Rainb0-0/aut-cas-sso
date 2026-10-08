/**
 * Pluggable persistence stores.
 *
 * The manager always persists (accounts + sessions) — the store only decides
 * *where*. Three implementations ship with the library:
 *
 * - {@link FileStore}   JSON file on disk; **default**, path configurable,
 *                       defaults to `./.aut-cas-sessions.json` in cwd.
 * - {@link MemoryStore} process-memory only (tests, ephemeral use).
 * - {@link LocalStorageStore} for browser single-page apps.
 *
 * A custom store only needs `load()` and `save(state)`; anything with those
 * methods is accepted by the manager.
 *
 * Node built-ins are imported dynamically *inside* {@link FileStore} so that
 * browser bundles of this package never touch `node:fs` (tree-shakers and
 * bundlers only resolve those imports when FileStore is actually used in a
 * Node context).
 */

/** In-memory store: keeps state for the lifetime of the process. */
export class MemoryStore {
  constructor() {
    this._state = null;
  }

  /** @returns {Promise<object|null>} */
  async load() {
    return this._state === null ? null : structuredClone(this._state);
  }

  /** @param {object} state */
  async save(state) {
    this._state = structuredClone(state);
  }
}

/** JSON file store with atomic writes (tmp file + rename). */
export class FileStore {
  /**
   * @param {string} [path='./.aut-cas-sessions.json'] absolute or cwd-relative.
   */
  constructor(path = './.aut-cas-sessions.json') {
    if (typeof path !== 'string' || !path) throw new TypeError('FileStore requires a non-empty path');
    this.path = path;
  }

  async #node() {
    const [{ mkdir, readFile, rename, writeFile }, { dirname, resolve }] = await Promise.all([
      import('node:fs/promises'),
      import('node:path'),
    ]);
    return { mkdir, readFile, rename, writeFile, dirname, resolve };
  }

  /** @returns {Promise<object|null>} */
  async load() {
    const { readFile, resolve } = await this.#node();
    const path = resolve(this.path);
    let raw;
    try {
      raw = await readFile(path, 'utf8');
    } catch (err) {
      if (err && (err.code === 'ENOENT' || err.code === 'ENOTDIR')) return null;
      throw err;
    }
    try {
      return JSON.parse(raw);
    } catch {
      // A corrupt store must not brick startup; treat as empty.
      return null;
    }
  }

  /** @param {object} state */
  async save(state) {
    const { mkdir, rename, writeFile, dirname, resolve } = await this.#node();
    const path = resolve(this.path);
    const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
    const data = JSON.stringify(state, null, 2);
    await mkdir(dirname(path), { recursive: true });
    await writeFile(tmp, data, { encoding: 'utf8', mode: 0o600 });
    await rename(tmp, path);
  }
}

/** Browser store backed by `localStorage`. */
export class LocalStorageStore {
  /** @param {string} [key='aut-cas-sso'] */
  constructor(key = 'aut-cas-sso') {
    if (typeof globalThis.localStorage === 'undefined') {
      throw new TypeError('localStorage is not available in this environment');
    }
    this.key = key;
  }

  async load() {
    const raw = globalThis.localStorage.getItem(this.key);
    if (raw == null) return null;
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async save(state) {
    globalThis.localStorage.setItem(this.key, JSON.stringify(state));
  }
}
