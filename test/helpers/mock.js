/**
 * Test helpers: a routing mock for `fetch` and a scripted fake WebSocket.
 */

/**
 * Build a fetch implementation backed by a route list.
 *
 * @param {{match: RegExp|((url: URL, init: RequestInit) => boolean),
 *          method?: string,
 *          respond: (url: URL, init: RequestInit) => {status?: number, headers?: Record<string,string|string[]>, body?: string}}[] } routes
 * @returns {{fetch: typeof fetch, calls: {url: string, method: string, headers: object, body: string|null}[]}}
 */
export function mockFetch(routes) {
  const calls = [];
  const fetchImpl = async (input, init = {}) => {
    const url = new URL(String(input));
    const method = (init.method || 'GET').toUpperCase();
    const record = {
      url: url.toString(),
      method,
      headers: normalize(init.headers),
      body: init.body != null ? String(init.body) : null,
    };
    calls.push(record);

    for (const route of routes) {
      if (route.method && route.method.toUpperCase() !== method) continue;
      const hit =
        route.match instanceof RegExp
          ? route.match.test(url.toString())
          : typeof route.match === 'function'
            ? route.match(url, init)
            : false;
      if (!hit) continue;
      const spec = route.respond(url, init) || {};
      return makeResponse(spec, url.toString());
    }
    throw new Error(`mockFetch: no route for ${method} ${url}`);
  };
  fetchImpl.calls = calls;
  return { fetch: fetchImpl, calls };
}

function normalize(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) out[k.toLowerCase()] = v;
  return out;
}

function makeResponse(spec, url) {
  const status = spec.status ?? 200;
  const headerEntries = [];
  for (const [k, v] of Object.entries(spec.headers || {})) {
    if (Array.isArray(v)) for (const item of v) headerEntries.push([k.toLowerCase(), item]);
    else headerEntries.push([k.toLowerCase(), String(v)]);
  }
  const getSetCookie = () => headerEntries.filter(([k]) => k === 'set-cookie').map(([, v]) => v);
  const headers = {
    get(name) {
      const key = String(name).toLowerCase();
      const found = headerEntries.find(([k]) => k === key);
      return found ? found[1] : null;
    },
    entries: () => headerEntries[Symbol.iterator](),
    getSetCookie,
    has: (name) => headerEntries.some(([k]) => k === String(name).toLowerCase()),
  };
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    url,
    async text() {
      return spec.body ?? '';
    },
    async json() {
      return JSON.parse(spec.body ?? '');
    },
  };
}

/**
 * A simpler scripted fake: `script(frame) -> response frame | null`.
 * Used for DDP tests: the server logic lives in `script`.
 */
export function ddpWebSocket(script) {
  const sockets = [];
  class FakeWS {
    constructor(url) {
      this.url = url;
      this.readyState = 0;
      this._listeners = new Map();
      this.sent = [];
      sockets.push(this);
      queueMicrotask(() => this._dispatch('open'));
    }
    addEventListener(type, fn) {
      if (!this._listeners.has(type)) this._listeners.set(type, []);
      this._listeners.get(type).push(fn);
    }
    removeEventListener(type, fn) {
      const list = this._listeners.get(type) || [];
      const i = list.indexOf(fn);
      if (i >= 0) list.splice(i, 1);
    }
    send(data) {
      this.sent.push(String(data));
      let frame;
      try {
        frame = script(JSON.parse(String(data)), this);
      } catch (err) {
        frame = { msg: 'error', reason: String(err && err.message) };
      }
      if (frame) {
        const frames = Array.isArray(frame) ? frame : [frame];
        for (const f of frames) queueMicrotask(() => this._dispatch('message', JSON.stringify(f)));
      }
    }
    close() {
      this.readyState = 3;
      queueMicrotask(() => this._dispatch('close', { code: 1000 }));
    }
    _dispatch(type, data) {
      const payload = type === 'message' ? { data } : type === 'close' ? data : {};
      for (const fn of this._listeners.get(type) || []) fn(payload);
    }
  }
  FakeWS.sockets = sockets;
  return FakeWS;
}
