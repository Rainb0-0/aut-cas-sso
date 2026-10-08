/**
 * Injectable, leveled logger.
 *
 * The library never writes to the console on its own: callers hand a logger
 * instance to {@link SessionManager} and every internal component receives it
 * through dependency injection. When no logger is supplied the library uses a
 * silent one.
 *
 * A logger is any object implementing a subset of:
 *
 * ```js
 * {
 *   debug(message, meta?),  // verbose flow tracing (ticket minting, probes, ...)
 *   info(message, meta?),   // lifecycle events (login, refresh, persistence)
 *   warn(message, meta?),   // recoverable problems (missing key, retries)
 *   error(message, meta?),  // failed operations
 * }
 * ```
 *
 * `meta` is an optional structured object that sinks may format as they wish.
 */

const LEVELS = Object.freeze({ debug: 10, info: 20, warn: 30, error: 40 });

/**
 * Create a console-backed logger.
 *
 * @param {object} [options]
 * @param {'debug'|'info'|'warn'|'error'|'silent'} [options.level='warn']
 *   Minimum level that gets emitted.
 * @param {(level: string, message: string, meta?: object) => void} [options.sink]
 *   Custom sink; defaults to `console.debug/info/warn/error`.
 * @param {string} [options.prefix='aut-cas-sso']
 * @returns {{debug: Function, info: Function, warn: Function, error: Function}}
 */
export function createLogger({ level = 'warn', sink, prefix = 'aut-cas-sso' } = {}) {
  const threshold = LEVELS[level];
  if (threshold === undefined) {
    throw new TypeError(`Unknown log level "${level}" (expected debug|info|warn|error|silent)`);
  }
  const emit =
    sink ||
    ((lvl, message, meta) => {
      const line = `[${prefix}] ${lvl}: ${message}`;
      const out = console[lvl] || console.log; // eslint-disable-line no-console
      if (meta !== undefined) out(line, meta);
      else out(line);
    });

  const make = (lvl) => (message, meta) => {
    if (LEVELS[lvl] >= threshold) emit(lvl, String(message), meta);
  };

  return { debug: make('debug'), info: make('info'), warn: make('warn'), error: make('error') };
}

/**
 * A logger that discards everything. Used as the library default so that
 * merely importing or running the library never produces output.
 *
 * @type {{debug: Function, info: Function, warn: Function, error: Function}}
 */
export const silentLogger = Object.freeze({
  debug() {},
  info() {},
  warn() {},
  error() {},
});

/**
 * Validate/coerce a caller-supplied logger.
 *
 * - `undefined`/`null` -> {@link silentLogger}
 * - a partial logger gets missing methods filled with no-ops
 * - anything else throws, so misconfiguration surfaces immediately
 *
 * @param {object|null|undefined} logger
 * @returns {{debug: Function, info: Function, warn: Function, error: Function}}
 */
export function normalizeLogger(logger) {
  if (logger == null) return silentLogger;
  if (typeof logger !== 'object') throw new TypeError('logger must be an object');
  const out = {};
  for (const lvl of ['debug', 'info', 'warn', 'error']) {
    const fn = logger[lvl];
    if (fn == null) out[lvl] = () => {};
    else if (typeof fn !== 'function') throw new TypeError(`logger.${lvl} must be a function`);
    else out[lvl] = fn.bind(logger);
  }
  return out;
}
