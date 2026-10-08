/**
 * Shared JSDoc types for service adapters (documentation-only module).
 *
 * A service adapter hides everything service-specific from the manager:
 * how to turn a CAS service ticket into a usable session, how to check
 * whether a stored session is still alive, and how to expose it as a
 * credential.
 *
 * @typedef {object} SessionState
 * @property {object} cookies serialized CookieJar (`CookieJar.toJSON()`), when cookie-based
 * @property {number|null} expiresAt epoch ms of hard expiry, or null when server-authoritative
 * @property {number} lastValidatedAt epoch ms of last successful redeem/probe
 * @property {object} [meta] adapter-specific data (username, final url, ...)
 * @property {string} [token] bearer-style token, when token-based (lms)
 *
 * @typedef {object} RedeemContext
 * @property {string} ticket fresh single-use CAS service ticket
 * @property {CookieJar} [jar] cookies of the previous session (may be empty)
 * @property {typeof fetch} fetchImpl
 * @property {object} logger
 * @property {(serviceId: string) => Promise<SessionState>} [ensureSession]
 *   dependency hook (lms uses it to guarantee a Moodle session first)
 *
 * @typedef {object} ProbeContext
 * @property {SessionState|null} state
 * @property {typeof fetch} fetchImpl
 * @property {object} logger
 *
 * @typedef {object} Credential
 * @property {'cookie'|'token'} type
 * @property {Record<string,string>|null} cookies name -> value (cookie services)
 * @property {string|null} token bearer token (token services)
 * @property {string|null} header ready-made Authorization header value, if applicable
 * @property {number|null} expiresAt epoch ms or null
 * @property {number} obtainedAt epoch ms
 *
 * @typedef {object} ServiceAdapter
 * @property {string} id stable service id (`courses`, `lmshome`, `samad`, `lms`)
 * @property {string} title human-readable name
 * @property {boolean} requiresCas
 * @property {string} serviceUrl exact URL requested from CAS when minting tickets
 * @property {(ctx: RedeemContext) => Promise<SessionState>} redeem
 * @property {(ctx: ProbeContext) => Promise<boolean>} probe
 * @property {(state: SessionState) => Credential} toCredential
 */

export {};
