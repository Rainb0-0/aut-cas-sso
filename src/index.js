/**
 * aut-cas-sso — public entry point.
 *
 * ```js
 * import { SessionManager, createLogger } from 'aut-cas-sso';
 *
 * const manager = new SessionManager({
 *   accounts: [{ id: 'main', username: 'user', password: 'secret' }],
 *   logger: createLogger({ level: 'debug' }),
 * });
 *
 * const cred = await manager.getCredential('courses', 'main');
 * // cred.cookies -> { MoodleSession, ... }  (or cred.token for 'lms')
 * await manager.stop();
 * ```
 */

export { SessionManager } from './manager.js';

// CAS core
export { CasClient, CAS_BASE_URL, upgradeToHttps, DEFAULT_TGT_TTL_MS } from './cas.js';

// Transport utilities for building authenticated requests
export { request, get, postForm, CookieJar, DEFAULT_TIMEOUT_MS } from './http.js';

// Persistence
export { FileStore, MemoryStore, LocalStorageStore } from './store.js';

// Logging
export { createLogger, silentLogger, normalizeLogger } from './logger.js';

// Password encryption
export { encryptSecret, decryptSecret, isCryptoAvailable } from './crypto.js';

// Errors
export {
  AutCasError,
  InvalidCredentialsError,
  TgtInvalidError,
  ServiceLoginError,
  ReauthenticationRequiredError,
  UnsupportedEnvironmentError,
  ConfigurationError,
} from './errors.js';

// Service adapters
export {
  defaultServices,
  coursesService,
  lmshomeService,
  samadService,
  lmsService,
} from './services/index.js';
export { COURSES_SERVICE_URL, moodleLooksAuthenticated } from './services/courses.js';
export { LMSHOME_SERVICE_URL } from './services/lmshome.js';
export { SAMAD_SERVICE_URL, samadLooksAuthenticated } from './services/samad.js';
export { LMS_U5AUTH, LMS_DDP_URL } from './services/lms.js';

// DDP (Meteor) client, exported for advanced consumers
export { DdpClient, DdpError, DEFAULT_DDP_URL } from './ddp.js';

import { SessionManager } from './manager.js';
export default SessionManager;
