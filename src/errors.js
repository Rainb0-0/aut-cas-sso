/**
 * Error types thrown by aut-cas-sso.
 *
 * Every library error extends {@link AutCasError} and carries a stable
 * `code` string so consumers can branch without matching on messages.
 */

export class AutCasError extends Error {
  /**
   * @param {string} code stable machine-readable code
   * @param {string} message human-readable message
   * @param {object} [details] structured context (service, account, status, ...)
   */
  constructor(code, message, details = {}) {
    super(message);
    this.name = new.target.name;
    this.code = code;
    Object.assign(this, details);
  }
}

/** CAS rejected the username/password when requesting a TGT. */
export class InvalidCredentialsError extends AutCasError {
  constructor(message = 'CAS rejected the credentials', details = {}) {
    super('INVALID_CREDENTIALS', message, details);
  }
}

/** The TGT could not be used to mint a service ticket (expired/revoked). */
export class TgtInvalidError extends AutCasError {
  constructor(message = 'CAS ticket-granting ticket is no longer valid', details = {}) {
    super('TGT_INVALID', message, details);
  }
}

/** A service refused the CAS ticket or its session (redeem/probe failed). */
export class ServiceLoginError extends AutCasError {
  constructor(message = 'Service login failed', details = {}) {
    super('SERVICE_LOGIN_FAILED', message, details);
  }
}

/** Session is gone and no password is available to fetch a new one. */
export class ReauthenticationRequiredError extends AutCasError {
  constructor(message = 'Session expired and no stored password is available; call addAccount() again', details = {}) {
    super('REAUTH_REQUIRED', message, details);
  }
}

/** A feature needs an API the current environment does not provide. */
export class UnsupportedEnvironmentError extends AutCasError {
  constructor(message = 'Required API is unavailable in this environment', details = {}) {
    super('UNSUPPORTED_ENVIRONMENT', message, details);
  }
}

/** Misuse of the public API (unknown service, missing account id, ...). */
export class ConfigurationError extends AutCasError {
  constructor(message = 'Invalid configuration or usage', details = {}) {
    super('CONFIGURATION', message, details);
  }
}
