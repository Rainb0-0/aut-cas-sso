# aut-cas-sso

Reusable **CAS SSO session manager** for AUT services — raw HTTP, no browser
automation, zero dependencies, multi-account.

It logs into `accounts.aut.ac.ir` over the CAS REST protocol and turns the
result into **usable session credentials** for each service, managing the
whole lifecycle for you: fetch on demand, probe for liveness, refresh when
invalid, persist across restarts.

| Service id | Site | Credential you get |
|---|---|---|
| `courses` | courses.aut.ac.ir (Moodle) | cookies: `MoodleSession`, `MOODLEID1_` (60-day remember), `HAX` |
| `lmshome` | lmshome.aut.ac.ir (Fararoom) | cookies: `sessionid` (12h, expiry tracked exactly), `csrftoken` |
| `samad`   | samad.aut.ac.ir (SAMAD) | cookies: `JSESSIONID`, `HASH_JSESSIONID` |
| `food`    | food.aut.ac.ir (سامانه تغذیه) | cookies: `.AspNet.ApplicationCookie`, `DGAUTH`, `fn` |
| `lms`     | lms.aut.ac.ir (Nima/Meteor) | `token`: Meteor resume token (~90 days, expiry tracked) |

- ✅ multiple accounts, used concurrently and independently
- ✅ credential on demand: fetch if none active, refresh if invalid
- ✅ no browser, no HTML scraping — raw HTTP against the real routes
- ✅ injectable debug logger
- ✅ library only — no runtime, no CLI required
- ✅ ESM, browser-bundlable, Node ≥ 22

## Install

```bash
npm install aut-cas-sso
```

## Quickstart

```js
import { SessionManager, createLogger, request } from 'aut-cas-sso';

const manager = new SessionManager({
  accounts: [{ id: 'main', username: 'student', password: 'secret' }],
  logger: createLogger({ level: 'debug' }),        // optional, silent by default
  encryptionKey: process.env.AUT_CAS_SESSION_KEY,  // optional, see "Persistence"
});

// One call: logs in, redeems the CAS ticket, stores the session.
const cred = await manager.getCredential('courses', 'main');

// Use it: cookie-based services…
const res = await request('https://courses.aut.ac.ir/my/', {
  headers: { cookie: Object.entries(cred.cookies).map(([k, v]) => `${k}=${v}`).join('; ') },
});

// …or the lms resume token:
const lms = await manager.getCredential('lms', 'main');
console.log(lms.token); // use as `{ resume: lms.token }` in a DDP `login` call

await manager.stop(); // flush persistence
```

`accountId` is **always explicit** — the manager never picks an account for
you, so multi-account setups stay deterministic:

```js
const a = await manager.getCredential('lmshome', 'alice');
const b = await manager.getCredential('lmshome', 'bob'); // independent session
```

## API

### `new SessionManager(options)`

| option | default | meaning |
|---|---|---|
| `accounts` | `[]` | `[{ id, username, password }]`, can also be added later |
| `store` | `new FileStore()` | persistence backend; `./.aut-cas-sessions.json` in cwd |
| `logger` | silent | object with `debug/info/warn/error(message, meta?)` |
| `encryptionKey` | `process.env.AUT_CAS_SESSION_KEY` | passphrase for stored passwords |
| `services` | courses/lmshome/samad/lms/food | adapter registry (bring your own) |
| `cas` | `{ baseUrl: 'https://accounts.aut.ac.ir/cas' }` | plus `tgtTtlMs`, `timeoutMs`, … |
| `probeIntervalMs` | `300000` | healthy sessions are re-probed at least this often |
| `expirySafetyMs` | `60000` | refresh this long before a known `expiresAt` |
| `fetchImpl` / `WebSocketImpl` | platform globals | inject for tests / exotic runtimes |

### Methods

```js
await manager.start();                 // optional; auto-runs on first use
await manager.getCredential(service, accountId); // -> Credential
await manager.probe(service, accountId);         // -> boolean (definitive only)
manager.invalidate(service, accountId);          // caller saw a 401 -> next call refetches
manager.getSessionInfo(service, accountId);      // sync snapshot, no network
manager.addAccount({ id, username, password });  // sync; persisted in background
manager.removeAccount(id);                       // drops account + sessions
manager.listAccounts();                          // never exposes passwords
await manager.flush();                           // await queued persistence
await manager.stop();
```

### Credential shape

```js
{
  service: 'courses',
  accountId: 'main',
  type: 'cookie' | 'token',
  cookies: { MoodleSession: '…', … } | null,  // cookie services
  token: '…' | null,                          // lms resume token
  header: null,                               // services define none today
  expiresAt: 1791494745651 | null,            // null = server-authoritative
  remainingMs: 43199877 | null,
  obtainedAt: 1791451545651,
}
```

### Errors (all extend `AutCasError`, stable `.code`)

| class | code | meaning |
|---|---|---|
| `InvalidCredentialsError` | `INVALID_CREDENTIALS` | CAS rejected username/password |
| `TgtInvalidError` | `TGT_INVALID` | TGT expired/revoked (auto re-login once, then surfaces) |
| `ServiceLoginError` | `SERVICE_LOGIN_FAILED` | service refused the ticket/session |
| `ReauthenticationRequiredError` | `REAUTH_REQUIRED` | session dead and no decryptable password |
| `UnsupportedEnvironmentError` | `UNSUPPORTED_ENVIRONMENT` | e.g. lms without `WebSocket` |
| `ConfigurationError` | `CONFIGURATION` | unknown service/account, missing accountId, … |

## How it works — the real routing (reverse-engineered, all verified live)

The whole module is raw HTTP. No browser, no form scraping:

```
1. POST https://accounts.aut.ac.ir/cas/v1/tickets   (username, password)
      -> 201 Created, Location: http://accounts.aut.ac.ir/cas/v1/tickets/TGT-…
         (http Location must be upgraded to https or the LB 301s you)
2. POST {TGT url}                                    (service=<service url>)
      -> 200 text/plain, body = single-use ST-… ticket
3. Service redeems ?ticket=ST-…  (each service differs — see below)
```

**courses (Moodle)** — service URL
`https://courses.aut.ac.ir/login/index.php?authCASattras=CASattras`
→ Moodle validates the ticket, hops through `?testsession=…` to `/my/`,
sets `MoodleSession` + `MOODLEID1_` (60-day sodium remember token — replaying
it can restore a session without spending a ticket).

**lmshome (Fararoom)** — service URL
`https://lmshome.aut.ac.ir/api/v1/auth/sso/callback/`
→ `200 {data:{user}}` + `sessionid` (Max-Age 43200 = 12h, tracked exactly) +
`csrftoken`. Probe: `GET /api/v1/auth/me/`.

**samad** — service URL `http://samad.aut.ac.ir/login/cas` (registered as
plain http!) but redeemed over https; the app then emits `http://` Location
headers behind an https load balancer, so every redirect is upgraded
(`upgradeInsecure`) or you loop forever. Probe: `GET /index/index.rose` —
anonymous responses embed the `j_security_check` login form, the dashboard
does not.

**food (سامانه تغذیه)** — service URL
`https://food.aut.ac.ir/Account/CasLogin` (the ASP.NET auth filter sends
every path through `/Account/Login` into CAS). Redeem walks
`CasLogin?ticket=…` → `/Home/index` → `/UserHome` →
`/UserHome/Index2?bypass=True` and collects `.AspNet.ApplicationCookie`
(the identity cookie), `DGAUTH` and `fn`. A rejected/replayed ticket
renders a 200 error page *at the food host* instead of bouncing to CAS, so
success additionally requires the identity cookie and actually entering the
app. Probe: `GET /Home/index` — dead sessions end on
`accounts.aut.ac.ir`. All auth cookies are session-scoped with no
-disclosed lifetime, so validity is probe-based.

**lms (Nima/Meteor)** — no direct CAS hook. The deployment reports
`settings.auth === "moodle"` and logs in through a custom OAuth provider
("u5auth") hosted by Moodle itself:

```
a. hold a Moodle session (the courses adapter fetches one via CAS),
b. GET https://courses.aut.ac.ir/local/oauth/login.php
       ?client_id=nima&response_type=code
       &redirect_uri=https://lms.aut.ac.ir/api/_oauth/u5auth&state=…
       (with Moodle cookies)          -> 302 with an authorization code
c. GET https://lms.aut.ac.ir/api/_oauth/u5auth?code=…&state=…
       -> HTML whose #config div carries credentialSecret
          (the Meteor server exchanges the code server-side),
d. DDP over wss://lms.aut.ac.ir/api/websocket:
       login { oauth: { credentialToken: state, credentialSecret } }
       -> { id, token, tokenExpires }  — the resume token (90-day expiry).
```

Step (d) needs a WebSocket. In environments without one, only the `lms`
service throws `UnsupportedEnvironmentError`; everything else keeps working.

## Validation policy — expiry + probe + retry

`getCredential()` decides in this order:

1. **Fresh** (redeemed/probed within `probeIntervalMs`) → return cached,
   zero network (verified: 0 ms).
2. **Hard expiry** known (`lmshome` 12h, `lms` tokenExpires) and inside
   `expirySafetyMs` → refresh without asking the network.
3. **Stale** → adapter probe:
   - definitive **false** → refresh,
   - **true** → keep serving, bump `lastValidatedAt`,
   - **transport error** → *not* proof of death: keep serving the cached
     session and log a warning.
4. Caller got a 401 from the service itself → `manager.invalidate(...)`,
   next `getCredential()` refetches.

(`lmshome` discloses a 12h cookie lifetime and `lms` a token expiry — both
track hard expiry; `courses`, `samad` and `food` are server-authoritative
and rely on probing.)

Concurrent `getCredential()` calls for the same service+account share a
single fetch (single-flight); CAS TGTs are shared per account with exactly
one automatic re-login retry when CAS reports the TGT dead.

## Persistence & encryption

Everything is always persisted (default `./.aut-cas-sessions.json`,
cwd-relative; pass `store: new FileStore('/elsewhere/x.json')` to change —
or `MemoryStore` / `LocalStorageStore` / any `{load, save}` object).

```json
{
  "v": 1,
  "accounts": { "main": { "username": "…", "password": { "alg": "AES-GCM", "kdf": {…}, "iv": "…", "ct": "…" } } },
  "sessions": { "courses::main": { "cookies": {…}, "expiresAt": null, "lastValidatedAt": 1791451545651 } }
}
```

- Passwords are encrypted with **AES-256-GCM** (PBKDF2-SHA256, 250k
  iterations) via WebCrypto — key from the `encryptionKey` option or
  `AUT_CAS_SESSION_KEY`.
- **No key configured** → sessions still persist, passwords are *skipped*
  with a logged warning, and refreshes fail later with
  `REAUTH_REQUIRED` (call `addAccount()` again to re-supply).
- CAS TGTs are memory-only by design: a restart performs one CAS login and
  then reuses the persisted service sessions (verified: restored in ~1 ms).
- The file is written atomically (tmp + rename) with mode `0600`.

**Security notes:** the session file contains live credentials for your
accounts — protect the key and the file. Prefer env vars over hardcoding
keys. Revoking access centrally (changing the password) invalidates
persisted sessions naturally.

## Logging

```js
import { createLogger, silentLogger } from 'aut-cas-sso';

createLogger({ level: 'debug' });            // console, [aut-cas-sso] prefix
createLogger({ level: 'info', sink: mySink }); // custom sink: (level, msg, meta) => …
// or pass any object with debug/info/warn/error; missing methods become no-ops.
```

Debug lines cover ticket minting, redeem/probe outcomes and timings,
refresh decisions, persistence; warnings cover missing keys, failed probes
and CAS re-logins. Passwords and full tokens are never logged.

## Using it from a browser / SPA

The package is plain ESM with **zero dependencies** and only lazy
`node:fs` imports inside `FileStore`, so bundlers (Vite, webpack, esbuild)
handle it without polyfills:

```js
import { SessionManager, LocalStorageStore } from 'aut-cas-sso';

const manager = new SessionManager({
  accounts: [{ id: 'me', username, password }],
  store: new LocalStorageStore(),   // browser persistence
});
```

Two platform caveats:

- `Set-Cookie` is not readable by browser `fetch` on cross-origin
  responses. Cookie-based services (`courses`, `lmshome`, `samad`, `food`)
  need Node, a same-site deployment, or a proxy that surfaces `Set-Cookie`.
  The `lms` token flow works wherever `fetch` + `WebSocket` exist.
- The AUT APIs must be reachable (CORS or proxy) from the page.

## Writing your own service adapter

```js
const myService = {
  id: 'mysvc', title: 'My service', requiresCas: true,
  serviceUrl: 'https://mysvc.example/login',   // exact URL registered at CAS
  async redeem({ ticket, jar, fetchImpl, logger }) {
    // GET serviceUrl + ?ticket=…, collect cookies into `jar`,
    // throw ServiceLoginError if no session was established
    return { cookies: jar.toJSON(), expiresAt: null, lastValidatedAt: Date.now(), meta: {} };
  },
  async probe({ state, fetchImpl, logger }) {
    // return false ONLY when you are sure the session is dead
    return true;
  },
  toCredential(state) { /* -> Credential (see types) */ },
};

new SessionManager({ services: { mysvc: myService }, … });
```

Adapters get `ensureSession(depId)` in `redeem` if they depend on another
service's session (that is exactly how `lms` uses `courses`).

## Development

```bash
npm test        # 68 unit tests, node:test, no network
npm run smoke   # opt-in live check of all five services
AUT_CAS_USER=… AUT_CAS_PASS=… AUT_CAS_SESSION_KEY=… npm run smoke
```

## License

MIT
