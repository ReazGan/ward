# Interpreting live-exposure-check results

What each check means, what a pass looks like, and the traps that cause false
alarms. The scan reports candidates; confirm a finding here before telling the
user it is real.

## Two traps that cause false alarms

Read these first, because they explain most wrong results.

1. The SPA fallback trap. A single-page app (and many static hosts) answers
   `200` with `index.html` for every path, including `/.env` and `/backup.zip`.
   A `200` status alone is not an exposed file. The scan already decides by
   content, not status: a `.env` is a finding only when the body has real
   `KEY=value` lines, a `.git/HEAD` only when the body starts with `ref:`. If
   you probe by hand, check the body, not the code.

2. The public-key trap. Some keys are meant to ship to the browser. A Stripe
   publishable key (`pk_live_...`, `pk_test_...`), a Supabase publishable key or
   anon JWT (a JWT whose role is `anon`), and a Firebase web `apiKey` are public
   by design. The scan counts them under "public keys in bundle" and does not
   report them. The real finding is a server-only key in the bundle: a Supabase
   `service_role` JWT or `sb_secret_`, a Stripe `sk_`/`rk_` secret key, an
   OpenAI, Anthropic, or AWS key, or a service-account JSON. For a public key the
   control is row level security, Firebase rules, or key restrictions, not
   secrecy, so do not tell the user to rotate it.

## bundle

Fetches the page and its same-origin scripts, then searches the page, the inline
data blobs (`__NEXT_DATA__`, `self.__next_f`), and every script for secrets.

- A `service_role` JWT, `sb_secret_`, or any provider secret key here is
  critical: anyone who loads the page has it. The user must move the call to a
  server they control and rotate the key.
- A publishable or anon key here is expected. See the public-key trap above.
- Nothing found means no secret-shaped value reached the client in what the scan
  could fetch. It does not prove a key is not loaded from a chunk the scan did
  not reach, so a clean result is "none seen", not a guarantee.

## files

Probes common sensitive paths (`/.env`, `/.env.local`, `/.git/HEAD`,
`/.git/config`, database dumps, backups, `.npmrc`) and decides by content.

- An exposed `.env` leaks every credential in it; an exposed `.git` lets anyone
  reconstruct the full source and history, including deleted secrets. Both are
  critical.
- A `200` with an HTML body is the SPA fallback, not an exposed file, and is not
  reported.
- The fix is to serve only a build or public directory, never the project root,
  and to deny dotfiles at the web server. If a file was exposed, assume it was
  downloaded and rotate anything it held.

## maps

Checks whether a bundle's `.js.map` is public. A body that starts with
`{"version":3` is a reachable source map; `sourcesContent` means the original
source text is included.

- This is an amplifier, not a breach by itself: it reveals source, comments, and
  internal routes that make other findings easier. Medium, or high when it
  includes the source text or leaks a secret.
- The fix is to stop emitting production browser source maps, or to upload them
  to the error tracker in CI and delete them from the deployed output.

## headers

Reports security response headers missing on the main page: Content-Security-
Policy, Strict-Transport-Security (HTTPS only), X-Content-Type-Options,
Referrer-Policy, X-Frame-Options, Permissions-Policy.

- This is defense in depth. Do not overstate it. Missing CSP, HSTS, or nosniff
  is medium; the rest are low.
- HSTS only applies over HTTPS, so the scan does not report it on an http
  localhost.
- Set them where the response is built: `headers()` in `next.config.js`,
  `helmet()` in Express, or the host for a static Vite, React or Next export
  build (`headers` in `vercel.json`, a `_headers` file on Netlify or Cloudflare
  Pages, `hosting.headers` in `firebase.json`, nginx `add_header ... always`).
  Start with `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  strict-origin-when-cross-origin` and `X-Frame-Options: DENY` (or CSP
  `frame-ancestors 'none'`), then add a CSP the app actually passes.
- An app builder's own preview domain may not let the app set headers; deploy
  to a host you control before judging this.

## cookies

Inspects Set-Cookie flags on the main page and, if the user points `--cookie-path`
at a login, on that response. With `--cookie-body` the scan POSTs that body to the
login, so use a test account.

- A session cookie without HttpOnly is readable by any script, so any XSS steals
  it. Without Secure it can travel over plain HTTP. `SameSite=None` sends it
  cross-site. Each is worth flagging.
- A non-session cookie missing a flag may be fine; this is why the finding asks
  you to confirm which cookie it is before you act.

## cors

Sends an arbitrary Origin and watches the response.

- The real finding is a response that reflects your arbitrary Origin (or `null`)
  together with `Access-Control-Allow-Credentials: true`. A site the user did
  not authorize can then read a logged-in user's responses. High when the app
  uses cookie auth.
- A fixed allow-list that returns its own trusted origin, not the one you sent,
  is correct and is not reported.
- A plain `Access-Control-Allow-Origin: *` without credentials is usually fine
  for a public, token-in-header API; the scan does not flag it on its own.

## debug

Asks for a path that should 404 and for the Vite dev client, then looks for
debug or dev-server fingerprints.

- A Django DEBUG page, a Werkzeug or Laravel debug page, or a dev server (Vite,
  Next.js) answering in production leaks source, settings, and stack traces, and
  a reachable Werkzeug console or vulnerable Laravel Ignition can run code.
- A normal 404 page with no fingerprint is a pass.

## webhook

Opt-in. Sends one forged, unsigned `checkout.session.completed` event, marked
paid, to the Stripe webhook path the user names. This is a POST: if the handler
does not verify it, the app runs its real fulfillment code (database writes,
emails, entitlements) for a fake session. Prefer a staging or test-mode
deployment.

- A 2xx response means the endpoint acts on events it never verified: anyone who
  knows the URL can grant themselves paid access or credits. Critical.
- Only a 400, 401, or 403 is a pass, and only from the handler itself.
- A 404, 405 or 501 means the path or method is wrong and the check proved
  nothing; a 3xx means the request went somewhere else. The scan lists these as
  inconclusive, not as a pass. Ask the user for the real route and re-run.
- A 500 can be a handler that fails closed because the secret is unset, or a
  crash after it acted on the event. The scan lists it as inconclusive; read the
  server log before calling it a pass.
- On a Supabase Edge Function, a 401 whose body mentions a missing or invalid
  JWT comes from the gateway (`verify_jwt` is on), not from the signature check.
  Stripe cannot call that function either; it needs `verify_jwt = false` and its
  own signature check, so this result proves nothing about verification.
- The fix is to verify every event with the signing secret and fail closed when
  the secret is unset.

## ratelimit

Opt-in. Sends a burst (`--n`, default 60, capped at 120) to the metered endpoint
the user names and counts the responses. Each call is a real request (POST by
default): on an LLM, SMS or email route it can cost money or send real
messages, so pick an endpoint whose calls are safe to repeat.

- No 429 in N requests, with the calls not all blocked by auth (401/403), means
  no limit at or below N per window, not no limit at all. Common defaults sit at
  or above the default burst: Laravel 10's default `api` limiter is 60 per
  minute, so 60 calls pass untouched. Before reporting, read the limiter config
  in the code, or re-run with `--n` above the configured limit (max 120).
- If the code has no limiter and the burst ran clean, an attacker can run up the
  bill (denial of wallet) or abuse the feature. Confirm the endpoint is actually
  metered before reporting.
- A 429 in the burst means a limiter is active (pass). All 401/403 means auth
  blocks first, so the logged-out burst cannot judge a limiter behind auth. Ask
  the user to put a test account's session token in an environment variable
  themselves and re-run with `--auth-bearer-env VAR` (the token never goes on
  the command line or into chat), or read the limiter config in the code.
- No 2xx and no 429 is inconclusive: a 400 or 422 means the probe body was
  refused (pass a valid one with `--ratelimit-body`), a 404 or 405 means the
  path or method is wrong.

## baas

Opt-in. Reads the user's own Supabase tables or Firebase collections logged out,
using the user's own anon or publishable key (never a secret key, and only ever
sent to the user's own project).

- Rows or documents returned to a logged-out request mean row level security
  (Supabase) or Security Rules (Firebase) are missing or open. This is the
  single highest-value finding in apps built this way. Critical.
- An empty array or a permission-denied response is good, but an empty array only
  proves the logged-out path is closed. With `--token-a` and `--token-b` the scan
  also checks that two different users do not see the same rows; confirm those
  rows are not meant to be shared before calling it a leak.
- The fix is in the database policies or rules, not the key. Rotating the anon
  key does nothing here.

LAST-VERIFIED: 2026-10-06
