# Express and Node

Fixes for Express and plain Node servers. Each item ends with the false-positive check to do before you report it.

## Static files

Serve one dedicated folder, never the project root.

```js
const path = require('path')
app.use(express.static(path.join(__dirname, 'public'), { dotfiles: 'ignore' }))
```

- Express 4 (send 0.x) only hides a path whose last part starts with a dot: `/.env` is hidden, but `/.git/config` and `/.git/HEAD` are served from a root folder. Express 5 ignores all dotfile paths by default. Files such as `server.js`, `package.json` and `db.sqlite` are served by both.
- Flask: keep the default `static/` folder. FastAPI: `StaticFiles(directory="static")`. Never `send_from_directory('.', path)` with a path from the URL.
- Firebase Hosting: `"public": "dist"` (the build folder), not `"."`.
- nginx in Docker: copy only the build output (`COPY --from=build /app/dist /usr/share/nginx/html`) and add a `.dockerignore` with `.env*`, `.git` and `*.pem`.
- nginx backstop:

```nginx
location ~ /\.(?!well-known) { deny all; }
location ~* \.(sql|sqlite|bak|env|log|pem|key)$ { deny all; }
```

If `.env` or `.git` was ever reachable, assume the repo was cloned and rotate every secret in it (rotation.md).

False positive: `express.static('dist', { dotfiles: 'allow' })` is sometimes needed for `.well-known`; it is fine when the folder holds only build output.

## Directory listing

`serve-index`, nginx `autoindex on`, Apache `Options Indexes` and Caddy `file_server browse` print a clickable list of every file in a folder. Logs, backups, key files and other users' uploads that land there later become one click away.

- Remove the listing middleware. `express.static(dir)` serves files by exact name and never lists a folder; put real access checks in front of anything private.
- nginx: `autoindex off;` (the default). Apache: `Options -Indexes`. Caddy: drop `browse`.
- Keep logs, keys and backups outside every served folder; if any was listed, rotate what it held (rotation.md).

False positive: a listing of a folder that only ever holds public downloads is a design choice. Check what the folder holds on the server.

## Production mode

Run Node with `NODE_ENV=production`. In any other mode Express's default error handler sends `err.stack` to the client, and view caching is off.

```dockerfile
ENV NODE_ENV=production
CMD ["node", "server.js"]
```

PM2: `env_production: { NODE_ENV: 'production' }` and start with `--env production`. On a PaaS, set it in the dashboard.

False positive: Heroku's Node buildpack and many hosts set it for you. Check the host settings before reporting.

## Error handler

Add a final error handler that logs on the server and returns a generic message.

```js
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err)
  console.error(err) // server side only
  const status = err.status && err.status < 500 ? err.status : 500
  res.status(status).json({ error: status < 500 ? 'Bad request' : 'Internal server error' })
})
```

Next.js route handlers, Flask and FastAPI: catch, log with `logger.exception`, return a generic body. Never return `err.stack` or `traceback.format_exc()`.

The `errorhandler` package is for development only: it sends the full stack trace to the client. Mount it behind a check: `if (process.env.NODE_ENV === 'development') app.use(errorhandler())`.

False positive: a stack sent only when `NODE_ENV === 'development'` is fine as long as production sets `NODE_ENV`.

## Helmet

```js
const helmet = require('helmet')
app.use(helmet()) // CSP, HSTS, nosniff, frame-ancestors, Referrer-Policy
```

If an inline script breaks under the default CSP, move it to a file or allow it with a nonce instead of `contentSecurityPolicy: false`. Having `helmet` in `package.json` does nothing until `app.use(helmet())` runs; check it is not commented out.

False positive: a reverse proxy (nginx, Caddy, the host) may already set the headers. A JSON-only API needs fewer of them.

## Cookie flags

`res.cookie` defaults to `httpOnly: false` and `secure: false`, and so does Next.js `cookies().set`. express-session defaults `cookie.secure` to false.

```js
app.set('trust proxy', 1) // behind a TLS proxy, so secure cookies are still sent
app.use(session({
  secret: required('SESSION_SECRET'), // throws when the env var is missing
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 8 * 3600 * 1000 },
}))
res.cookie('session', id, { httpOnly: true, secure: true, sameSite: 'lax' })
```

Use `sameSite: 'none'` only when the frontend is on another site and CSRF is handled. Better: put the API on the same site (`api.example.com`, or a same-origin `/api` rewrite) and keep `lax`.

False positive: theme or locale cookies, and CSRF tokens that JavaScript must read (`XSRF-TOKEN`), do not need httpOnly.

## CORS with credentials

Reflecting any Origin together with credentials lets any site read a logged-in user's data. Use an exact allowlist.

```js
const allowed = new Set((process.env.CORS_ORIGINS || '').split(',').filter(Boolean))
app.use(cors({ origin: (origin, cb) => cb(null, !origin || allowed.has(origin)), credentials: true }))
// !origin lets non-browser clients through; CORS never authenticated them anyway
```

- Never `origin: true` with `credentials: true`, never a callback that always allows, never an unanchored regex (`/example\.com/` also matches a lookalike domain). Anchor it: `/^https:\/\/app\.example\.com$/`.
- Manual headers: echo the Origin only after an allowlist check, and send `Vary: Origin`.
- Never allow the `null` origin.

False positive: `Access-Control-Allow-Origin: *` without credentials is fine for a public or bearer-token API. `origin: '*'` with credentials is broken, not readable: a simple request still carries the cookies, but the browser will not let the page read a credentialed response whose `Access-Control-Allow-Origin` is `*` (CSRF is a separate question). If auth uses only the Authorization header, the impact is lower.

## Webhook raw body

Stripe signature checks need the raw body. Mount the webhook route with `express.raw` before `express.json()`.

```js
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET
  if (!secret) return res.status(500).send('webhook secret not configured') // fail closed
  let event
  try { event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret) }
  catch (e) { return res.status(400).send('bad signature') }
  res.json({ received: true }) // then act on event, not on req.body
})
app.use(express.json()) // after the webhook route
```

Next.js route handlers read the body with `await req.text()` before verifying.

False positive: a handler that verifies with `constructEvent` and acts only on the returned `event` is correct.

## Logging

Log ids and outcomes, never payloads, headers or the environment.

```js
const logger = require('pino')({
  redact: ['req.headers.authorization', 'req.headers.cookie', '*.password', '*.token'],
})
logger.info({ userId, route: req.path, status: res.statusCode })
```

Remove `console.log(req.body)`, `console.log(req.headers)` and `console.log(process.env)` before deploy (a `no-console` lint rule on server code helps). Rotate any key that reached the logs. A password printed by a seed or admin script is usually also hardcoded in it: rotate it and read it from env.

False positive: logging that a value exists (`hasAuth: !!req.headers.authorization`), its length, or a hash or fingerprint of it is fine. So is a log inside `if (process.env.NODE_ENV === 'development')`. Output of a local script or emulator matters less than server logs, but CI keeps it.

## Dev server in production

Production runs the built app, not the dev server. Dev servers ship debug endpoints, unminified source and reload sockets. Vite's dev server exposed with `--host` has had a long series of file-read bypasses, from CVE-2025-30208 (March 2025) to CVE-2026-53571 (June 2026, Windows paths; fixed in 8.0.16, 7.3.5 and 6.4.3, with no 5.x or 4.x fix). Upgrading closes the known ones, not the class: never deploy the dev server.

| Stack | Dev command (do not deploy) | Production command |
|---|---|---|
| Next.js | `next dev`, `npm run dev` | `next build`, then `next start` (or the platform) |
| Vite / React SPA | `vite`, `vite --host` | `vite build`, then serve `dist/` from static hosting |
| Create React App | `react-scripts start`, `npm start` | `react-scripts build`, then serve `build/` |
| Django | `manage.py runserver` | `gunicorn project.wsgi` |
| Flask | `flask run`, `app.run()` | `gunicorn app:app` |
| FastAPI | `uvicorn --reload` | `uvicorn main:app`, or gunicorn with uvicorn workers |
| Laravel | `php artisan serve` | php-fpm behind nginx or Apache, docroot `public/` |
| Expo | `expo start`, a development client | `eas build --profile production` without `developmentClient` |

False positive: `Dockerfile.dev`, `docker-compose.override.yml`, `Procfile.dev` and dev containers are meant for local work.

LAST-VERIFIED: 2026-10-06
