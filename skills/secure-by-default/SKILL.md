---
name: secure-by-default
description: "Write authentication, database access, secret handling, payments, file uploads, and LLM endpoints securely by default. Use whenever adding or editing login or sessions, Supabase or Firebase queries, API routes or Server Actions, environment variables or API keys, Stripe or checkout code, upload handlers, CORS, redirects, or a route that calls an LLM, even when the user does not mention security."
license: MIT
compatibility: "No scripts. Rules only."
metadata:
  author: ReazGan
  version: "0.1.0"
---
Paths in this file are relative to this skill's folder.

# Secure by default

Apply these rules, unasked, to every line you write or edit that touches auth, data, secrets, payments, uploads, outbound requests or a model call. It is cheap now and expensive to retrofit.

## Six laws

1. The browser is public. A secret, a price or an auth decision that reaches the client is already broken.
2. Deny by default. Every table, row, route and Server Action checks "is this this user's", not just "is someone logged in".
3. Never trust the request body for price, role, quantity, owner ids or verification flags. Take the user id from the verified session.
4. Verify every payment webhook signature and fail closed when the secret is unset.
5. Treat user input and model output as untrusted at every sink: HTML, SQL, shell, URL, file path.
6. Secrets live only on a server you control, never behind a public env prefix.

When a law blocks the quick fix, fix the cause:
- An env var undefined in the browser means the call belongs on the server. Do not add `NEXT_PUBLIC_` or `VITE_`.
- A CORS error means add the one origin that needs access, not every origin.
- An empty Supabase result means write the right policy, not `using (true)` or the service key.
- An SDK that refuses to run in the browser is right. Do not set `dangerouslyAllowBrowser` for a key you ship.

## Auth and data access

- Supabase: in the same change that creates a table, add `alter table <t> enable row level security;` and one policy per operation `to authenticated`, with `using ((select auth.uid()) = user_id)` and `with check ((select auth.uid()) = user_id)` on insert and update. Use `using (true)` only on truly public, read-only tables with no private columns.
- Never read `user_metadata` in a policy; users can edit it. Keep roles in `app_metadata`, a roles table the user cannot write, or Firebase custom claims (`request.auth.token.admin == true`).
- A Supabase `security definer` function lives in a schema the API does not expose and sets `search_path = ''`. A function only the server calls gets `revoke execute ... from public, anon, authenticated`; a grant to `service_role` alone locks nothing. Views over protected tables use `with (security_invoker = true)`.
- Firebase rules: `allow read, write: if request.auth != null && request.auth.uid == userId;` (or compare `resource.data.ownerUid`). Never ship `if true`, a bare `request.auth != null` on per-user data, or the test-mode date rule.
- Every query by an id from the request also filters by owner (`where: { id, userId: session.userId }`) or checks the row's owner before returning or changing it. Return 404 otherwise.
- Route handlers and Server Actions are public endpoints. Validate arguments and check auth and ownership inside each one; a page, layout or middleware check does not cover them (middleware or `proxy.ts` only redirects, CVE-2025-29927). In server code use `getClaims()` or `getUser()`, never `getSession()`.
- Admin checks run on the server against a server-side role. Client flags (`isAdmin`, localStorage) only hide buttons.
- Write allow-listed fields only: `const { title, body } = input`, then set `user_id` from the session. Never `insert(req.body)`, `Model(**data)`, `create($request->all())` or DRF `fields = '__all__'`.

More: `references/data-and-auth.md`.

## Secrets

- `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_`, `REACT_APP_`, `PUBLIC_`, `next.config` `env:`, Vite `define` and `app.json` `extra` all put the value in the shipped bundle. A secret never goes there; move the call to a server route, Edge Function or Cloud Function.
- Never create a Supabase client with `service_role` or `sb_secret_` in browser or app code, and never call `supabase.auth.admin` from the client.
- Public by design, leave them in the client: Stripe `pk_`, Supabase anon or `sb_publishable_`, Firebase web `apiKey`, Sentry DSN, PostHog `phc_`, reCAPTCHA and Turnstile site keys. RLS, rules and key restrictions protect them, not secrecy.
- Read secrets through a loader that throws when the variable is missing: no `|| 'secret'` or `?? 'dev-key'` fallbacks, no tutorial values. Generate signing secrets per environment (`openssl rand -base64 48`).
- A key the user pastes goes into the git-ignored `.env`, never into source; put a placeholder in `.env.example`. Never return or log `process.env` or `os.environ`.

More: `references/secrets.md`.

## Payments and metered endpoints

- The client sends a product or plan id. The server takes the price from its own catalog (`PRICES[plan]`) or a Stripe Price id. Never `amount`, `price` or `unit_amount` from the request.
- Webhooks: read the raw body (`await req.text()`, or `express.raw()` mounted before `express.json()`), call `stripe.webhooks.constructEvent(raw, sig, secret)`, return 500 when the secret is unset and 400 on a bad signature. Never wrap verification in `if (secret)`.
- Grant access from the webhook on `checkout.session.completed` and `checkout.session.async_payment_succeeded`, only when `payment_status` is not `unpaid` (ACH and SEPA complete unpaid), idempotently (unique session or event id, `on conflict do nothing`). A success page may call the same fulfill function after retrieving the session from Stripe, granting to its `client_reference_id`, never from client data.
- Every route that costs money (model calls, email, SMS, images) requires auth, a per-user rate limit and input size caps. OTP, signup and password-reset sends also get a per-destination throttle, a resend cooldown and a CAPTCHA.

More: `references/payments-and-abuse.md`.

## Uploads and server-side fetch

- Check file type from the content (magic bytes), allow-list extensions, re-encode images and cap the size (multer `limits.fileSize`). Never trust the extension or `Content-Type`.
- Store files under a random server-side name. Never put `originalname` in a path; if you must build one, `path.basename` it and verify the resolved path stays inside the upload root.
- Keep user files private (private bucket, per-user Storage rules) and serve them through signed URLs with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. Never serve user SVG or HTML inline.
- Fetching a user-supplied URL: https only and a host allow-list. If any host must work, resolve DNS and reject private, loopback and link-local addresses at connect time and again after every redirect. `next/image` `remotePatterns` lists exact hosts, never `**`.

More: `references/uploads-and-fetch.md`.

## LLM endpoints

- Call the model from the server with a server-only key. Require auth, a per-user rate limit, a prompt length cap and an output token cap. The server picks the model, system prompt and tools; never take them from the request.
- Render model output as text or through a sanitizer (react-markdown without `rehype-raw`, or DOMPurify). Never pass it raw to `dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `eval`, SQL or a shell.
- No keys, connection strings or access rules in the system prompt. Assume it leaks and enforce access in code.
- Tools run with the end user's permissions (an RLS-scoped client, read-only where possible), never `service_role`. Validate model-chosen arguments like user input.
- If one agent holds private data, reads untrusted content (web pages, emails, uploads, other users' text) and can act outward (send, post, write, fetch a URL), break one leg: drop the tool, or require human approval before the outward action.

More: `references/llm-endpoints.md`.

## Queries, rendering, redirects and config

- SQL: placeholders only (`$1`, `?`, Prisma tagged `$queryRaw`). Never interpolate input into `$queryRawUnsafe`, `whereRaw`, `.extra()`, f-strings or string concatenation. Sort columns and directions come from an allow-list.
- Mongo: cast input to scalars (`String(x)`) or schema-validate it, so an object cannot become a query operator.
- Shell: `execFile`, `spawn([...])` or `subprocess.run([...])` with an argument list. Never `exec`, `os.system` or `shell=True` with input.
- HTML: let the framework escape. Raw sinks (`dangerouslySetInnerHTML`, `v-html`, `{@html}`, Blade `{!! !!}`, Jinja `|safe`, `mark_safe`) only take sanitized strings.
- Redirects from `next`, `returnTo` or `redirect`: accept a path only if it starts with exactly one `/` and has no backslash, tab, CR or LF (browsers drop those and read `\` as `/`, so `/<tab>/evil.com` reaches `//evil.com`), else use a default. Or require `new URL(value, base).origin` to equal the base origin.
- CORS: an exact origin list from env. Never `origin: true`, a reflected `Origin` header or `allow_origins=["*"]` together with credentials.
- Cookies: `httpOnly`, `secure` in production, `sameSite: 'lax'`. Keep the framework's CSRF protection on and exempt only signature-verified webhooks; cookie-auth route handlers check `Origin` or a CSRF token.
- Production: debug off (`DEBUG`, `APP_DEBUG`, Flask `debug`), `NODE_ENV=production`, generic error bodies, and no request bodies, auth headers, tokens or passwords in logs.

More: `references/uploads-and-fetch.md` (SQL, Mongo, shell, HTML) and `references/payments-and-abuse.md` (CSRF, redirects).

## Handoff

Asked whether a built app is safe, or about to deploy: hand off to preflight-audit. Given the user's own running URL: hand off to live-exposure-check.
