# Payments and abuse

Fix patterns for code that moves money or spends it per call: Stripe and other gateways' webhooks, prices, fulfillment, paid API routes, message sends, CSRF and redirects. Each section ends with the false-positive note, the safe shape that must not be "fixed".

## Webhook signature

Verify every Stripe event against the raw body and the endpoint secret. Fail closed when the secret is missing. Never fall back to the parsed body.

Express (mount `express.json()` after this route, or skip it for this path):

```js
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return res.status(500).send('webhook secret not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret);
  } catch (err) {
    return res.status(400).send('bad signature');
  }
  handleEvent(event);              // only the verified event from here on
  res.json({ received: true });
});
```

Next.js App Router (`app/api/stripe/webhook/route.ts`):

```ts
export async function POST(req: Request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return new Response('misconfigured', { status: 500 });
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature') ?? '', secret);
  } catch {
    return new Response('bad signature', { status: 400 });
  }
  await handleEvent(event);
  return Response.json({ received: true });
}
```

Supabase Edge Function (`supabase/functions/stripe-webhook/index.ts`). Stripe sends no Supabase JWT, so turn the gateway check off for this one function: `[functions.stripe-webhook]` with `verify_jwt = false` in `supabase/config.toml`, or `--no-verify-jwt` on deploy. The signature is its auth:

```ts
Deno.serve(async (req) => {
  const secret = Deno.env.get('STRIPE_WEBHOOK_SECRET');
  if (!secret) return new Response('misconfigured', { status: 500 });
  let event;
  try {
    event = await stripe.webhooks.constructEventAsync(await req.text(), req.headers.get('stripe-signature') ?? '',
      secret, undefined, Stripe.createSubtleCryptoProvider());
  } catch {
    return new Response('bad signature', { status: 400 });
  }
  await handleEvent(event);
  return Response.json({ received: true });
});
```

- Flask, FastAPI, Django: `stripe.Webhook.construct_event(payload, sig_header, secret)` and return 400 on `stripe.error.SignatureVerificationError`. Read the secret with `os.environ["STRIPE_WEBHOOK_SECRET"]` so a missing value stops startup.
- Laravel Cashier only adds its signature middleware when `STRIPE_WEBHOOK_SECRET` is set, so set it in every environment.
- Prove it: a POST with `Stripe-Signature: t=1,v1=00` must get a 4xx (400 from a `constructEvent` handler, 403 from Cashier), never a 2xx. Test the real path with `stripe listen --forward-to localhost:3000/api/stripe/webhook` and `stripe trigger checkout.session.completed`.

False positive: verification may sit in a shared helper, in Cashier or in dj-stripe. A `constructEvent` whose result is ignored while the handler keeps reading `req.body` is still broken.

## Raw body

Stripe signs the exact bytes it sent. Parsing and re-serializing the body breaks the check, and the usual next "fix" is deleting it.

| Stack | Read the raw body |
|---|---|
| Express | `express.raw({ type: 'application/json' })` on the route, or `express.json({ verify: (req, _res, buf) => { req.rawBody = buf } })` and pass `req.rawBody` |
| Next.js App Router | `await req.text()`, never `req.json()` first |
| Next.js Pages Router | `export const config = { api: { bodyParser: false } }`, then read the stream into a Buffer |
| Flask / FastAPI / Django | `request.get_data()` / `await request.body()` / `request.body` |
| Laravel | `$request->getContent()` (Cashier does this) |

False positive: `express.json()` mounted after the webhook route, or one that skips the webhook path, is fine.

## Server-side prices

The client says what it wants (a plan key, product ids, quantities). The server decides what it costs.

```js
const PRICES = { pro: 'price_...', team: 'price_...' };   // or load from your DB
app.post('/checkout', requireAuth, async (req, res) => {
  const price = PRICES[req.body.plan];
  if (!price) return res.status(400).end();
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price, quantity: 1 }],
    client_reference_id: req.user.id,
    success_url: `${process.env.APP_URL}/billing?session_id={CHECKOUT_SESSION_ID}`,
  });
  res.json({ url: session.url });
});
```

- Cart: load each product by id and build `unit_amount` from the stored price, never from `item.price` in the request. Accept quantities only as positive integers with a maximum.
- Python: `price = CATALOG[body.plan]` before `stripe.checkout.Session.create(...)`. Laravel: `Product::findOrFail($request->integer('product_id'))->price`, never `$request->amount`.

False positive: donations, tips and top-ups are variable by design. Keep a server-side minimum and maximum, and credit what Stripe reports as paid (`amount_total`), not what was requested.

## Fulfill from the webhook

Grant access in the `checkout.session.completed` and `checkout.session.async_payment_succeeded` handlers, on the server. The success page shows status and never writes a plan, role or credits from client code. If it also fulfills for speed, it calls the same idempotent function, which asks Stripe:

```js
async function fulfillCheckout(sessionId) {
  const session = await stripe.checkout.sessions.retrieve(sessionId);
  if (session.payment_status === 'unpaid') return;
  const userId = session.client_reference_id;   // set when you created the session
  // record session.id and grant to userId once, see the next section
}
```

Grant to the user recorded on the session (`client_reference_id`, or `metadata.userId` you set), never to whoever opened the success page: the `session_id` in that URL can be shared or leaked. If the page shows details, also require that the signed-in user equals `client_reference_id`.

False positive: a success page that retrieves the session, checks `payment_status` and grants to `client_reference_id` before writing is fine, as long as the webhook also exists for users who close the tab.

## Idempotent fulfillment

Stripe delivers each event at least once and not in order. Record what you processed under a unique key (`create table processed_events (event_id text primary key)`), in the same transaction as the side effect.

```js
await db.tx(async (t) => {                          // pg-promise
  const first = await t.oneOrNone('insert into processed_events (event_id) values ($1) '
    + 'on conflict do nothing returning event_id', [event.id]);
  if (!first) return;                                // already handled
  await t.none('update profiles set credits = credits + $1 where id = $2', [100, userId]);
});
```

- node-postgres: run `BEGIN` and `COMMIT` on one client from `pool.connect()` and check the insert's `rowCount`. Prisma: create the processed row inside `prisma.$transaction` and treat error `P2002` as "already done".
- Supabase: supabase-js has no transactions. Put the insert (`on conflict do nothing`, then `if not found then return false; end if;`) and the grant in one SQL function, `revoke execute` on it from `public`, `anon` and `authenticated`, and call it from the webhook with `.rpc()`.
- Never mark an event processed before its work has committed. For slow work, record the event together with a job row (an outbox) that a worker retries, then return 2xx.
- Adding credits or balance needs the event id check. For state such as a plan, do not trust event order: on each subscription event retrieve the current Subscription from Stripe (or compare `event.created` with a stored timestamp) and set the plan from its status.

False positive: a unique constraint on the session or payment id in a migration, or an upsert keyed on it, already makes the handler safe.

## Other payment gateways

Razorpay, SSLCommerz, Paystack, PayPal, iyzico, Shopier and the rest follow the same rules.

- Create the payment from your own pending order: the client sends product ids, the server computes and stores the amount, then sends that amount to the gateway.
- Verify every callback before writing: the gateway's signature with a secret that fails closed (`if (!secret)` return 500, never `env || ''`) and a constant-time compare, or the gateway's validation API.
- Bind it to the order: the order id and amount in the verified data must equal your stored pending order, and that order must belong to the caller. A valid payment for a cheap order must not mark an expensive one paid.
- Prefer the gateway's server-to-server webhook or IPN over the browser's return call, and fulfill idempotently on the gateway's payment id.

False positive: handlers that look the order up from the gateway's own verified response, or compare the amount in a shared helper.

## Metered and LLM routes

Every route that costs money per call (LLM, image generation, SMS, email, geocoding) needs a server-side session check, a per-user and per-IP limit, input and output caps, and a provider-side budget.

```ts
import { Ratelimit } from '@upstash/ratelimit';
const rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(20, '1 m') });

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { success } = await rl.limit(`chat:${session.user.id}`);
  if (!success) return new Response('Too Many Requests', { status: 429 });
  const { prompt } = await req.json();
  if (typeof prompt !== 'string' || prompt.length > 4000) return new Response('Bad Request', { status: 400 });
  // call the provider with a server-side key and a max output token cap
}
```

- Express: `express-rate-limit` on the route plus your auth middleware. FastAPI: a `slowapi` limiter plus `Depends(get_current_user)`. Laravel: `Route::middleware(['auth', 'throttle:20,1'])`. Server Actions are public POST endpoints: check the session inside each one, a page-level check does not cover them.
- Set a monthly spend limit and alerts in the provider console as the backstop. Keep the key on the server, never behind `NEXT_PUBLIC_`, `VITE_` or `EXPO_PUBLIC_`.

False positive: a middleware or gateway that already requires login for the route (check that its matcher really includes the path), a key the user supplies for their own account, and local models.

## OTP, SMS and email sends

A form that sends an SMS or email to an address the visitor types is a target for SMS pumping and email bombing.

- Limit per IP, per account and per destination, with a resend cooldown (for example 60 seconds) and a daily cap.
- Put a CAPTCHA or attestation in front of the send and verify it on the server (Turnstile or reCAPTCHA siteverify, Firebase App Check).
- Allow only the countries you serve (Twilio Geo Permissions, Firebase or Identity Platform SMS regions).
- Prefer a managed fraud filter (Twilio Verify Fraud Guard) over a homemade blocklist, and alert on spikes.
- In code: verify the CAPTCHA token, then call the limiter once with `otp:ip:${ip}` and once with `otp:to:${phone}` (same `Ratelimit` as above), return 429 when either fails, and only then call the provider.
- Supabase Auth limits its own email and SMS sends. Raising those limits, or moving to custom SMTP or SMS, means adding your own controls.

False positive: sends behind login, to an address loaded from your own DB, or to a fixed admin inbox are lower risk.

## CSRF

Cookie-authenticated routes that change state must reject cross-site requests. Bearer tokens in an `Authorization` header are not CSRF-prone.

- Django, Laravel, Flask-WTF: keep the built-in protection on. Exempt only webhook routes that verify their own signature.
- Express: `csurf` is deprecated. Use a maintained synchronizer-token or session-bound double-submit library, or check Fetch Metadata and Origin on every unsafe method:

```js
const APP_ORIGINS = new Set((process.env.APP_ORIGINS || '').split(',').filter(Boolean));
app.use((req, res, next) => {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.path.startsWith('/api/stripe/webhook')) return next();   // checked by signature
  const site = req.get('sec-fetch-site');
  const origin = req.get('origin');
  if (site === 'cross-site') return res.status(403).end();
  if ((site === 'same-site' || (!site && origin)) && !APP_ORIGINS.has(origin)) return res.status(403).end();
  next();
});
```

- `same-site` also covers sibling subdomains such as `app.example.com` calling `api.example.com`; allow it only for the frontend origins you list in `APP_ORIGINS`.
- Session cookie flags as defense in depth: `httpOnly: true, secure: true, sameSite: 'lax'`. SameSite alone is not enough across browsers.
- Next.js Server Actions compare Origin with Host for you. Route Handlers do not; add the check above to cookie-authenticated ones.

False positive: webhook routes are correctly exempt, and JSON APIs that only accept a bearer token need no CSRF token.

## Open redirects

Follow a `next`, `returnTo` or `redirect` value only when it is a path on your own site: one leading `/`, not `//` or `/\`, and no backslash or control character anywhere (browsers drop tabs and newlines and read `\` as `/`, so `/<tab>/host` becomes `//host`). Otherwise use a default, or check it against an allowlist.

```js
function safeNext(value, fallback = '/dashboard') {
  if (typeof value !== 'string' || !/^\/(?![\/\\])/.test(value) || /[\x00-\x1f\x7f\\]/.test(value)) return fallback;
  return value;
}
res.redirect(safeNext(req.query.next));
```

- Or parse and compare (in a `try`, `new URL` throws on bad input): `const u = new URL(value, 'https://placeholder.invalid')`, reject unless `u.origin === 'https://placeholder.invalid'`, then redirect to `u.pathname + u.search + u.hash`.
- Django: `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()}, require_https=request.is_secure())`.
- Flask: accept a value only if it starts with a single `/`, the second character is not `/` or `\`, it holds no backslash or control character, and `urlsplit(value)` shows no scheme or netloc. A netloc check alone lets `/\host` through.
- Allowlists: compare the parsed origin or an exact path. `url.includes(allowed)` accepts any URL that merely contains the allowed value.
- Laravel: `redirect()->intended('/dashboard')` uses the session. Run a query value through the same check before `redirect()->to()`.
- `new URL(next, origin)` does not help: an absolute or `//host` value replaces the origin. `${origin}${next}` is safe only after the `startsWith('/')` check; without it, a value starting with `.` or `@` changes the host.

False positive: constant targets, allowlisted paths, and a parameter that is only passed on as a query value inside another URL.

LAST-VERIFIED: 2026-10-06
