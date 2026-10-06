# Secrets

Rule of thumb: a secret only lives on a server you control. The browser or the app calls your server, your server checks the user, then calls the provider. Each section ends with the false-positive note, the safe shape that must not be "fixed".

## Public env prefixes

These prefixes copy the value into the JavaScript that ships to every visitor at build time. Renaming a variable to one of them is the usual way a secret leaks.

| Prefix | Framework | Exposed through |
|---|---|---|
| `NEXT_PUBLIC_` | Next.js | inlined into client bundles at `next build` |
| `VITE_` | Vite, Laravel + Vite, Lovable and Bolt exports | `import.meta.env` in client code |
| `REACT_APP_` | Create React App | `process.env` in the bundle |
| `EXPO_PUBLIC_` | Expo | plain text in the compiled app |
| `PUBLIC_` | SvelteKit, Astro | `$env/static/public`, `import.meta.env` |
| `NUXT_PUBLIC_` | Nuxt | `runtimeConfig.public` |
| `GATSBY_`, `VUE_APP_` | Gatsby, Vue CLI | the bundle |

The trap: a client component reads `process.env.OPENAI_API_KEY`, gets `undefined`, and the quick fix is `NEXT_PUBLIC_OPENAI_API_KEY`. The right fix is to keep the name unprefixed and move the call to server code (see "Call third-party APIs from server code"). A secret behind one of these prefixes is leaked once it has been built and deployed: rotate it, a new build does not recall the old one.

Mobile: `react-native-config`, `react-native-dotenv` (`@env`), `app.json` / `app.config.*` `extra` and every `EXPO_PUBLIC_` value end up inside the app binary. An EAS environment variable reaches the binary only when app code or app config reads it; a non-public variable used only by the build job (for example `SENTRY_AUTH_TOKEN` for source map upload) stays on EAS. EAS "secret" visibility does not help once a value is embedded.

False positive: publishable, anon and site keys are meant to be public (next section). A prefix the project's framework does not expose (a `VITE_` name in a Next.js app) is not public.

## Public by design

Leave these in client code. Protect the data behind them with the control in the last column, not with secrecy.

| Value | Shape | What actually protects you |
|---|---|---|
| Stripe publishable key | `pk_live_...`, `pk_test_...` | server-side prices and webhook checks |
| Supabase publishable or anon key | `sb_publishable_...`, a JWT with role `anon` | RLS on every table |
| Firebase web config | `apiKey: "AIza..."`, `authDomain`, `projectId` | Security Rules, App Check, API key restrictions |
| Google Maps browser key | `AIza...` | HTTP referrer or app restrictions plus API restrictions |
| Sentry DSN, PostHog key | `https://...@...ingest.sentry.io/...`, `phc_...` | rate limits on the provider side |
| Mapbox public token | `pk.` (an `sk.` token is secret) | URL restrictions |
| reCAPTCHA, Turnstile, hCaptcha site key | site key only | the secret key, verified on your server |
| Algolia search-only key, Pusher app key | search key, app key | the admin key and Pusher secret stay on the server |

Check the value, not only the name. A Supabase JWT with role `service_role` is a secret even when the variable says ANON; decode the middle part (base64url JSON) locally to see the role, never paste it into a website. A Google `AIza` key is only harmless while it is restricted. Never ship an unrestricted key, and never add the Gemini (Generative Language) API to the allowed APIs of a key that ships to clients: once that API is enabled anywhere in the project, an unrestricted key can call it on your bill. Firebase AI Logic needs the API enabled in the project, which is fine while the client key stays restricted to Firebase APIs (keys Firebase creates since May 2024 start out restricted that way).

## Bundler config that inlines env

These copy values into the bundle whatever the variable is called:

- Next.js `env: { ... }` in `next.config.*` (every key, prefix or not), and `publicRuntimeConfig` on Next.js 15 and older (removed in 16).
- Vite `define: { 'process.env.X': ... }`, and `loadEnv(mode, dir, '')` with the empty third argument, which loads every variable, not only `VITE_` ones.
- webpack `DefinePlugin` / `EnvironmentPlugin`, Nuxt `runtimeConfig.public`, Expo `app.config.*` `extra`.

```js
// vite.config.ts: loadEnv without the third argument loads VITE_ names only; inline public values only
const env = loadEnv(mode, process.cwd())
export default defineConfig({ define: { __APP_VERSION__: JSON.stringify(process.env.npm_package_version) } })
// next.config.mjs: server secrets need no config at all, route handlers read process.env directly
```

False positive: public values (site URL, `NODE_ENV`, version strings, publishable keys) in these blocks are fine. `serverRuntimeConfig` (Next.js 15 and older) stays on the server; on Next.js 16 read server secrets from `process.env` in server code.

## Call third-party APIs from server code

The OpenAI and Anthropic SDKs refuse to run in a browser until `dangerouslyAllowBrowser: true` is set, and Anthropic's API needs the `anthropic-dangerous-direct-browser-access` header. Setting either to clear the error ships the key. The same goes for `fetch('https://api.openai.com/...')` or any email, SMS or payment API called from a component or an Expo screen.

Next.js route handler:

```ts
// app/api/chat/route.ts
import 'server-only'
import OpenAI from 'openai'
import { auth } from '@/lib/auth'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

export async function POST(req: Request) {
  const session = await auth()
  if (!session) return new Response('Unauthorized', { status: 401 })
  const { message } = await req.json()
  if (typeof message !== 'string' || message.length > 4000) return new Response('Bad request', { status: 400 })
  // per-user rate limit here
  const r = await openai.responses.create({ model: 'gpt-4.1-mini', input: message, max_output_tokens: 500 })
  return Response.json({ text: r.output_text })
}
```

Vite or Lovable SPA on Supabase: put the call in an Edge Function and call it with `supabase.functions.invoke('chat', { body: { message } })`, which sends the user's JWT.

```ts
// supabase/functions/chat/index.ts
import { withSupabase } from 'npm:@supabase/server@1'
import { Ratelimit } from 'npm:@upstash/ratelimit@2'
import { Redis } from 'npm:@upstash/redis@1'

function requiredEnv(name: string): string {
  const v = Deno.env.get(name)
  if (!v) throw new Error(`Missing required env var ${name}`) // fail at boot, never send "Bearer undefined"
  return v
}
const OPENAI_API_KEY = requiredEnv('OPENAI_API_KEY')
const limiter = new Ratelimit({
  redis: new Redis({ url: requiredEnv('UPSTASH_REDIS_REST_URL'), token: requiredEnv('UPSTASH_REDIS_REST_TOKEN') }),
  limiter: Ratelimit.slidingWindow(20, '1 m'),
})

export default {
  // auth: 'user' verifies the caller's JWT; requests without a valid session never reach the handler
  fetch: withSupabase({ auth: 'user' }, async (req, ctx) => {
    const userId = ctx.userClaims?.id
    if (!userId) return new Response('Unauthorized', { status: 401 })
    const { success } = await limiter.limit(`chat:${userId}`)
    if (!success) return new Response('Too many requests', { status: 429 })
    const body = await req.json().catch(() => null)
    const message = body?.message
    if (typeof message !== 'string' || !message || message.length > 4000) return new Response('Bad request', { status: 400 })
    const r = await fetch('https://api.openai.com/v1/responses', {
      method: 'POST',
      headers: { Authorization: `Bearer ${OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'gpt-4.1-mini', input: message, max_output_tokens: 500 }),
    })
    if (!r.ok) {
      console.error('chat upstream failed', { userId, status: r.status }) // no prompt text, no provider body
      return new Response('Upstream error', { status: 502 })
    }
    const data = await r.json()
    const text = data.output?.find((o: { type: string }) => o.type === 'message')?.content?.[0]?.text ?? ''
    return Response.json({ text }) // only the answer, never the provider's raw response
  }),
}
```

Set the keys with `supabase secrets set OPENAI_API_KEY=...` (and the Upstash pair). Do not build the user client from the legacy `SUPABASE_ANON_KEY`: projects created since November 2025 do not have it, and it stops working once legacy keys are disabled (removal is planned for late 2026). `withSupabase` (from `@supabase/server`) verifies the caller and handles the project keys itself, so no key appears in the function code; `llm-endpoints.md` has the full checklist for metered routes. Expo: the same idea, an Expo Router API route, a Cloud Function or any small backend. App Check and Play Integrity reduce abuse but do not make an embedded key secret.

False positive: bring-your-own-key tools, where each user types their own key at runtime and it stays in their browser, may use `dangerouslyAllowBrowser`. The finding is a key from the build or the source.

## Admin keys stay on the server

- `supabase.auth.admin.*` only works with the `service_role` or `sb_secret_` key, and that key bypasses RLS. Never in browser or app code.
- `firebase-admin` and service account JSON files grant full access to the project. Never import them in client code and never put the JSON in `public/`, `static/` or `src/`.

```ts
// lib/supabase-admin.ts
import 'server-only'
import { createClient } from '@supabase/supabase-js'
export const admin = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!, {
  auth: { persistSession: false },
})
// use it only in route handlers or Server Actions that first check the caller is an admin on the server
```

Firebase: run admin work in Cloud Functions with `initializeApp()` and the default service account, or point `GOOGLE_APPLICATION_CREDENTIALS` at a key file outside the repo. Delete any key file that was committed or served, then create a new one.

False positive: the same calls in an API route, a Server Action, an Edge Function, a Cloud Function or a module with `import 'server-only'` are correct.

## Never send the environment

Do not return `process.env`, `os.environ`, `app.config`, `settings`, `phpinfo()` or `$_ENV` from an endpoint, and do not hand them to a page as props. In Next.js, props of a client component, `getServerSideProps` props and the RSC payload all reach the browser.

```js
// Express: an explicit allow-list of public values
app.get('/api/public-config', (req, res) => {
  res.json({ supabaseUrl: process.env.SUPABASE_URL, stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY })
})
```

Flask and FastAPI: return named public values (`jsonify(supabase_url=os.environ["SUPABASE_URL"])`), never `dict(os.environ)`. Next.js: pass the client only the fields it shows (a small object, not the DB row or `process.env`). Keep modules that read secrets behind `import 'server-only'`. Never render `{{ config }}` in Jinja or dump `settings` into a Django template.

False positive: `!!process.env.OPENAI_API_KEY` in a health check only sends a boolean. A secret passed to `jwt.sign` or an HMAC whose result is returned is used, not sent.

## Fail closed on missing env

A fallback like `process.env.JWT_SECRET || 'secret'` quietly becomes the production key the day the variable is missing. Read secrets through a loader that stops the app instead.

```ts
// lib/env.ts
export function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`Missing required env var ${name}`)
  return v
}
export const JWT_SECRET = required('JWT_SECRET')
```

```python
# pydantic-settings: no default for secrets, startup fails when one is unset
from pydantic import SecretStr
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    secret_key: SecretStr
    openai_api_key: SecretStr

settings = Settings()   # without pydantic: SECRET_KEY = os.environ["SECRET_KEY"]
```

```php
// Laravel config/services.php: no literal second argument for secrets
'stripe' => ['secret' => env('STRIPE_SECRET')],
```

Docker Compose: `JWT_SECRET: ${JWT_SECRET:?set JWT_SECRET}` fails instead of `${JWT_SECRET:-changeme}`.

A key the user pastes goes into a git-ignored `.env` (`.gitignore`: `.env`, `.env.*`, `!.env.example`), never into source. Check first: `git check-ignore .env` must print the file name, and `git ls-files .env` must print nothing (exports from Lovable and Bolt often commit `.env` with only public values; then add it to `.gitignore` and run `git rm --cached .env` before writing a server secret, or use `supabase secrets set` and the host's env settings). Put a placeholder in `.env.example`.

False positive: defaults for non-secrets (`PORT || 3000`, a localhost URL) are fine, and so is a dev-only fallback the code refuses when `NODE_ENV` is production.

## Signing secrets

JWT secrets, session and cookie secrets, `SECRET_KEY`, `NEXTAUTH_SECRET` / `AUTH_SECRET`, Laravel `APP_KEY`: anyone who knows the value can forge a login. Values from tutorials and READMEs are public: `keyboard cat`, `django-insecure-...` keys from `startproject`, the FastAPI JWT tutorial key, `secret`, `changeme`, and the example JWT secret in Supabase's self-hosting `.env.example` (decoded keys with `"iss": "supabase-demo"` mean the demo keys are still in use).

Generate one per environment, at least 32 random bytes, and keep it out of the repo:

```bash
openssl rand -base64 48
python -c "import secrets; print(secrets.token_urlsafe(64))"
php artisan key:generate
python -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"
```

If a signing secret was ever committed, shipped or shared between environments, replace it (users get logged out, that is expected). Do not keep the leaked value in a fallback or "previous keys" list.

False positive: throwaway keys in test settings, `conftest.py` or a dev-only settings module are fine when production never loads them; check `DJANGO_SETTINGS_MODULE` or the app factory. A `SESSION_KEY = 'cart'` that names a session field is not a signing key.

LAST-VERIFIED: 2026-10-06
