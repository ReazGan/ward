# Expo and React Native

Everything inside an app binary is public. Anyone can unpack an APK or IPA and read its strings, and Hermes bytecode keeps strings readable. Each item ends with the false-positive check to do before you report it.

## Public env prefix

`EXPO_PUBLIC_*` variables are inlined as plain text into the compiled app. Expo's docs say not to store private keys there.

```ts
// fine: public values
const url = process.env.EXPO_PUBLIC_SUPABASE_URL
const anon = process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY
// wrong: a secret behind the public prefix, e.g. EXPO_PUBLIC_OPENAI_API_KEY
```

False positive: Supabase anon or publishable keys, the Firebase config, RevenueCat public SDK keys, a Sentry DSN and a OneSignal app id are public by design. Protect the data with RLS or Security Rules instead.

## Keys in app config

These all end up in the bundle or in the repo:

- `app.json` and `app.config.js` `extra`
- `env` blocks inside `eas.json` build profiles (committed)
- `react-native-config` and `react-native-dotenv` (`import { X } from '@env'`)
- string constants in app code

EAS secret visibility does not help a value that you embed in the app: it is still in the binary.

```js
// app.config.js: only public settings in extra
export default ({ config }) => ({ ...config, extra: { apiUrl: process.env.EXPO_PUBLIC_API_URL } })
```

False positive: `extra.eas.projectId`, public URLs and feature flags are fine.

## Provider calls from the app

A call from app code to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com` or `api.stripe.com` with a key means the key is in the app. Anyone can extract it and spend your money.

False positive: Stripe through `@stripe/stripe-react-native` with a publishable key is fine; the secret key stays on your server.

## Route through a backend

Put the provider call behind an endpoint you own, and authenticate and rate limit the user there.

```ts
// app/api/chat+api.ts (Expo Router API route, deployed to a server or EAS Hosting)
export async function POST(req: Request) {
  const user = await verifyUser(req.headers.get('authorization'))
  if (!user) return new Response('Unauthorized', { status: 401 })
  const { message } = await req.json()
  if (typeof message !== 'string' || message.length > 4000) return new Response('Bad request', { status: 400 })
  // per-user rate limit, then call the provider with process.env.OPENAI_API_KEY (no EXPO_PUBLIC_ prefix)
  return Response.json({ ok: true })
}
```

Other options: a Supabase Edge Function, a Firebase Cloud Function, or any small backend. The app sends the user's session token, never the provider key.

## App Check is not secrecy

Firebase App Check, Play Integrity and App Attest make abuse harder; they do not make an embedded key secret. Keep keys on the server and add attestation on top. For Gemini use Firebase AI Logic, which proxies the call, instead of a raw Gemini API key in the app.

False positive: App Check in front of Firestore or Storage is a good extra layer, not a finding.

## Release builds

- The production EAS profile must not set `"developmentClient": true`:

```json
{
  "build": {
    "development": { "developmentClient": true, "distribution": "internal" },
    "production": { "autoIncrement": true }
  }
}
```

- Strip `console.log` from release builds (for example `babel-plugin-transform-remove-console` in the production Babel env), so tokens never reach device logs.
- Do not ship debug menus, test accounts or staging API URLs in the production profile.

False positive: a development client in the `development` or `preview` profile is the normal setup.

## After a leak

A key that shipped in a binary stays in every installed copy until users update.

- Rotate it at the provider (rotation.md).
- Restrict Google keys by Android package and SHA-1 or iOS bundle id, plus API restrictions.
- Plan a forced update if the old key has to be deleted, because old app versions keep using it.

LAST-VERIFIED: 2026-10-06
