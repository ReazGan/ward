# Next.js

Fixes for Next.js findings. Each item ends with the false-positive check to do before you report it.

## Public env prefix

Anything named `NEXT_PUBLIC_*` is inlined into the JavaScript sent to the browser at build time. It is public, whatever file it came from.

- Keep secrets unprefixed and read them only in server code: route handlers, Server Actions, server components, and `lib/` modules that import `server-only`.
- If a client component needs data from a paid or secret API, call your own route handler and let it call the provider.

```ts
// lib/env.ts
import 'server-only'
export function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`Missing env var ${name}`)
  return v
}
```

False positive: `NEXT_PUBLIC_SUPABASE_ANON_KEY`, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY`, a Stripe publishable key (`pk_...`), the Firebase web `apiKey` and analytics ids are public by design. Check the value (decode the JWT role, check the prefix) before calling it a leak.

## Next config env

Values listed under `env` in `next.config.*` are always inlined into the client bundle, with or without the prefix. `publicRuntimeConfig` (Next 15 and older; removed in Next 16) reaches the browser too.

```js
// next.config.js: delete secrets from env and read them on the server instead
module.exports = {
  // env: { OPENAI_API_KEY: process.env.OPENAI_API_KEY },
}
```

```ts
// app/api/chat/route.ts
const key = process.env.OPENAI_API_KEY // server only
```

Rotate any secret that was listed there: it already shipped in old builds and CDN caches (rotation.md).

False positive: entries that hold public values (site URL, publishable keys) are fine. `serverRuntimeConfig` (Next 15 and older) stays on the server; Next 16 removed both runtime configs, so read server values from unprefixed env vars instead of moving them there.

## Server Actions are public

Every exported function in a `'use server'` file is a public POST endpoint. A page-level auth check does not protect the actions defined on that page.

```ts
'use server'
export async function deletePost(id: unknown) {
  if (typeof id !== 'string') throw new Error('bad id')     // arguments are hostile
  const { userId } = await verifySession()                   // auth inside the action
  const post = await db.post.findUnique({ where: { id } })
  if (!post || post.authorId !== userId) throw new Error('forbidden') // ownership
  await db.post.delete({ where: { id } })
}
```

Server Actions get a built-in Origin check against CSRF (`experimental.serverActions.allowedOrigins` widens it; a request with no Origin header is let through with a warning). Route handlers do not: protect cookie-auth route handlers yourself.

False positive: an action that only reads public data needs no auth.

## Middleware and proxy

Next 16 renamed `middleware.ts` to `proxy.ts` (exporting `proxy`, on the Node runtime); `middleware.ts` still works but is deprecated. Either file is for optimistic redirects only. Enforce auth again next to the data: in the data access layer, each route handler and each Server Action.

- In server and proxy code use `supabase.auth.getClaims()` or `getUser()`, not `getSession()`, which reads the cookie without verifying it.
- Read the `matcher`: excluding `/api` or dynamic segments leaves them ungated.

```ts
// proxy.ts (Next 16) or middleware.ts: redirect only
export default async function proxy(req: NextRequest) {
  const session = await readSessionCookie(req)
  if (!session && req.nextUrl.pathname.startsWith('/dashboard'))
    return NextResponse.redirect(new URL('/login', req.nextUrl))
  return NextResponse.next()
}
```

False positive: middleware that redirects while the data layer also checks is the recommended pattern. A matcher that skips `/_next/static` and images is normal.

## CVE-2025-29927

A crafted internal header let requests skip middleware entirely on self-hosted Next.js, so auth done only in middleware was bypassed.

- Affected: 11.1.4 to 12.3.4, 13.0.0 to 13.5.8, 14.0 to 14.2.24, 15.0 to 15.2.2.
- Patched for this CVE only in 12.3.5, 13.5.9, 14.2.25 and 15.2.3. Those are not safe targets: later critical advisories hit every release below 15.5.24 / 16.3.6, so upgrade to the latest patch of 15.x or 16.x (as of 2026-10 at least 15.5.24 or 16.3.6), then stop relying on middleware alone. See [data-and-auth.md](data-and-auth.md#cve-2025-29927).
- Related: CVE-2024-51479 (pathname based middleware auth bypass, fixed in 14.2.15).

False positive: apps hosted on Vercel were shielded at the edge, but still upgrade. Check the installed version in the lockfile, not the range in package.json.

## dangerouslySetInnerHTML

Never pass user or model output to `dangerouslySetInnerHTML` without sanitizing it.

```tsx
import DOMPurify from 'isomorphic-dompurify'
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
```

For markdown use `react-markdown` without `rehype-raw`, or add `rehype-sanitize` after `rehype-raw`.

False positive: a developer-constant string (for example JSON-LD built from your own data with `<` escaped) is fine. Read where the HTML comes from.

## Remote images

`images.remotePatterns` with hostname `'**'` (or no pathname) turns the image optimizer into an open proxy and a blind SSRF.

```js
images: { remotePatterns: [{ protocol: 'https', hostname: 'cdn.example.com', pathname: '/uploads/**' }] }
```

Next 16 follows at most 3 redirects (`images.maximumRedirects`) and refuses local IPs unless `images.dangerouslyAllowLocalIP` is set; leave both at their defaults.

False positive: a fixed list of your own CDN hosts is fine.

## SSRF advisories

None of these is the image optimizer. Check the installed version in the lockfile.

- CVE-2024-34351 (13.4.0 to 14.1.0, fixed 14.1.1): self-hosted Server Actions that redirect to a relative path can be pointed at another host through the Host header.
- CVE-2025-57822 (fixed 14.2.32 and 15.4.7): middleware that passes request headers into the response (`NextResponse.next({ headers: request.headers })`). To change upstream request headers use `NextResponse.next({ request: { headers: newHeaders } })`.
- CVE-2026-64645 (12.0.0 to 15.5.20 and 16.0.0 to 16.2.10; fixed 15.5.21 and 16.2.11, no 14.x fix): a `rewrites()` or `redirects()` rule that builds its destination hostname from request input (such as `https://:tenant.example.com`) can be pointed at another host; the fixed suffix does not hold. Upgrade and keep destination hosts fixed.

False positive: apps on Vercel are not self-hosted for the first two, but still upgrade.

## Source maps

`productionBrowserSourceMaps: true` publishes the original source of every page. Leave it off, or upload maps to your error tracker in CI and delete them before deploy.

```js
// next.config.js with Sentry
module.exports = withSentryConfig(nextConfig, { sourcemaps: { deleteSourcemapsAfterUpload: true } })
```

- Vite: `build.sourcemap: false`, or `'hidden'` plus `filesToDeleteAfterUpload: ['./dist/**/*.map']` in the Sentry plugin.
- Create React App: `GENERATE_SOURCEMAP=false` in `.env.production`.
- webpack production: `devtool: false`, or `'hidden-source-map'` with deletion after upload.
- Vercel: turn on Protected Source Maps for existing projects. Static host backstop: `location ~* \.map$ { return 404; }`.

False positive: open-source frontends lose little. Maps that the build deletes after upload never ship.

## Security headers

Set baseline headers in `next.config.js`. Start CSP in Report-Only mode, then enforce it; a nonce-based CSP needs `proxy.ts` and dynamic rendering.

```js
const securityHeaders = [
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'Content-Security-Policy-Report-Only',
    value: "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" },
]
module.exports = { async headers() { return [{ source: '/(.*)', headers: securityHeaders }] } }
```

`output: 'export'` ignores `headers()`; set them on the host instead (next section).

False positive: the CDN or reverse proxy may already add them. Check the live response headers (live-exposure-check) before reporting.

## Static hosts and SPAs

A Vite, React or Create React App build (and a Next static export) is plain files, so the host sets the headers. Use the same values as above.

- Vercel, `vercel.json`: `{ "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Content-Type-Options", "value": "nosniff" }] }] }`
- Netlify and Cloudflare Pages: a `_headers` file in the published folder (for Vite, `public/_headers`), a path line such as `/*` followed by indented `Header-Name: value` lines.
- Firebase Hosting, `firebase.json`: `"hosting": { "headers": [{ "source": "**", "headers": [{ "key": "X-Frame-Options", "value": "DENY" }] }] }`
- nginx: `add_header X-Content-Type-Options "nosniff" always;`. A location block with its own `add_header` drops the ones from the server block, so repeat them there.

An app builder's own preview or hosting domain may not let you set response headers; deploy the build to a host you control. A `<meta http-equiv="Content-Security-Policy">` tag in `index.html` is only a partial backstop: it cannot set `frame-ancestors`, HSTS or nosniff.

False positive: the host or CDN may add headers outside the repo. Check the live response.

## Files in public

Everything in `public/` (Next.js, Vite, CRA, Laravel) or a served `static/` folder is downloadable as-is. Keep dumps, SQLite files, backups, logs, keys and env files out of it.

- Move data files outside the web root and serve them through an authenticated route if users need them.
- Add the patterns to `.gitignore` and the deploy ignore list.
- If a key or `.env` was ever served, rotate everything in it (rotation.md).

False positive: `robots.txt`, `.well-known/`, Laravel's `public/.htaccess` and images are fine. A file only matters if the deploy includes it.

## Data passed to the client

Props passed from a server component to a client component are serialized into the page, and `getServerSideProps` props land in `__NEXT_DATA__`. Pass only the fields the UI needs, never `process.env` or a raw database row. Optional extra guard: `experimental.taint` with `experimental_taintUniqueValue` on secret values.

False positive: passing public fields of a record (name, avatar URL) is fine.

LAST-VERIFIED: 2026-10-06
