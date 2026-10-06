# Rule reference

<!-- Generated from the RULES lists in scripts/_rules_*.py by gen_rules_md.py (a maintainer and CI step). Do not edit by hand. -->

One entry per rule that `scripts/scan_app.py` can report. Find a finding's entry by its rule id, or print only the entries you need with `python3 scripts/scan_app.py --explain RULE_ID[,RULE_ID]`.

Each entry says what the rule looks for, why coding agents produce it, the false-positive trap to rule out before you report it, and where the fix is. The scanner reports candidates. Read the code at the reported line and confirm the problem before fixing anything.

The severity shown is the rule's default. A check can report one hit higher or lower when the code around it is stronger or weaker evidence; the scan output shows the severity of each hit.

Rules: 102.

## Data access and auth

Module: `scripts/_rules_dataauth.py`

### data-client-password-check

**critical** | confidence medium | confirm before reporting | stacks: *

- What: password or PIN compared to a value shipped in client code
- Class: password checked in the browser
- Why agents produce it: A quick admin gate is a string compare in the component, sometimes against a VITE_ or NEXT_PUBLIC_ variable, and both end up in the JavaScript bundle.
- False-positive trap: Comparisons of input types or state names ('password', 'text', 'strong') are ignored, as are feature flags (VITE_DISABLE_PASSWORD_LOGIN === 'true'). A check that only toggles UI while a server verifies the password is fine; a test fixture is not shipped code.
- Fix: [data-and-auth.md#client-side-checks](data-and-auth.md#client-side-checks)

### data-firebase-rules-open

**critical** | confidence high | confirm before reporting | stacks: firebase

- What: Firebase rule lets anyone, logged out, read or write this data
- Class: open Firebase rules
- Why agents produce it: allow read, write: if true is the rule that makes the first write succeed, and tutorials ship it. Firebase clients talk straight to the database, so the rules are the only gate.
- False-positive trap: allow read: if true on a collection that is public by design (leaderboard, published posts) with restricted writes is fine and is only reported when the path looks private. The firebaseConfig apiKey in client code is not a secret and is never the bug.
- Fix: [stack-firebase.md#owner-only-rules](stack-firebase.md#owner-only-rules)

### data-firebase-test-mode

**critical** | confidence high | direct | stacks: firebase

- What: Firebase test-mode rule: everyone can read and write until a date
- Class: Firebase test-mode rules
- Why agents produce it: The console's test mode writes request.time < timestamp.date(...) and the project ships with it. Until the date everything is open; after it, everything breaks.
- False-positive trap: None in production. In a local emulator-only rules file it is harmless; check firebase.json.
- Fix: [stack-firebase.md#test-mode-rules](stack-firebase.md#test-mode-rules)

### data-nextjs-middleware-cve

**critical** | confidence high | confirm before reporting | stacks: nextjs

- What: Next.js version lets a request header skip middleware (CVE-2025-29927)
- Class: Next.js middleware bypass (CVE-2025-29927)
- Why agents produce it: Agents pin the Next.js version they were trained on and put auth in middleware; self-hosted apps on 11.1.4 to 15.2.2 can be bypassed with one header.
- False-positive trap: Apps hosted on Vercel were shielded at the edge, but should still upgrade. A caret range with no lockfile installs a release past this CVE, but on 12, 13 and 14 it still installs versions with later critical advisories; the version reported is the lockfile or node_modules version when one exists. A middleware that only refreshes a session cookie is reported as medium. Never recommend the CVE patch floor itself (12.3.5, 13.5.9, 14.2.25, 15.2.3) as the target.
- Fix: [data-and-auth.md#cve-2025-29927](data-and-auth.md#cve-2025-29927)

### data-supabase-rls-disabled

**critical** | confidence high | confirm before reporting | stacks: supabase

- What: Supabase table in an exposed schema never gets RLS enabled
- Class: Supabase table without RLS
- Why agents produce it: The query works from the browser without any policy, so the agent never writes one. Tables made with raw SQL migrations do not get RLS automatically, and the anon key ships in the bundle.
- False-positive trap: Tables in a schema that is not exposed (private, extensions), tables whose grants to anon and authenticated are revoked, and RLS turned on by a DO block or event trigger are fine. RLS switched on in the dashboard but never written to a migration also shows here: confirm with the Security Advisor or supabase db advisors (CLI 2.81 or newer) before reporting; supabase db lint only runs plpgsql_check and says nothing about RLS.
- Fix: [stack-supabase.md#enable-rls-and-owner-policies](stack-supabase.md#enable-rls-and-owner-policies)

### data-admin-route-no-role

**high** | confidence medium | confirm before reporting | stacks: node, python

- What: admin route or endpoint with no server-side role check
- Class: admin route without a role check
- Why agents produce it: The admin screen is hidden in the UI, so the agent stops at 'is logged in' (or at nothing) on the API route behind it, and one decorator gets left off when a route is added later.
- False-positive trap: A middleware or proxy that checks the role for /admin paths, a role check inside a handler defined in another module, and a blueprint-wide before_request check are fine; confirm before reporting. For a route missing a decorator its siblings use, check whether it is public on purpose.
- Fix: [data-and-auth.md#client-side-checks](data-and-auth.md#client-side-checks)

### data-client-role-flag

**high** | confidence medium | confirm before reporting | stacks: *

- What: role or login flag read from browser storage; anyone can flip it in devtools
- Class: client-side role check
- Why agents produce it: The UI is the only surface the agent can see, so it gates admin screens on a localStorage flag and never adds the same check on the server.
- False-positive trap: Fine as a UI hint when the server or RLS enforces the same rule independently. Confirm the API routes, Server Actions or tables behind the screen check the role server-side.
- Fix: [data-and-auth.md#client-side-checks](data-and-auth.md#client-side-checks)

### data-cookie-identity

**high** | confidence medium | confirm before reporting | stacks: *

- What: server reads the user id or role from a plain cookie the client can edit
- Class: identity from an unsigned cookie
- Why agents produce it: Setting a user_id or role cookie at login is the shortest way to remember who is signed in, and nothing in the demo shows that the browser can rewrite it.
- False-positive trap: A signed or encrypted cookie (Express signedCookies, a signed session, a verified JWT) is fine; a cookie used only to pick a UI default is harmless. Confirm what the value decides.
- Fix: [data-and-auth.md#sessions-and-jwts](data-and-auth.md#sessions-and-jwts)

### data-firebase-any-auth

**high** | confidence medium | confirm before reporting | stacks: firebase

- What: rule only checks request.auth != null, so any signed-in user reaches every user's data
- Class: any signed-in user allowed
- Why agents produce it: request.auth != null looks secure, but anyone can sign up (or sign in anonymously) and then read or change every other user's documents.
- False-positive trap: Data that is genuinely shared by all signed-in users (a team workspace where every member is trusted) is fine. Create-only rules and reads of non-private paths are not reported. An OR is as open as its most open branch: isAdmin() || isSignedIn() counts as any signed-in user.
- Fix: [stack-firebase.md#any-signed-in-user](stack-firebase.md#any-signed-in-user)

### data-firebase-role-field

**high** | confidence medium | confirm before reporting | stacks: firebase

- What: rules read a role from a document its owner can write
- Class: role in a user-writable document
- Why agents produce it: Agents store role or isAdmin on users/{uid} and let the owner edit their own document, so the role check reads a value the user controls.
- False-positive trap: Fine when the write rule blocks the role field (affectedKeys().hasOnly([...]), diff(...)) or only the Admin SDK writes the document. Custom claims (request.auth.token.admin) are the right fix. A fixed admin email is fine only together with request.auth.token.email_verified == true.
- Fix: [stack-firebase.md#roles-with-custom-claims](stack-firebase.md#roles-with-custom-claims)

### data-hardcoded-auth-bypass

**high** | confidence medium | confirm before reporting | stacks: *

- What: login or OTP check accepts a fixed code written in the server code
- Class: hardcoded login or OTP bypass
- Why agents produce it: A demo or app-store reviewer account needs to get past SMS or email codes, so the agent adds if (phone === '...' && code === '123456') and it ships to production.
- False-positive trap: A bypass behind an env flag that is off in production, or a provider's published test number, is fine. Error-code comparisons (error.code === '23505') are not reported.
- Fix: [data-and-auth.md#sessions-and-jwts](data-and-auth.md#sessions-and-jwts)

### data-idor-by-id

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: record looked up by an id from the request with no ownership check nearby
- Class: IDOR / missing ownership check
- Why agents produce it: The agent checks that someone is logged in, then fetches by the id from the URL or body and stops. In a one-user demo both versions return the same data.
- False-positive trap: A by-id query followed by an owner check (row.userId !== session.user.id), a where clause or earlier scoped lookup that includes the owner (projectId: workspace.id), admin-only wrappers and procedures (withAdmin, adminProcedure), signed cron, queue and webhook handlers, public resources, tenant-scoped clients, Laravel models whose route binding is scoped to the user, and DRF views with get_queryset are fine. Supabase queries through a client built from the anon key and the caller's token are covered by RLS. A filter on user_id taken from the request is reported too.
- Fix: [data-and-auth.md#ownership-checks](data-and-auth.md#ownership-checks)

### data-jwt-not-verified

**high** | confidence medium | confirm before reporting | stacks: *

- What: server reads JWT claims without verifying the signature
- Class: JWT decoded but not verified
- Why agents produce it: decode() returns the claims and looks like it works, so agents use it in middleware and API routes instead of verify().
- False-positive trap: Decoding in browser code to read exp for the UI is fine. Peeking at the header before a real verify call in the same file is not reported. An OIDC id_token taken straight from the provider's token endpoint over TLS may skip the signature (OIDC Core 3.1.3.7) and is low.
- Fix: [data-and-auth.md#sessions-and-jwts](data-and-auth.md#sessions-and-jwts)

### data-mass-assignment

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: request data written into a create or update without an allow-list (whole body, or a role field)
- Class: mass assignment
- Why agents produce it: Spreading the body is the shortest code that makes the form work, and the TypeScript type or the UI looks like a whitelist, but neither is enforced at runtime.
- False-positive trap: A body built from an explicit allow-list ({ title, content }), a value parsed by a schema that strips unknown keys, Laravel models with a safe $fillable (or the default guarded model) and Pydantic input models without privileged fields are fine. A role or plan field from the request is fine behind a server-side admin check; a chat message's role and a job title are not privileges.
- Fix: [data-and-auth.md#mass-assignment](data-and-auth.md#mass-assignment)

### data-service-role-no-caller-check

**high** | confidence medium | confirm before reporting | stacks: supabase

- What: Edge Function or route uses the service role key on request input without checking the caller
- Class: service-role function with no caller check
- Why agents produce it: verify_jwt is on by default and looks like auth, but the public anon key is itself a valid JWT. With the service role client every query skips RLS, so the function is the only gate.
- False-positive trap: Functions that call getUser() or getClaims(), compare a shared secret or verify a webhook signature are not reported, nor are handlers wrapped in @supabase/server withSupabase() with auth 'user' (the default) or 'secret'; 'publishable' or 'none' lets anyone in and is still reported. A deliberately public endpoint (contact form) still needs input limits and rate limiting; confirm what it can change.
- Fix: [stack-supabase.md#edge-functions-and-seed-accounts](stack-supabase.md#edge-functions-and-seed-accounts)

### data-supabase-own-row-privileged

**high** | confidence medium | confirm before reporting | stacks: supabase

- What: own-row insert or update policy on a table with a role, plan, credits or verified column
- Class: user can edit own privilege column
- Why agents produce it: auth.uid() = id looks like a complete policy, but RLS works on rows, not columns: the owner can change every column of their row, including role, is_verified, plan or credits.
- False-positive trap: Fine when a column grant (grant update (name, bio) ...) leaves the privileged column out, when update is revoked from authenticated, or when a BEFORE INSERT or UPDATE trigger on the table resets or rejects that column. Confirm the column really grants something.
- Fix: [stack-supabase.md#permissive-policies](stack-supabase.md#permissive-policies)

### data-supabase-policy-allows-all

**high** | confidence high | confirm before reporting | stacks: supabase

- What: RLS policy uses true (or only 'is signed in') where it should check the row owner
- Class: Supabase policy open to everyone
- Why agents produce it: USING (true) is the fastest way to stop a query from returning nothing, and the dashboard templates offer it. It turns RLS back off for that command.
- False-positive trap: A read policy USING (true) on a genuinely public table (catalog, published posts) with no write policy and no private columns is fine, and is only reported when the table name or its columns look private. An insert-only policy on a public form table with no owner column is fine. Restrictive policies are ignored. A schema that shares every table among signed-in users (a one-team CRM) is reported once per file; it is fine when public sign-ups are off.
- Fix: [stack-supabase.md#permissive-policies](stack-supabase.md#permissive-policies)

### data-supabase-service-key-client

**high** | confidence medium | confirm before reporting | stacks: supabase

- What: Supabase service role or secret key referenced in client code; the admin client must stay on the server
- Class: service role key in client code
- Why agents produce it: When a query fails under RLS, swapping in the service role key makes it work, so agents create an admin client next to the browser client, often in a module the browser code imports.
- False-positive trap: The service key in Edge Functions, API routes, Server Actions or files with import 'server-only' is correct and is not reported. A non-public env var reads as undefined in the browser, so the key is one prefix away from leaking rather than leaked: confirm whether the bundler inlines it. Literal keys are reported by find_secrets.py and public-prefixed names by secret-public-env-prefix, both as critical. The bare 'sb_secret_' prefix in a key-type check (Lovable's generated client) names no key and is ignored.
- Fix: [stack-supabase.md#service-role-key](stack-supabase.md#service-role-key)

### data-supabase-user-metadata-authz

**high** | confidence medium | confirm before reporting | stacks: supabase

- What: role or plan read from user_metadata, which the user can edit
- Class: access decided by user_metadata
- Why agents produce it: Sign-up code passes a role in options.data, and the agent reads it back for access checks without knowing that every user can rewrite user_metadata with updateUser().
- False-positive trap: Copying display fields such as full_name or avatar_url from raw_user_meta_data in a sign-up trigger is fine and is not reported. app_metadata (raw_app_meta_data) is server-only and is the right place for roles. Only the last definition of a function counts; one-time backfill statements are reported as low.
- Fix: [stack-supabase.md#user-metadata-in-policies](stack-supabase.md#user-metadata-in-policies)

### data-supabase-view-bypasses-rls

**high** | confidence medium | confirm before reporting | stacks: supabase

- What: view in an exposed schema runs with its owner's rights and skips RLS
- Class: view bypassing RLS
- Why agents produce it: Agents add a convenience view that joins several tables. Created by postgres, it ignores the callers' RLS and leaks rows the base-table policies block.
- False-positive trap: Views created WITH (security_invoker = true) or later altered to it are fine, as are views whose select grant is revoked from anon and authenticated, views over data that is public anyway, and views that select only aggregates (count, exists) and no row data.
- Fix: [stack-supabase.md#views-and-rls](stack-supabase.md#views-and-rls)

### data-weak-password-hash

**high** | confidence medium | confirm before reporting | stacks: *

- What: password hashed with MD5 or SHA instead of a password hash
- Class: fast password hash
- Why agents produce it: Hand-rolled sign-up code reaches for the hash function it knows, not a slow password hash.
- False-positive trap: Hashing a reset token or an API key with SHA-256 is fine. SHA-1 of a password for a haveibeenpwned range check is fine and skipped. PBKDF2, bcrypt, scrypt and argon2 are not matched; neither is a fingerprint of the stored hash or a pre-hash fed straight into bcrypt. A fast PASSWORD_HASHERS entry inside test settings is fine.
- Fix: [data-and-auth.md#password-hashing](data-and-auth.md#password-hashing)

### data-nextjs-middleware-only-auth

**medium** | confidence low | confirm before reporting | stacks: nextjs

- What: route writes data with no auth check of its own; only middleware or proxy guards it
- Class: middleware as the only gate
- Why agents produce it: Agents put the auth gate in one convenient place and assume everything behind it is covered. Matchers often skip /api, and middleware is meant for optimistic checks only.
- False-positive trap: Routes that are public on purpose, webhook and auth callback routes, and routes that query Supabase with the user's session (RLS still applies) are not reported. Confirm the matcher and whether the route is meant to be public.
- Fix: [data-and-auth.md#middleware-and-proxy](data-and-auth.md#middleware-and-proxy)

### data-serializer-all-fields

**medium** | confidence medium | confirm before reporting | stacks: django

- What: ModelSerializer or ModelForm with fields = '__all__' lets clients write every column
- Class: writable __all__ serializer
- Why agents produce it: fields = '__all__' is the shortest Meta block, and it exposes role, owner and price columns too.
- False-positive trap: A serializer used only for output, or one whose sensitive columns are all in read_only_fields, is safe today but fragile: new columns become writable. Reported as low when read_only_fields is present. A User form or serializer with exclude = [...] is reported when is_superuser or is_staff stays writable.
- Fix: [data-and-auth.md#mass-assignment](data-and-auth.md#mass-assignment)

### data-supabase-admin-by-email

**medium** | confidence medium | confirm before reporting | stacks: supabase

- What: policy or definer function grants access by comparing the JWT email to a fixed address
- Class: admin decided by a fixed email
- Why agents produce it: A bootstrap admin is the owner's email written into a policy. With email confirmation off, or before the owner signs up, anyone can register that address and get the admin rights.
- False-positive trap: Safe only while email confirmation is on and the owner already holds the account; a roles table or app_metadata claim is the durable fix.
- Fix: [stack-supabase.md#user-metadata-in-policies](stack-supabase.md#user-metadata-in-policies)

### data-supabase-definer-exposed

**medium** | confidence medium | confirm before reporting | stacks: supabase

- What: security definer function in an exposed schema that never checks the caller
- Class: RLS-bypassing RPC
- Why agents produce it: A security definer function runs as its owner and ignores RLS. In the public schema it is callable by anon and authenticated through /rest/v1/rpc.
- False-positive trap: Trigger functions, functions that check auth.uid() or auth.jwt() (directly or through a guard helper such as IF NOT is_admin() THEN RAISE), functions in a private schema and functions whose EXECUTE was revoked from public, anon and authenticated are not reported. PUBLIC holds EXECUTE by default, so a revoke from anon alone or a grant to service_role changes nothing. Read-only helpers that return a flag or an id are grouped as low; a function granted to anon on purpose for a public form is low but still needs input limits.
- Fix: [stack-supabase.md#security-definer-functions](stack-supabase.md#security-definer-functions)

### data-supabase-definer-search-path

**medium** | confidence high | direct | stacks: supabase

- What: security definer function without a fixed search_path
- Class: security definer without search_path
- Why agents produce it: Agents copy security definer to get past an RLS error and leave out set search_path, so the function resolves unqualified names through a path the caller can influence.
- False-positive trap: A later ALTER FUNCTION ... SET search_path fixes it and is taken into account. Functions with set search_path = '' (or a fixed list, quoted or not as pg_dump writes it) are fine.
- Fix: [stack-supabase.md#security-definer-functions](stack-supabase.md#security-definer-functions)

### data-supabase-getsession-server

**medium** | confidence high | confirm before reporting | stacks: supabase

- What: server code trusts supabase.auth.getSession(), which reads the cookie without verifying it
- Class: unverified session on the server
- Why agents produce it: getSession() is the call agents remember from client code; on the server it returns whatever the cookie says without checking the JWT.
- False-positive trap: getSession() in browser code is fine, including TanStack Router route files (createFileRoute). A file that also calls getUser() or getClaims() to verify the user (the SvelteKit safeGetSession pattern) is not reported. A middleware that calls getSession() only to refresh the cookie is reported as low.
- Fix: [stack-supabase.md#getclaims-over-getsession](stack-supabase.md#getclaims-over-getsession)

### data-supabase-seeded-auth-users

**medium** | confidence high | confirm before reporting | stacks: supabase

- What: migration inserts accounts into auth.users, so they exist in production too
- Class: demo accounts in a migration
- Why agents produce it: To make a demo work the agent inserts users with a known password and email_confirmed_at = now() into a migration, and migrations run against the production database.
- False-positive trap: supabase/seed.sql and other seed files only run locally and are not reported. An insert that creates a service account with a random password the team rotates is rarer but fine.
- Fix: [stack-supabase.md#edge-functions-and-seed-accounts](stack-supabase.md#edge-functions-and-seed-accounts)

## Secrets reaching the client

Module: `scripts/_rules_secrets.py`

### secret-admin-sdk-in-client

**critical** | confidence medium | confirm before reporting | stacks: *

- What: Firebase Admin SDK or a service account key file is reachable from the client
- Class: admin SDK or service account on the client side
- Why agents produce it: Agents import firebase-admin or a downloaded serviceAccountKey.json into frontend code to skip Security Rules, or drop the key file in public/ so the app can fetch it.
- False-positive trap: The Firebase web config (apiKey, authDomain, projectId) is public by design and is not this finding. firebase-admin in Cloud Functions, API routes or other server code is correct. A nested server package under src/ (its own package.json that depends on firebase-admin, such as the admin SDK Firebase Data Connect generates) is skipped while no client file imports it.
- Fix: [secrets.md#admin-keys-stay-on-the-server](secrets.md#admin-keys-stay-on-the-server)

### secret-bundler-inlines-env

**critical** | confidence high | confirm before reporting | stacks: *

- What: bundler config inlines a server env value (or all of process.env) into the client bundle
- Class: bundler config inlines server env
- Why agents produce it: Next.js copies every key under next.config env into the bundle whatever its prefix, and Vite define or webpack DefinePlugin replace process.env.X with the literal value. Agents use them to make a key 'available' in client code, and some app-builder templates ship define blocks that inline GEMINI_API_KEY.
- False-positive trap: Public values (site URL, NODE_ENV, version strings, publishable keys) in these blocks are fine. Vite loadEnv(mode, dir) without the third '' argument only loads VITE_ variables, so inlining that env object is safe. serverRuntimeConfig (Next.js 15 and older) stays on the server; Next.js 16 removed both runtime config options.
- Fix: [secrets.md#bundler-config-that-inlines-env](secrets.md#bundler-config-that-inlines-env)

### secret-env-sent-to-client

**critical** | confidence high | confirm before reporting | stacks: *

- What: a response, page prop or template sends server env values or the whole config to the client
- Class: server environment sent to the client
- Why agents produce it: Agents add a /api/config endpoint, getServerSideProps props or a component prop so the frontend can read a key it needs, and sometimes return the whole process.env or os.environ to 'debug' it.
- False-positive trap: Returning an explicit allow-list of public values (site URL, publishable key, anon key) is the correct pattern and is not reported. Checks such as !!process.env.KEY or key === undefined only send a boolean and are not reported.
- Fix: [secrets.md#never-send-the-environment](secrets.md#never-send-the-environment)

### secret-public-env-prefix

**critical** | confidence high | confirm before reporting | stacks: *

- What: a secret-shaped env var uses a prefix that inlines it into the client bundle
- Class: server secret behind a public env prefix
- Why agents produce it: The agent sees 'X is undefined in the browser' and the shortest fix is to rename the variable with NEXT_PUBLIC_, VITE_, EXPO_PUBLIC_ or REACT_APP_, which copies the value into every bundle.
- False-positive trap: Publishable, anon and site keys are public by design: NEXT_PUBLIC_SUPABASE_ANON_KEY, *_PUBLISHABLE_KEY, VITE_FIREBASE_API_KEY, *_RECAPTCHA_SITE_KEY, Sentry DSN and PostHog keys are not reported. A prefix the project's framework does not expose (VITE_ in a Next.js app) is not reported. Check the value when the name is ambiguous.
- Fix: [secrets.md#public-env-prefixes](secrets.md#public-env-prefixes)

### secret-supabase-admin-in-client

**critical** | confidence medium | confirm before reporting | stacks: *

- What: supabase.auth.admin is called from client code; it only works with the service key, which bypasses RLS
- Class: Supabase admin API in client code
- Why agents produce it: Agents build admin screens (list users, delete users, invite) in the frontend and then hand the browser client the service_role key so the admin calls stop failing.
- False-positive trap: The same call in a server route, a Server Action ('use server'), an Edge Function or a file that imports 'server-only' is correct and is not reported.
- Fix: [secrets.md#admin-keys-stay-on-the-server](secrets.md#admin-keys-stay-on-the-server)

### secret-hardcoded-signing-key

**high** | confidence high | confirm before reporting | stacks: *

- What: a JWT, session or framework signing secret is a literal in the source
- Class: hardcoded or default signing secret
- Why agents produce it: Tutorials and READMEs show literal secrets ('keyboard cat', the FastAPI tutorial key, django-insecure- keys from startproject) and agents copy them to make auth work.
- False-positive trap: Throwaway keys in test settings, conftest.py and dev-only settings modules are fine as long as production never loads them; check DJANGO_SETTINGS_MODULE or the app factory. A literal that is replaced from the environment later in the same file is not reported. In Django split settings, a literal in base.py that a production module (from .base import *) replaces from the environment is skipped when the deploy config selects that module, and medium otherwise.
- Fix: [secrets.md#signing-secrets](secrets.md#signing-secrets)

### secret-llm-sdk-in-browser

**high** | confidence medium | confirm before reporting | stacks: *

- What: LLM SDK set to run in the browser (dangerouslyAllowBrowser or the Anthropic direct browser header)
- Class: LLM SDK running in the browser
- Why agents produce it: The OpenAI and Anthropic SDKs refuse to run in a browser until this flag is set. Agents set it to clear the error instead of moving the call to a server route, so the key ships to every visitor.
- False-positive trap: Bring-your-own-key tools where each user types their own key at runtime (kept in localStorage or state) are a legitimate use and are not reported. Files that only run on the server are skipped.
- Fix: [secrets.md#call-third-party-apis-from-server-code](secrets.md#call-third-party-apis-from-server-code)

### secret-provider-call-from-client

**high** | confidence medium | confirm before reporting | stacks: *

- What: client code calls an LLM or email provider API directly, so the provider key must be in the bundle
- Class: paid API called straight from client code
- Why agents produce it: No-backend SPAs and Expo apps have no server to hold the key, so agents call the provider from the browser or the app with the key attached.
- False-positive trap: Bring-your-own-key tools that send the user's own key are fine. A URL string used only for display or docs is not a call. Calls from server routes are not reported.
- Fix: [secrets.md#call-third-party-apis-from-server-code](secrets.md#call-third-party-apis-from-server-code)

### secret-public-env-token

**high** | confidence medium | confirm before reporting | stacks: *

- What: a token or webhook env var uses a prefix that inlines it into the client bundle
- Class: token behind a public env prefix
- Why agents produce it: Agents expose API tokens and webhook URLs to the browser so a client component can call the service directly instead of going through a server route.
- False-positive trap: Some tokens are public by design: Mapbox pk. tokens, Cesium ion and Contentful or Storyblok delivery tokens. A value in .env that is public by design (pk_, pk., anon JWT) is not reported. Browser log ingest tokens (Axiom, Better Stack / Logtail source tokens, Datadog client tokens) are reported as info: they are fine when they can only send logs. Each variable is reported once, at its env file or env schema, with the other places listed; lines that only test whether it is set (!!env.X, if (X)) do not count. Read the provider docs for the token type before moving it.
- Fix: [secrets.md#public-env-prefixes](secrets.md#public-env-prefixes)

### secret-signing-fallback

**high** | confidence high | confirm before reporting | stacks: *

- What: a secret env var falls back to a literal when it is missing, so production can run with a known value
- Class: signing secret with a literal fallback
- Why agents produce it: Agents write process.env.JWT_SECRET || 'secret' or os.getenv('SECRET_KEY', 'dev') so the app starts without a .env file. When the variable is missing in production the literal signs every session.
- False-positive trap: A fallback that only applies outside production (the code throws when NODE_ENV is production and the variable is unset) is fine. Fallbacks for public values or for API keys that only fail a request are not reported. Test and dev-only settings files, test runner configs (playwright, vitest, jest, cypress) and dev, local, test or CI compose files and Dockerfiles are skipped; compose.override files are reported as low.
- Fix: [secrets.md#fail-closed-on-missing-env](secrets.md#fail-closed-on-missing-env)

## Payments, abuse and request logic

Module: `scripts/_rules_logic.py`

### pay-webhook-unverified

**critical** | confidence high | confirm before reporting | stacks: *

- What: Stripe webhook handler acts on events but nothing in the project verifies the Stripe signature
- Class: payment webhook signature not verified
- Why agents produce it: Agents wire the webhook route straight to the event switch, or copy the branch of Stripe's sample that deserializes the body when no secret is set. Anyone who knows the URL can then post a fake checkout.session.completed and get credited. With other gateways the same happens in the IPN or return handler that trusts the posted status.
- False-positive trap: Verification can live in a helper in another file (the scanner already skips this when any production file calls constructEvent or verify_header), in Laravel Cashier's controller or dj-stripe, or in an API gateway. Confirm the route that receives Stripe's POST actually checks the Stripe-Signature header before reporting. Other gateways (SSLCommerz, Razorpay, Paystack and the like): a callback that marks an order paid is reported when it neither checks a signature nor asks the gateway, and at medium when it asks the gateway but never compares the returned amount and order id with the stored order. A status copied from the posted data into an order update (the FAILED or CANCELLED branch) is reported at medium when no signature is checked. Safe: the order is looked up from the gateway's own response, or the amount and id are compared somewhere the scanner did not see.
- Fix: [payments-and-abuse.md#webhook-signature](payments-and-abuse.md#webhook-signature)

### pay-webhook-verify-optional

**critical** | confidence high | confirm before reporting | stacks: *

- What: Stripe signature check only runs when the webhook secret is set, or its failure is ignored
- Class: payment webhook verification can be skipped
- Why agents produce it: Stripe's quickstart wraps constructEvent in if (endpointSecret) and falls back to the parsed body. Agents copy it and never set STRIPE_WEBHOOK_SECRET in production, so forged events are accepted. Several 2026 CVEs are this exact guard.
- False-positive trap: Safe: if (!secret) return a 500 before verifying, or an else branch that fails closed. Also safe: a try/catch whose catch returns 400. The rule only fires when the handler also assigns the event from the raw or parsed body, so check that this fallback really reaches the fulfillment code. It also reports an HMAC signature check (Razorpay, Paystack, a webhook) whose key is env || '' with no empty-key check; a startup check elsewhere that refuses to boot without the variable makes that safe.
- Fix: [payments-and-abuse.md#webhook-signature](payments-and-abuse.md#webhook-signature)

### abuse-llm-route-open

**high** | confidence medium | confirm before reporting | stacks: *

- What: Server route calls a paid LLM API with no auth check and no rate limit in sight
- Class: denial of wallet
- Why agents produce it: Agents build /api/chat as a thin proxy because the demo works without login or limits. Anyone who finds the endpoint can run up the provider bill or resell access.
- False-positive trap: Auth or limits may be global: Next.js middleware or proxy whose matcher covers the route, an app.use() limiter or auth in the Express entry file, FastAPI router dependencies, an API gateway. They may also sit in a wrapper or helper: withWorkspace(...), an auth action client, a project helper that loads the user and throws. The scanner skips the common forms and follows the route's own imports one level for auth and two levels for the LLM call; confirm the route really answers a logged-out request. Local-only models are not metered.
- Fix: [payments-and-abuse.md#metered-and-llm-routes](payments-and-abuse.md#metered-and-llm-routes)

### abuse-send-no-throttle

**high** | confidence medium | confirm before reporting | stacks: *

- What: Endpoint sends an SMS, OTP or email to a destination from the request with no rate limit or CAPTCHA
- Class: SMS or email pumping
- Why agents produce it: Agents wire 'send code' or 'verify email' straight to Twilio or the mailer. Fraudsters use the form to send messages to premium number ranges (SMS pumping) or to flood inboxes and burn quota.
- False-positive trap: Sends behind login, sends to an address loaded from your own DB by the email the visitor typed (password reset for a known user), and sends to a fixed admin address are lower risk and not flagged. A send to a user looked up by an id from the request is flagged at medium when the route has no auth check at all; a shared-secret header from a DB webhook makes it safe. The message says when the email body also carries request text without escaping. Limits can also be global middleware or the provider's fraud guard (Twilio Verify Fraud Guard, Supabase Auth's built-in limits); check those before reporting.
- Fix: [payments-and-abuse.md#otp-sms-and-email-sends](payments-and-abuse.md#otp-sms-and-email-sends)

### pay-client-amount

**high** | confidence medium | confirm before reporting | stacks: *

- What: Payment amount for a Stripe PaymentIntent, Checkout line item or charge comes from the request
- Class: client-controlled price
- Why agents produce it: The shortest path from a cart to Stripe, Razorpay, SSLCommerz or any other gateway is to pass the cart's amount or item prices to the create call, or to let the browser insert the order row with its own total. An attacker edits the request and pays one cent for a real product.
- False-positive trap: Safe: the client sends a plan or product id and the server looks the price up in its own catalog or DB (PRICES[plan], product.price), or computes the total from ids (calculateOrderAmount(items)). Quantity from the client is fine with server prices. Donations, tips and top-ups are meant to be variable; the scanner skips files that say so, check others for a server-side min and max. A browser order insert (medium) is safe when a trigger or RPC recomputes the total from product prices before anything is charged or shipped.
- Fix: [payments-and-abuse.md#server-side-prices](payments-and-abuse.md#server-side-prices)

### pay-fulfill-on-redirect

**high** | confidence medium | confirm before reporting | stacks: *

- What: Checkout success page grants a plan, credits or access without confirming the payment with Stripe
- Class: fulfillment on the success page
- Why agents produce it: Agents put the 'give the user Pro' write where the browser lands after checkout. Anyone can open the success URL without paying, and customers whose browser never returns are never served.
- False-positive trap: Safe: the page only shows status, or calls a shared fulfill function that retrieves the Checkout Session and checks payment_status (the scanner skips files that do both). The webhook should still be the main path.
- Fix: [payments-and-abuse.md#fulfill-from-the-webhook](payments-and-abuse.md#fulfill-from-the-webhook)

### csrf-protection-disabled

**medium** | confidence medium | confirm before reporting | stacks: django, flask, laravel, python, php

- What: Framework CSRF protection is switched off for a route or the whole app
- Class: framework CSRF disabled
- Why agents produce it: When a form or fetch call fails with a CSRF error, the quickest agent fix is @csrf_exempt, an except entry, or removing the middleware. Cookie-authenticated actions then accept cross-site posts.
- False-positive trap: Webhook endpoints (Stripe, PayPal, GitHub) are correctly exempt, and views authenticated by a header token instead of cookies are not CSRF-prone. The scanner skips webhook-like names and views that never touch request.user or the session; confirm the rest.
- Fix: [payments-and-abuse.md#csrf](payments-and-abuse.md#csrf)

### csrf-session-no-token

**medium** | confidence low | confirm before reporting | stacks: express

- What: State-changing Express route uses the cookie session, and the project has no CSRF defense
- Class: CSRF on cookie sessions
- Why agents produce it: Agents add express-session or cookie-session for login and forget CSRF because same-origin fetch works in development. A page on another site can then post as the logged-in user.
- False-positive trap: A SameSite=Lax or Strict session cookie, an Origin or Sec-Fetch-Site check, or a CSRF library called anywhere in the project makes the scanner skip; so does Authorization-header auth. A library that is only listed in package.json, or whose call is commented out, does not count. SameSite alone is defense in depth, not a full fix.
- Fix: [payments-and-abuse.md#csrf](payments-and-abuse.md#csrf)

### pay-webhook-no-idempotency

**medium** | confidence low | confirm before reporting | stacks: *

- What: Stripe webhook adds credits or balance with no check that the event was already processed
- Class: webhook not idempotent
- Why agents produce it: Stripe delivers events at least once and may retry or send them out of order. A handler that does credits += N on every delivery double-credits users.
- False-positive trap: Idempotency can live elsewhere: a unique constraint on the event or session id in a migration, an upsert, or a queue that dedupes. The scanner skips files that mention event.id, ON CONFLICT, upsert or a stored session id, and projects with such a unique index in SQL or Prisma.
- Fix: [payments-and-abuse.md#idempotent-fulfillment](payments-and-abuse.md#idempotent-fulfillment)

### pay-webhook-parsed-body

**medium** | confidence medium | confirm before reporting | stacks: *

- What: Stripe webhook verifies a parsed or re-serialized body instead of the raw request bytes
- Class: webhook body parsed before verification
- Why agents produce it: Stripe signs the exact raw body. Agents call await req.json(), mount express.json() first, or pass JSON.stringify(req.body). Verification then always fails, and the next agent edit tends to remove the check to make webhooks work.
- False-positive trap: Safe: App Router await req.text(), express.raw() on the webhook route (or express.json() mounted after it, or with a verify callback that keeps rawBody), Pages Router with bodyParser: false, Flask request.data, FastAPI await request.body(), Django request.body.
- Fix: [payments-and-abuse.md#raw-body](payments-and-abuse.md#raw-body)

### redirect-open

**medium** | confidence medium | confirm before reporting | stacks: *

- What: Redirect target comes from a next, returnTo or redirect parameter without a same-site check
- Class: open redirect
- Why agents produce it: 'Send the user back where they came from' is implemented by echoing the parameter. Attackers use your login link to land victims on a phishing page or to leak OAuth codes.
- False-positive trap: Safe: a constant target, an exact-match allowlist, url_has_allowed_host_and_scheme, a parsed origin compared with your own, or a check that the value starts with one /, is not // or /\, and holds no backslash or control character. A // check or a urlsplit netloc check alone is reported: browsers read /\host and a tab or newline after the first / as another host. Prefixing the origin (`${origin}${next}`) is safe only together with the startsWith('/') check. new URL(next, base) alone is not safe, and an allowlist matched with includes() accepts any URL that contains it.
- Fix: [payments-and-abuse.md#open-redirects](payments-and-abuse.md#open-redirects)

### csrf-csurf-deprecated

**low** | confidence high | direct | stacks: node

- What: csurf is deprecated (since 2022-09) and no longer maintained
- Class: deprecated CSRF package
- Why agents produce it: Older tutorials and agent training data still add csurf for Express CSRF. It is archived, had a double-submit weakness, and leaves apps on an unmaintained dependency.
- False-positive trap: The app may be token-authenticated (Authorization header, no cookies) and not need CSRF at all; then remove csurf instead of replacing it.
- Fix: [payments-and-abuse.md#csrf](payments-and-abuse.md#csrf)

## Injection, XSS, uploads and SSRF

Module: `scripts/_rules_injection.py`

### cmdi-code-eval

**critical** | confidence medium | confirm before reporting | stacks: node, python, php

- What: eval() / new Function() / exec(), a template compiled from a string, or an object deserializer (pickle, yaml.load, node-serialize, unserialize) runs request input as code
- Class: code injection
- Why agents produce it: Calculators, formula fields and "run this snippet" features get built with eval(req.body.expr); Flask pages get built with render_template_string(f"...{name}..."), which evaluates Jinja in the value. Import and session features reach for pickle.loads() or unserialize() because they round-trip any object.
- False-positive trap: Only request input is reported, except node-serialize, yaml.load() without SafeLoader and js-yaml load() before version 4: those are reported on any data (medium when the data's source is not traced and the file is no request handler) but skipped when they read a file the developer named. PyYAML pinned at 5.4 or newer makes a bare yaml.load() safe. eval of a constant, render_template_string() with a fixed template and the value passed as a variable, ast.literal_eval(), yaml.safe_load() and pickle of the app's own cache files are safe. PHP unserialize() of request data with ['allowed_classes' => false] is medium, since the PHP manual still warns against it.
- Fix: [uploads-and-fetch.md#code-evaluation](uploads-and-fetch.md#code-evaluation)

### cmdi-node-shell

**critical** | confidence medium | confirm before reporting | stacks: node

- What: exec() / execSync() (or spawn with shell: true) runs a command string built from a variable
- Class: OS command injection
- Why agents produce it: "Convert this file" and "download this URL" features get built as exec(`ffmpeg -i ${input} ...`); exec always runs through a shell, so ; and $() in the value run commands.
- False-positive trap: execFile('ffmpeg', ['-i', input]) and spawn(cmd, [args]) without shell: true never use a shell and are safe even with user input in an argument. A fully constant command is not flagged. Severity is lower when the file does not look like a request handler.
- Fix: [uploads-and-fetch.md#shell-commands](uploads-and-fetch.md#shell-commands)

### cmdi-php-shell

**critical** | confidence medium | confirm before reporting | stacks: php, laravel

- What: shell_exec() / exec() / system() / passthru() or backticks run a command built from a variable
- Class: OS command injection
- Why agents produce it: PHP's shell functions take one string; agents interpolate request values into it for image or PDF tools.
- False-positive trap: A value passed through escapeshellarg() is safe, and constant commands are not flagged. Values checked with is_numeric(), ctype_*() or filter_var() first are not flagged. PDO's ->exec() is a method, not the shell function, and is not matched. Vendored libraries (libs/, vendor/, a license banner inside lib/) are skipped.
- Fix: [uploads-and-fetch.md#shell-commands](uploads-and-fetch.md#shell-commands)

### cmdi-python-shell

**critical** | confidence medium | confirm before reporting | stacks: python, django, flask, fastapi

- What: os.system() / os.popen() or subprocess with shell=True runs a command built from a variable
- Class: OS command injection
- Why agents produce it: f-strings make os.system(f'convert {name} ...') and subprocess.run(cmd, shell=True) one-liners, so agents reach for them in upload and export handlers.
- False-positive trap: subprocess.run(['convert', name, out]) with a list and no shell=True is safe. A value wrapped in shlex.quote() is safe. Constant commands and click / typer command arguments (the operator's own input) are not flagged; severity is lower outside request handlers.
- Fix: [stack-python.md#command-injection](stack-python.md#command-injection)

### sqli-js-string-query

**critical** | confidence medium | confirm before reporting | stacks: node

- What: SQL string built with interpolation or + is passed to query(), knex.raw(), sequelize.literal() or similar
- Class: SQL injection
- Why agents produce it: Template literals make it easy to drop a variable into SQL; agents do it for dynamic WHERE, IN lists and ORDER BY, where the parameterized form takes more code.
- False-positive trap: Parameterized calls (pool.query('... $1', [id]), knex.whereRaw('x = ?', [x]), a { text, values } config object) are safe. Tagged templates (sql`...`, Prisma.sql) are safe. When the call passes parameters, only request input or an ORDER BY value is flagged, so placeholder-built WHERE clauses stay quiet. A sort column picked through an allowlist (ALLOWED.includes(x) ? x : 'id'), a loop over a constant list, and LIMIT with a number-typed value are not flagged. supabase .or() with the signed-in user's own id is not flagged; in browser code it is low, since it runs under the caller's own RLS.
- Fix: [uploads-and-fetch.md#sql-queries](uploads-and-fetch.md#sql-queries)

### sqli-php-string-query

**critical** | confidence medium | confirm before reporting | stacks: php, laravel

- What: SQL with an interpolated or concatenated variable reaches DB::raw(), a *Raw() method, PDO or mysqli
- Class: SQL injection
- Why agents produce it: Laravel's raw helpers and plain PDO accept any string; agents interpolate "$id" or concatenate request values because it works in the demo.
- False-positive trap: whereRaw('x = ?', [$x]), DB::select($sql, [$x]) and PDO prepare() with ? or :name placeholders are safe. Interpolating a table property ({$this->table}, $this->schemaTable), (int) casts, arithmetic, in_array() / match() picks and values checked with ctype_digit(), is_numeric(), filter_var() or an anchored digits-only preg_match() are not flagged. $wpdb->prepare() is safe. Vendored libraries (libs/, vendor/, or a license banner inside lib/) are skipped.
- Fix: [uploads-and-fetch.md#sql-queries](uploads-and-fetch.md#sql-queries)

### sqli-prisma-raw-unsafe

**critical** | confidence high | confirm before reporting | stacks: node, prisma

- What: $queryRawUnsafe / $executeRawUnsafe gets a string built with interpolation
- Class: SQL injection
- Why agents produce it: The tagged $queryRaw template parameterizes, but agents switch to the Unsafe variant to build a dynamic query (search, sort, filters) and interpolate values into the string.
- False-positive trap: prisma.$queryRaw`... ${x}` (tagged template) and Prisma.sql are safe: do not flag them. $queryRawUnsafe('... WHERE id = $1', id) with placeholders and separate arguments is safe. An interpolated constant (an ALL_CAPS table name) is not flagged.
- Fix: [uploads-and-fetch.md#sql-queries](uploads-and-fetch.md#sql-queries)

### sqli-python-string-query

**critical** | confidence medium | confirm before reporting | stacks: python, django, flask, fastapi

- What: SQL built with an f-string, % or .format() reaches cursor.execute(), .raw(), RawSQL(), .extra() or text()
- Class: SQL injection
- Why agents produce it: f-strings are the shortest way to build a query, so agents use them in cursor.execute(), Django .raw() and SQLAlchemy text() instead of passing parameters.
- False-positive trap: cursor.execute('... %s', (x,)) passes x as a parameter: the comma, not the % operator, is the safe form. .raw('... %s', [x]), RawSQL(sql, [x]), text(':x') with bound params and the ORM (.filter(name=x)) are safe. psycopg sql.SQL(...).format(sql.Identifier(x)) is safe.
- Fix: [stack-python.md#sql-injection](stack-python.md#sql-injection)

### nosqli-request-filter

**high** | confidence medium | confirm before reporting | stacks: node, python

- What: a MongoDB filter takes a value (or the whole object) straight from the request body or query string
- Class: NoSQL operator injection
- Why agents produce it: Agents write User.findOne({ email: req.body.email, password: req.body.password }); a JSON body can send an object with a query operator instead of a string, and the filter then matches any user.
- False-positive trap: Values cast to a string (String(x)), wrapped as { $eq: x }, checked with typeof x === 'string', or parsed by a schema (zod, Joi, Pydantic) are safe. req.params values are always strings. exists(), remove(), count() and update() count only on a Mongo-looking receiver (a Model, a collection), and Sequelize-style { where: ... } options are not Mongo filters. Projects that set sanitizeFilter: true on a patched Mongoose (6.13.9, 7.8.9, 8.22.1, 9.1.6 or newer) are skipped; on older releases findings drop to medium. express-mongo-sanitize counts only when app.use() mounts it on Express 4; it does not protect req.query on Express 5.
- Fix: [uploads-and-fetch.md#nosql-filters](uploads-and-fetch.md#nosql-filters)

### path-traversal-request

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: a file is read, written or sent from a path built with request input
- Class: path traversal
- Why agents produce it: Download and preview endpoints get written as res.sendFile(path.join(dir, req.query.file)) or open(os.path.join(DIR, name)); ../ in the value reaches any file.
- False-positive trap: path.basename(), secure_filename(), send_from_directory(), res.sendFile(name, { root }) and a resolve-then-startsWith(root) check are safe, and so are PHP values checked with ctype_*(), is_numeric() or an anchored preg_match(). FastAPI / Flask path parameters without the path converter cannot contain a slash and are not flagged (they can still hold a backslash, a separator on Windows hosts). PHP include of a fixed file is not matched. Archive entry names (zip slip) count only when the file uses an archive library; tarfile extractall() is reported only without filter= in a request handler.
- Fix: [uploads-and-fetch.md#file-paths-from-the-request](uploads-and-fetch.md#file-paths-from-the-request)

### sqli-laravel-request-column

**high** | confidence medium | confirm before reporting | stacks: laravel, php

- What: orderBy() / groupBy() takes its column name from request input
- Class: SQL injection (column name)
- Why agents produce it: Sortable tables are wired straight to ?sort=; Laravel binds values but cannot bind column names, and its docs say never to let user input pick them.
- False-positive trap: A column checked with in_array() against a fixed list, a match() or a validation rule 'in:a,b' / Rule::in() is safe. The sort direction is validated by Laravel itself.
- Fix: [stack-laravel.md#raw-queries](stack-laravel.md#raw-queries)

### ssrf-request-url

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: server code fetches a URL taken from the request with no host allowlist or private-IP check
- Class: SSRF
- Why agents produce it: Link previews, "import from URL", avatar-by-URL and webhook testers are built as fetch(req.query.url); the server then reaches cloud metadata and internal services for the caller.
- False-positive trap: A URL with a fixed host where the request only fills the path or query (`https://api.example.com/items/${id}`) is not SSRF and is not flagged, also when the fixed base is an ALL_CAPS constant defined in the project; an unresolved base constant is medium. Files that allowlist hosts, use an SSRF-filtering agent, or resolve the name and check the address are skipped; a check of the host name as text, or an address check with redirects turned on, only lowers the finding to medium. Comments and flag names do not count as guards. Browser-side fetch is not SSRF.
- Fix: [uploads-and-fetch.md#server-side-fetch](uploads-and-fetch.md#server-side-fetch)

### upload-client-filename

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: an upload is written to disk under the file name the client sent
- Class: file upload path traversal
- Why agents produce it: multer's filename callback, Flask's file.filename and PHP's $_FILES name are the obvious names to save under; a name like ../../app.js writes outside the upload folder.
- False-positive trap: path.basename(), secure_filename(), a random name (uuid, crypto.randomUUID(), random_bytes, hashName()) and taking only the extension are safe. Django's storage.save() validates the path. Using the original name only for display, a database column, a UI message or a browser-side File / Promise is not flagged, and "use client" files are skipped. Laravel / Symfony move() keeps only the base name, so it is medium (overwrite, client extension), and skipped for a fresh random folder. PHP basename() of the client name is still reported when no extension allowlist exists.
- Fix: [uploads-and-fetch.md#server-side-file-names](uploads-and-fetch.md#server-side-file-names)

### xss-blade-unescaped

**high** | confidence medium | confirm before reporting | stacks: laravel, php

- What: Blade {!! !!} prints a value without escaping
- Class: XSS
- Why agents produce it: {!! !!} is how Blade prints HTML, so agents use it for rich text and markdown and sometimes for plain fields.
- False-positive trap: {{ }} is escaped. {!! !!} around csrf_field(), method_field(), __() / trans() strings, route()/url()/asset(), e(...), escape*() helpers, clean()/Purifier::clean(), form builders (Form::, Html::, *Form::) and $slot is not flagged. json_encode() is flagged (medium) only outside a <script> block, where a quote breaks out of an attribute. A project helper that builds HTML is reported once, low when it escapes or renders a view; a markdown helper with html_input 'escape' or 'strip' and allow_unsafe_links false is not flagged.
- Fix: [stack-laravel.md#blade-raw-output](stack-laravel.md#blade-raw-output)

### xss-framework-raw-html

**high** | confidence medium | confirm before reporting | stacks: node, laravel, php, python, django, flask, fastapi

- What: v-html, {@html}, bypassSecurityTrustHtml or a server template's raw tag (EJS <%-, Handlebars {{{, Pug !=, |safe / |raw, autoescape off) renders a value with no sanitizer
- Class: XSS
- Why agents produce it: Vue, Svelte, Angular and the server template engines escape by default; agents opt out with v-html, {@html}, <%- or {{{ }}} to show rich text or markdown, or turn autoescape off to stop entities showing.
- False-positive trap: Plain {{ }} / { } / <%= %> interpolation is escaped and never flagged. A value computed through DOMPurify or another sanitizer in the component's script (also through a member assignment), or a fixed string, is not flagged. EJS include() and layout body are not flagged. Angular's own [innerHTML] binding is sanitized by Angular and is not matched. With a server-side purifier in the project, v-html on API data is reported at medium.
- Fix: [uploads-and-fetch.md#rendering-html](uploads-and-fetch.md#rendering-html)

### xss-markdown-rehype-raw

**high** | confidence medium | confirm before reporting | stacks: node

- What: react-markdown / unified uses rehype-raw with no rehype-sanitize after it
- Class: XSS
- Why agents produce it: Chat UIs add rehype-raw so the model's HTML renders; react-markdown is safe by default only until that plugin is added.
- False-positive trap: react-markdown without rehype-raw is safe and never flagged. rehype-raw followed by rehype-sanitize in the same plugin list is safe; sanitize placed before raw is flagged. A sanitizer applied in another shared config file needs a manual check.
- Fix: [uploads-and-fetch.md#markdown-and-model-output](uploads-and-fetch.md#markdown-and-model-output)

### xss-python-template-safe

**high** | confidence medium | confirm before reporting | stacks: python, django, flask, fastapi

- What: a Jinja / Django template uses |safe or autoescape off, or code calls mark_safe() / Markup() on a variable
- Class: XSS
- Why agents produce it: |safe and mark_safe() are the one-word fix when HTML shows up escaped, so agents add them to rich text, markdown output and sometimes user fields.
- False-positive trap: |tojson|safe, json_script, values sanitized with bleach / nh3, format_html() and Markup('<b>{}</b>').format(x) (which escapes x) are safe. mark_safe() on a fixed string, an escape() result, render_to_string() or Literal / int / date-typed values is not flagged. |safe in a plain-text template (an email text part, SMS, subject or title template with no HTML tags) and on a {% cycle %} / {% with %} constant is not flagged; on a server-made SVG or QR code, or in an HTML email template (an emails/ or mail/ folder), it is low.
- Fix: [stack-python.md#template-xss](stack-python.md#template-xss)

### xss-react-dangerous-html

**high** (medium when the HTML comes from a prop or parameter the scanner cannot follow; low when a lint suppression above the line gives a reason, or in a React Email template) | confidence medium | confirm before reporting | stacks: node, nextjs, nextjs-app, nextjs-pages, react-vite, cra, expo

- What: dangerouslySetInnerHTML renders a value with no sanitizer
- Class: XSS
- Why agents produce it: Rendering rich text, markdown or a model's answer as HTML is one prop away, and the demo content is harmless, so agents skip DOMPurify.
- False-positive trap: A value wrapped in DOMPurify.sanitize() (or assigned from it, also through a useState setter), a fixed string or template, an imported constant, a loop over a constant array, JSON.stringify() into a JSON-LD script tag, syntax-highlighter output (shiki codeToHtml, hljs, Prism), mermaid.render() SVG (unless securityLevel is loose) and marked with a DOMPurify postprocess hook are not flagged. The shadcn/ui chart.tsx style tag is skipped, and a lint suppression that gives a reason lowers the finding to low, as does a React Email template (mail clients run no scripts; still escape user text there). react-markdown without rehype-raw needs no dangerouslySetInnerHTML at all.
- Fix: [uploads-and-fetch.md#rendering-html](uploads-and-fetch.md#rendering-html)

### xss-reflected-response

**high** | confidence medium | confirm before reporting | stacks: node, python, php

- What: request input is sent back inside an HTML response without escaping
- Class: XSS (reflected)
- Why agents produce it: Quick endpoints build HTML with a template string: res.send(`<h1>${req.query.name}</h1>`), a Flask route returning f"<p>{name}</p>", or PHP echo $_GET[...]. Express and Flask send strings as text/html.
- False-positive trap: Only request input is reported. Values passed through an escape function (escape-html, markupsafe.escape, htmlspecialchars), JSON responses (res.json, jsonify, json_encode) and render_template() / res.render() with autoescape are safe. PHP HTML built into a variable ($html .= '<pre>' . $_GET['x']) that is printed later, maybe by another file, is reported at medium.
- Fix: [uploads-and-fetch.md#rendering-html](uploads-and-fetch.md#rendering-html)

### ssrf-next-image-any-host

**medium** | confidence high | direct | stacks: nextjs, nextjs-app, nextjs-pages

- What: next/image remotePatterns allows any hostname ('**'), or images.dangerouslyAllowLocalIP is true
- Class: SSRF / open image proxy
- Why agents produce it: A wildcard host is the quickest way to stop the 'hostname is not configured' error for user avatars, and dangerouslyAllowLocalIP is the quickest way past a 400 on a private image host.
- False-positive trap: A list of exact hosts (and a pathname) is not flagged, but an allowed host that redirects still sends the optimizer elsewhere (Next.js 16 follows up to images.maximumRedirects, 3 by default, without checking remotePatterns again), so check for open redirects or user uploads on those hosts. With images.unoptimized: true or a custom loader the Next.js optimizer does not fetch, so the rule is skipped.
- Fix: [stack-nextjs.md#remote-images](stack-nextjs.md#remote-images)

### upload-client-mime-check

**medium** | confidence low | confirm before reporting | stacks: node, python, php

- What: upload type is validated only by the Content-Type the client sent
- Class: file upload type check
- Why agents produce it: multer's fileFilter examples check file.mimetype; that header is set by the client, so an HTML or SVG file passes as image/png.
- False-positive trap: A check of the file's bytes (file-type, finfo, getimagesize, Pillow, python-magic) or re-encoding the image in the same file makes this safe. If the file is stored under a random name with a fixed extension and served with nosniff, the header check is only cosmetic.
- Fix: [uploads-and-fetch.md#validate-by-content](uploads-and-fetch.md#validate-by-content)

### upload-no-size-limit

**medium** | confidence medium | confirm before reporting | stacks: node, flask

- What: upload middleware has no file size limit
- Class: file upload size
- Why agents produce it: multer and express-fileupload accept files of any size by default; Flask has no request size limit until MAX_CONTENT_LENGTH is set.
- False-positive trap: A limit enforced by the reverse proxy (nginx client_max_body_size) or the platform also works; check the deploy config before reporting. multer({ limits: { fileSize } }) is safe.
- Fix: [uploads-and-fetch.md#size-limits](uploads-and-fetch.md#size-limits)

### xss-dom-innerhtml

**medium** | confidence low | confirm before reporting | stacks: *

- What: innerHTML / insertAdjacentHTML / document.write gets data built into HTML with no escaping
- Class: XSS
- Why agents produce it: Building a list with innerHTML = items.map(i => `<li>${i.name}</li>`) is the quickest way to render fetched data, and nothing escapes i.name.
- False-positive trap: Assigning a fixed string, clearing with '', values passed through an escape function (escapeHtml(x), DOMPurify.sanitize(x)), numbers and lengths, and lookups in an ALL_CAPS constant map are not flagged. Unknown helper calls are not flagged, so a helper that escapes internally stays quiet. jQuery .html(data.field) in a callback of the app's own $.ajax / $.getJSON is reported as low: servers often send fragments they rendered with an escaping template. The docs/ site is not scanned.
- Fix: [uploads-and-fetch.md#rendering-html](uploads-and-fetch.md#rendering-html)

## Deployment and configuration

Module: `scripts/_rules_deploy.py`

### deploy-cors-credentials-laravel

**high** | confidence medium | confirm before reporting | stacks: laravel

- What: config/cors.php allows every origin with supports_credentials => true
- Class: CORS misconfiguration
- Why agents produce it: Agents open CORS fully to unblock a separate SPA frontend and switch on credentials for Sanctum cookie auth.
- False-positive trap: allowed_origins ['*'] with supports_credentials false is fine for token APIs. An explicit FRONTEND_URL list with credentials is the correct Sanctum setup.
- Fix: [stack-laravel.md#cors](stack-laravel.md#cors)

### deploy-cors-credentials-node

**high** | confidence high | confirm before reporting | stacks: node

- What: CORS reflects any Origin while allowing credentials
- Class: CORS misconfiguration
- Why agents produce it: A CORS error is the most common blocker when the frontend and API live on different domains; the fastest generated fix is cors({ origin: true, credentials: true }).
- False-positive trap: Access-Control-Allow-Origin: * without credentials is fine for a public or bearer-token API (a browser will not let a page read a credentialed response whose Access-Control-Allow-Origin is *). origin: '*' with credentials: true is broken, not exploitable for reading. An exact allowlist (Set or array lookup) with credentials is fine. If the API uses Authorization headers only, severity drops to medium.
- Fix: [stack-express-node.md#cors-with-credentials](stack-express-node.md#cors-with-credentials)

### deploy-cors-credentials-python

**high** | confidence high | confirm before reporting | stacks: python

- What: CORS allows every origin with credentials (FastAPI, django-cors-headers or Flask-CORS reflect the Origin)
- Class: CORS misconfiguration
- Why agents produce it: FastAPI tutorials show allow_origins=['*'] and agents add allow_credentials=True to make cookie login work; Starlette then echoes any Origin.
- False-positive trap: allow_origins=['*'] without allow_credentials=True is fine for a public API. An explicit list of your own origins with credentials is fine. CORS_ALLOW_ALL_ORIGINS in a dev-only settings module is not flagged; in a base module that the production settings import and switch off it is skipped, or reported low when no deploy config names that production module.
- Fix: [stack-python.md#cors](stack-python.md#cors)

### deploy-django-debug

**high** | confidence medium | confirm before reporting | stacks: django

- What: Django DEBUG is on (or defaults to on) in a settings module that production may load
- Class: debug mode in production
- Why agents produce it: startproject ships DEBUG = True and agents deploy the generated settings as they are; the debug page then shows tracebacks, settings and request data to anyone.
- False-positive trap: DEBUG = True in a dev-only settings module (settings/dev.py, local.py) that production never imports is fine. The rule reads DJANGO_SETTINGS_MODULE from the Dockerfile, Procfile, compose and env files, manage.py and wsgi.py: when the production module imports this one and sets DEBUG off it stays quiet, and when only a production.py that nobody names overrides it the finding drops to low. DEBUG read from an env var that defaults to off is fine.
- Fix: [stack-python.md#django-debug](stack-python.md#django-debug)

### deploy-flask-debug

**high** | confidence medium | confirm before reporting | stacks: flask

- What: Flask debug mode or the Werkzeug debugger is enabled where production may run it
- Class: debug mode in production
- Why agents produce it: Flask tutorials end with app.run(debug=True) and agents deploy that file with python app.py, or set FLASK_DEBUG=1 in the Dockerfile to see errors. The Werkzeug debugger runs code on request.
- False-positive trap: app.run(debug=True) under if __name__ == '__main__' is fine when production starts the app with gunicorn, uwsgi or waitress (the rule checks Procfile, Dockerfile and dependencies). FLASK_DEBUG in .flaskenv or a local .env is the normal dev setup and is not flagged.
- Fix: [stack-python.md#flask-debug](stack-python.md#flask-debug)

### deploy-laravel-debug

**high** | confidence high | confirm before reporting | stacks: laravel

- What: Laravel APP_DEBUG is on in a production env file, a committed .env, or config/app.php
- Class: debug mode in production
- Why agents produce it: Laravel's .env.example ships APP_DEBUG=true and agents copy it to the server, or upload the whole project with its local .env to shared hosting.
- False-positive trap: APP_DEBUG=true in a local, untracked .env with APP_ENV=local is the normal dev setup and is not flagged. .env.example is not scanned. Confirm which env file the server actually loads.
- Fix: [stack-laravel.md#debug-mode](stack-laravel.md#debug-mode)

### deploy-sensitive-file-public

**high** | confidence high | confirm before reporting | stacks: *

- What: An env file, key, database dump, backup or log sits inside a folder that is served as-is
- Class: sensitive files served
- Why agents produce it: Agents drop seed dumps, SQLite files and exported backups into public/ or static/ so the app can fetch them, and copy .env next to the built files.
- False-positive trap: public/.htaccess, .well-known/, .gitkeep and robots.txt are not flagged. A file in public/ is only live if the deploy includes it; check the deployed URL with live-exposure-check.
- Fix: [stack-nextjs.md#files-in-public](stack-nextjs.md#files-in-public)

### deploy-static-project-root

**high** | confidence high | confirm before reporting | stacks: *

- What: Static file serving points at the project folder, so .env, .git, source or database files are downloadable
- Class: sensitive files served
- Why agents produce it: The shortest way to serve a frontend from one server file is express.static(__dirname) or static_folder='.', and the shortest Firebase or nginx deploy copies the whole folder.
- False-positive trap: express.static(path.join(__dirname, 'public')) or a dedicated dist/ folder is fine. Express 5 hides dotfiles by default, Express 4 still serves .git/config. send_from_directory('.', 'index.html') with a fixed file name is fine. Firebase skips dotfiles when ignore lists '**/.*'.
- Fix: [stack-express-node.md#static-files](stack-express-node.md#static-files)

### deploy-cookie-flags-node

**medium** | confidence medium | confirm before reporting | stacks: node

- What: A session or auth cookie is set without httpOnly, with secure: false, or with sameSite: 'none'
- Class: weak cookie flags
- Why agents produce it: secure: false is added to make cookies work on http://localhost and ships; sameSite: 'none' is added to fix cross-domain login; res.cookie and Next.js cookies().set default httpOnly to off.
- False-positive trap: secure: process.env.NODE_ENV === 'production' is fine. Non-auth cookies (theme, locale) and CSRF/XSRF cookies that JavaScript must read are not flagged. express-session and iron-session default to httpOnly, so only an explicit httpOnly: false is flagged there. secure: false inside an if (development) branch is skipped.
- Fix: [stack-express-node.md#cookie-flags](stack-express-node.md#cookie-flags)

### deploy-cookie-flags-php

**medium** | confidence medium | confirm before reporting | stacks: php

- What: Plain PHP sets a session or token cookie without HttpOnly, or turns the session cookie flags off
- Class: weak cookie flags
- Why agents produce it: setcookie('session', $id) is the shortest form in every PHP tutorial, and both HttpOnly and Secure default to off; ini_set('session.cookie_httponly', 0) is added to let JavaScript read the cookie.
- False-positive trap: Theme, locale and CSRF cookies are not flagged. A setcookie with httponly passed as a variable, or an options array built elsewhere, cannot be read and is skipped. Clearing a cookie (empty value or an expiry in the past) is skipped. Laravel's own session cookie is covered by deploy-laravel-session-cookie.
- Fix: [stack-laravel.md#plain-php-cookies](stack-laravel.md#plain-php-cookies)

### deploy-cookie-flags-python

**medium** | confidence medium | confirm before reporting | stacks: python

- What: A session or token cookie is set without httponly=True, or with secure=False
- Class: weak cookie flags
- Why agents produce it: FastAPI, Flask and Django set_cookie all default httponly to False, and generated login code calls response.set_cookie('access_token', token) with no flags.
- False-positive trap: Cookies that are not session or token cookies are not flagged. httponly passed from settings (httponly=settings.X) counts as set. Django's own session cookie is HttpOnly by default.
- Fix: [stack-python.md#cookies](stack-python.md#cookies)

### deploy-dev-server-in-prod

**medium** | confidence medium | confirm before reporting | stacks: *

- What: The production start command runs a development server
- Class: dev server in production
- Why agents produce it: Asked to deploy to a VPS or PaaS, agents reuse the command that worked locally: npm run dev under PM2, next dev in a Dockerfile, manage.py runserver or php artisan serve in a Procfile.
- False-positive trap: Dev-named files (Dockerfile.dev, docker-compose.override.yml, Procfile.dev, .devcontainer) and plain docker-compose.yml files used for local work are skipped. In package.json only start scripts that are not the template default are flagged (react-scripts start, ng serve and expo start are left alone).
- Fix: [stack-express-node.md#dev-server-in-production](stack-express-node.md#dev-server-in-production)

### deploy-directory-listing

**medium** | confidence high | confirm before reporting | stacks: *

- What: Directory listing is on (serve-index, nginx autoindex, Apache Options Indexes or Caddy browse)
- Class: directory listing
- Why agents produce it: Asked to let users or admins browse files, agents mount serve-index on a folder or switch on autoindex, and the folder later fills with logs, backups, keys or uploads.
- False-positive trap: A listing of a folder that holds only public downloads is a design choice; confirm what the folder contains on the server. Severity is high when the path looks like logs, keys, backups, uploads or ftp. Listings mounted inside an if (development) check are skipped, and Options -Indexes is the safe form.
- Fix: [stack-express-node.md#directory-listing](stack-express-node.md#directory-listing)

### deploy-error-stack-leak

**medium** | confidence high | confirm before reporting | stacks: node, python

- What: An error response sends the stack trace (err.stack, a Python traceback, or the errorhandler middleware) to the client
- Class: stack traces in responses
- Why agents produce it: Agents return the full error to make debugging easier and the debug branch ships: res.status(500).json({ error: err.stack }), return {'error': traceback.format_exc()}, or app.use(errorhandler()) copied from an Express example.
- False-positive trap: A stack included only when NODE_ENV is development (or under if app.debug) is fine; the rule skips responses whose arguments or enclosing if mention the environment, and errorhandler() mounted inside such a check. Logging the stack server-side is fine.
- Fix: [stack-express-node.md#error-handler](stack-express-node.md#error-handler)

### deploy-laravel-session-cookie

**medium** | confidence high | confirm before reporting | stacks: laravel

- What: config/session.php weakens the session cookie (http_only false, secure false, or same_site none)
- Class: weak cookie flags
- Why agents produce it: Agents loosen session cookie settings to get a cross-domain SPA login working over plain HTTP.
- False-positive trap: The default 'secure' => env('SESSION_SECURE_COOKIE') is fine; set SESSION_SECURE_COOKIE=true in the production env. same_site none is sometimes needed for embedded apps.
- Fix: [stack-laravel.md#session-cookies](stack-laravel.md#session-cookies)

### deploy-log-secrets-laravel

**medium** | confidence medium | confirm before reporting | stacks: php

- What: PHP code logs the whole request, a password or token, or the whole config
- Class: secrets or PII in logs
- Why agents produce it: Log::info($request->all()) is the quickest way to see what a form posts and it stays in the login controller.
- False-positive trap: Log::info($request->except(['password', 'token'])) or logging selected fields is fine. Logging a user id or route is fine.
- Fix: [stack-laravel.md#logging](stack-laravel.md#logging)

### deploy-log-secrets-node

**medium** | confidence medium | confirm before reporting | stacks: node

- What: Server code logs secrets, tokens, auth headers or request bodies with passwords
- Class: secrets or PII in logs
- Why agents produce it: Debug statements such as console.log(req.body) on the login route, console.log(req.headers) or console.log(process.env) are added while fixing a bug and never removed.
- False-positive trap: Logging the presence of a value (!!token, token ? 'set' : 'missing', token.length) or a hashed, fingerprinted or redacted form (hash(token), s.replaceAll(token, '[redacted]')) is fine, and so are message-catalog keys (messages.missingCredentials) and logs inside an if (development) block (with or without braces). Local scripts, CLIs, seeds and emulators (scripts/, bin/, cli/, seed/) are reported low. Structured loggers with redact configured are skipped. Browser and app code is not checked.
- Fix: [stack-express-node.md#logging](stack-express-node.md#logging)

### deploy-log-secrets-python

**medium** | confidence medium | confirm before reporting | stacks: python

- What: Python code prints or logs os.environ, auth headers, tokens or request bodies with passwords
- Class: secrets or PII in logs
- Why agents produce it: print(os.environ) and logger.info(request.json) are added while debugging config or login and stay in.
- False-positive trap: os.environ.get('X') of one non-secret setting is fine. Logging len(token) or whether a value is set is fine. Words inside log strings are ignored, f-string expressions are checked.
- Fix: [stack-python.md#logging](stack-python.md#logging)

### deploy-source-maps

**medium** | confidence high | confirm before reporting | stacks: node

- What: The production build publishes source maps (the original source code)
- Class: source maps in production
- Why agents produce it: productionBrowserSourceMaps or build.sourcemap: true is copied in to debug a production error and never removed; Create React App emits maps unless told not to.
- False-positive trap: Maps uploaded to an error tracker and deleted before deploy (filesToDeleteAfterUpload, deleteSourcemapsAfterUpload) are fine and skip the rule. Open-source frontends lose little: with an open-source LICENSE file the finding drops to low (a package.json license alone does not count, npm init writes ISC everywhere). Vercel Protected Source Maps gate .map files on that host.
- Fix: [stack-nextjs.md#source-maps](stack-nextjs.md#source-maps)

### deploy-express-no-helmet

**low** | confidence medium | confirm before reporting | stacks: express

- What: The Express app sets no security headers (helmet missing or never called), or turns helmet's CSP off
- Class: missing security headers
- Why agents produce it: Headers are not needed for the app to work, so agents skip helmet, install it and never call it, or disable its CSP when an inline script breaks.
- False-positive trap: A reverse proxy (nginx, Caddy, the host) may add the headers; the rule checks configs in the repo only. helmet counts only when server code calls it (a commented-out app.use(helmet()) does not). A pure JSON API needs fewer headers than an app that serves HTML.
- Fix: [stack-express-node.md#helmet](stack-express-node.md#helmet)

### deploy-express-node-env

**low** | confidence low | confirm before reporting | stacks: express

- What: Express app is deployed without NODE_ENV=production and has no error handler of its own
- Class: stack traces in production
- Why agents produce it: Agents write a Dockerfile or PM2 config that runs node server.js and never set NODE_ENV; Express's default error handler then returns err.stack in every 500 response.
- False-positive trap: Many hosts set NODE_ENV=production for you (Heroku's Node buildpack does), and the value may live in the host dashboard. Only flagged when a deploy config exists in the repo, none of them sets NODE_ENV=production, and the app has no 4-argument error handler (typed, multi-line and trailing-comma parameter lists count).
- Fix: [stack-express-node.md#production-mode](stack-express-node.md#production-mode)

### deploy-laravel-ignition

**low** | confidence high | confirm before reporting | stacks: laravel

- What: Ignition (Laravel's debug error page) is installed for production or is a vulnerable version
- Class: debug tooling in production
- Why agents produce it: Agents add packages with composer require without --dev, and older Laravel 8 apps still pin facade/ignition below the CVE-2021-3129 fix.
- False-positive trap: spatie/laravel-ignition in require-dev is the Laravel default and is fine when production runs composer install --no-dev. The CVE only bites with APP_DEBUG on, but upgrade anyway.
- Fix: [stack-laravel.md#ignition](stack-laravel.md#ignition)

### deploy-nextjs-no-security-headers

**low** | confidence medium | confirm before reporting | stacks: nextjs

- What: The Next.js app sets no security headers (CSP, HSTS, nosniff, frame-ancestors)
- Class: missing security headers
- Why agents produce it: Headers are not needed for the app to work, so agents never add a headers() block.
- False-positive trap: Headers may be set by the CDN, reverse proxy or host dashboard; the rule checks next.config headers(), proxy.ts/middleware.ts, vercel.json, netlify.toml, _headers and nginx configs in the repo (header names in comments do not count). Confirm on the live URL with live-exposure-check before reporting.
- Fix: [stack-nextjs.md#security-headers](stack-nextjs.md#security-headers)

## Supply chain

Module: `scripts/_rules_supply.py`

### supply-installed-worm-artifact

**critical** | confidence medium | confirm before reporting | stacks: node

- What: an installed package ships a known worm file or an install script that downloads and runs code
- Class: worm file or download-and-run install script in node_modules
- Why agents produce it: Dependencies run preinstall and postinstall scripts with the developer's full rights. The 2025-2026 npm worms (Shai-Hulud, ChainDrop) used exactly these hooks to steal tokens.
- False-positive trap: A postinstall that runs a local build or a node script shipped in the package (node install.js, node -e "try{require('./postinstall')}catch(e){}") is normal and is not reported. Read the reported script before deleting anything.
- Fix: [supply-chain.md#after-a-compromise](supply-chain.md#after-a-compromise)

### supply-known-bad-version

**critical** | confidence high | direct | stacks: *

- What: a lockfile, manifest or installed package pins a release known to be malicious
- Class: known malicious release installed or locked
- Why agents produce it: Compromised maintainer accounts and self-spreading worms publish malicious versions of popular packages; an install during the exposure window locks them in, and AI-built apps rarely review lockfile changes.
- False-positive trap: Only exact versions from public advisories are listed (see KNOWN_BAD in _rules_supply.py). A version range in package.json is not a finding by itself; the lockfile shows what was installed. Deno imports (npm:pkg@1.2.3, esm.sh/pkg@1.2.3) in deno.json or Supabase Edge Functions are checked the same way: only an exact version counts.
- Fix: [supply-chain.md#known-bad-versions](supply-chain.md#known-bad-versions)

### supply-risky-lifecycle-script

**high** | confidence medium | confirm before reporting | stacks: node

- What: a preinstall, install, postinstall or prepare script downloads code or runs a known worm tell
- Class: install script downloads or runs remote code
- Why agents produce it: Install hooks run on every npm install, including in CI with deploy tokens. Agents paste setup one-liners (curl ... | sh) into postinstall to automate a step.
- False-positive trap: prisma generate, patch-package, husky, a local build or node scripts/setup.js are normal hooks and are not reported. node -e is only reported when it spawns processes, fetches or decodes data.
- Fix: [supply-chain.md#lifecycle-script-tells](supply-chain.md#lifecycle-script-tells)

### supply-url-dependency

**medium** | confidence medium | confirm before reporting | stacks: *

- What: a dependency is installed from a URL, plain http or an unpinned git ref instead of the registry
- Class: dependency installed from a URL or git
- Why agents produce it: URL specs skip the registry's integrity and malware checks; PhantomRaven packages declared http tarball dependencies so the payload never appeared on npm. Agents add git or tarball specs to pull a fork or a fix that is not published yet.
- False-positive trap: file:, link:, workspace: and npm: aliases are local or registry specs and are not reported. A git dependency pinned to a full 40-character commit hash is reproducible and is not reported. Private registries over https in lockfiles are not reported.
- Fix: [supply-chain.md#url-and-git-dependencies](supply-chain.md#url-and-git-dependencies)

### supply-unlocked-dependency

**low** | confidence low | confirm before reporting | stacks: *

- What: a declared dependency is missing from the lockfile; confirm it exists on the registry before installing
- Class: dependency never installed from the lockfile
- Why agents produce it: Models invent plausible package names (about one in five suggestions in the USENIX 2025 study) and attackers register them. A name the agent added that never made it into the lockfile is exactly the package nobody has verified yet.
- False-positive trap: An offline scan cannot tell a hallucinated name from a real package added since the last install. Workspace packages and anything already in node_modules are skipped. A sub-project is only compared with a parent lockfile when it is a workspace member (or a file: dependency) of that project, and with several lockfiles in one folder a name counts as locked when any of them has it. Check the registry page: age, downloads, repository link and a name that is not a near-copy of a popular package.
- Fix: [supply-chain.md#check-a-package-before-installing](supply-chain.md#check-a-package-before-installing)

### supply-no-install-hardening

**info** | confidence high | confirm before reporting | stacks: *

- What: the package manager runs dependency install scripts or accepts releases published minutes ago (hardening advice is info; a missing lockfile is low, dangerouslyAllowAllBuilds medium)
- Class: install hardening missing
- Why agents produce it: Most 2025-2026 supply chain attacks were live for under a week. A release-age cooldown and disabled dependency scripts would have blocked them. pnpm 11 is the only manager that turns both on by default (dependency build scripts blocked unless allowed, a one-day minimumReleaseAge); npm, Yarn, Bun and uv need the settings added, and agents never add them.
- False-positive trap: Settings in a user-level ~/.npmrc or set only in CI are not visible to this scan; if they exist there, this note is already handled. pnpm 10+ blocks dependency build scripts unless allowed, and Bun runs them only for its built-in allowlist of popular packages, so for them only the release age is reported. ignore-scripts=true also skips the project's own postinstall (prisma generate and the like): read the trade-offs before adding it. Test, docs, example and template sub-projects are skipped; the advice is one note per package manager, and a lockfile left over from another manager is reported as unused instead of getting its own advice.
- Fix: [supply-chain.md#install-hardening](supply-chain.md#install-hardening)
