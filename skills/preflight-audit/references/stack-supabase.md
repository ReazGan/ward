# Supabase

Load this when the scan reports `stacks` with `supabase` or any `data-supabase-*` rule.

The browser holds the publishable (anon) key by design. The key is not the bug. A table the key can reach without Row Level Security is. Every table in an exposed schema (default `public`) that the `anon` or `authenticated` role has grants on is served at `/rest/v1/<table>` (and through GraphQL when pg_graphql is enabled), and RLS is the only thing between the anon key and the rows.

Ask the user to cross-check with Supabase's own advisors (Dashboard > Advisors > Security Advisor, or `supabase db advisors` with Supabase CLI 2.81 or newer; `supabase db lint` only runs plpgsql_check and says nothing about RLS):

| Advisor lint | Meaning | Scanner rule |
|---|---|---|
| 0013_rls_disabled_in_public | table in an exposed schema without RLS | data-supabase-rls-disabled |
| 0008_rls_enabled_no_policy | RLS on, no policy: fails closed, a broken feature, not a leak | none |
| 0024_rls_policy_always_true (docs: 0024_permissive_rls_policy) | UPDATE, DELETE or ALL `USING (true)` or `WITH CHECK (true)`; read-all SELECT policies are not flagged | data-supabase-policy-allows-all |
| 0023_sensitive_columns_exposed | table without RLS exposed to the API with private-looking columns | data-supabase-rls-disabled |
| 0015_rls_references_user_metadata | policy trusts `user_metadata` | data-supabase-user-metadata-authz |
| 0010_security_definer_view | view runs as its owner and skips RLS | data-supabase-view-bypasses-rls |
| 0002_auth_users_exposed | a view re-exposes `auth.users` | data-supabase-view-bypasses-rls |
| 0016_materialized_view_in_api | materialized view cannot enforce RLS | data-supabase-view-bypasses-rls |
| 0028 / 0029 ..._security_definer_function_executable | definer function callable by anon or authenticated | data-supabase-definer-exposed |

The advisor does not flag `for select using (true)`; judge read-all policies on private tables yourself. Data API exposure (dated): from 2026-04-28 new projects could opt out of auto-exposing new `public` tables, this became the default for new projects from 2026-05-30, and from 2026-10-30 it applies to new tables in all existing projects. Existing tables keep their grants, and a migration with an explicit `grant` plus `USING (true)` is still wide open. Write RLS anyway.

Migrations run in file order and the last definition wins. Before reporting a table, policy, view or function, search the later migrations for a `drop`, a `create or replace`, an `alter ... enable row level security` or a `do $$` loop that changes it.

## Enable RLS and owner policies

Tables made with raw SQL migrations (what agents write) do not get RLS automatically. Put this in a migration, never only in the dashboard:

```sql
alter table public.profiles enable row level security;

create policy "owners read own" on public.profiles
  for select to authenticated
  using ( (select auth.uid()) = user_id );

create policy "owners insert own" on public.profiles
  for insert to authenticated
  with check ( (select auth.uid()) = user_id );

create policy "owners update own" on public.profiles
  for update to authenticated
  using ( (select auth.uid()) = user_id )
  with check ( (select auth.uid()) = user_id );

create policy "owners delete own" on public.profiles
  for delete to authenticated
  using ( (select auth.uid()) = user_id );
```

- An UPDATE policy needs a matching SELECT policy or updates silently do nothing.
- `with check` is what stops a user writing a row that belongs to someone else.
- `auth.uid()` is null when logged out. `to authenticated` plus the explicit comparison states the intent instead of relying on null being false.
- Wrapping `auth.uid()` in `(select ...)` lets Postgres evaluate it once per query.
- Genuinely public read data: `for select to anon, authenticated using (true)` is fine with no write policy and no private columns.

False-positive notes: tables in a schema that is not exposed, tables whose grants are revoked from both `anon` and `authenticated`, and RLS switched on by a DO block or an event trigger are not reported. If RLS was switched on in the dashboard and never written to a migration, the repo does not match production: run `supabase db diff` to capture it, then confirm with the Security Advisor.

## Permissive policies

`USING (true)` turns RLS back off for that command. These all mean "anyone" or "any signed-in user":

- `using (true)` / `with check (true)` with no `to` clause (defaults to `public`, which includes anon)
- `to authenticated using (true)`
- `using (auth.role() = 'authenticated')` or `using (auth.uid() is not null)`
- `using (user_id is null or auth.uid() = user_id)`: every ownerless row is open, and the same insert rule lets anyone create such rows. Make the owner `not null default auth.uid()` instead.

The dashboard template "Enable insert for authenticated users only" is `to authenticated with check (true)`: any user can insert rows with any `user_id`. Replace with an owner check:

```sql
drop policy "Enable insert for authenticated users only" on public.posts;
create policy "insert own posts" on public.posts
  for insert to authenticated
  with check ( (select auth.uid()) = author_id );
```

RLS works on rows, not columns: an own-row policy (`auth.uid() = id`) lets the owner change every column of that row, including `role`, `is_verified`, `plan` or `credits`. Column grants (or a BEFORE trigger that resets those columns) stop that:

```sql
revoke update on public.profiles from authenticated;
grant update (display_name, bio, avatar_url) on public.profiles to authenticated;
```

False-positive notes: a read-only `using (true)` on public data (catalog, published posts) is fine and is only reported when the table name or its columns look private. An insert-only open policy on a public form table with no owner column (waitlist, contact) is fine if the app validates the fields. Restrictive policies never grant access and are ignored. A one-team app that shares every table among signed-in users is reported once per file and is fine only when public sign-ups are off (`enable_signup = false` under `[auth]` and the same in the dashboard).

## User metadata in policies

`user_metadata` (`raw_user_meta_data`) is set by the client at sign-up (`options.data`) and editable at any time with `supabase.auth.updateUser({ data: ... })`. Never base access on it, nor on a fixed admin email (`auth.jwt() ->> 'email' = 'owner@...'`), which anyone can register while email confirmation is off. Use `app_metadata`, which only the server can write (`supabaseAdmin.auth.admin.updateUserById(userId, { app_metadata: { role: 'admin' } })`), or a roles table:

```sql
create policy "admins read reports" on public.reports
  for select to authenticated
  using ( (auth.jwt() -> 'app_metadata' ->> 'role') = 'admin' );
```

In the sign-up trigger, copy display fields only and set roles to a default:

```sql
insert into public.profiles (id, full_name, role)
values (new.id, new.raw_user_meta_data ->> 'full_name', 'member');
```

False-positive note: reading `full_name` or `avatar_url` from metadata is fine and is not reported.

## Security definer functions

A `security definer` function runs with its owner's rights and ignores RLS. In an exposed schema it is callable by anon and authenticated at `/rest/v1/rpc/<name>`. Rules:

- Prefer `security invoker` (the default) so RLS applies.
- If definer is needed (a helper used inside policies), put it in a schema that is not exposed, pin `set search_path = ''`, schema-qualify every name, and grant execute only to who needs it.
- PUBLIC holds EXECUTE on every new function, so `grant ... to service_role` or a revoke from anon alone changes nothing. A function only Edge Functions call (`supabaseAdmin.rpc(...)`) stays in `public` with `revoke execute on function public.f(uuid) from public, anon, authenticated; grant execute on function public.f(uuid) to service_role;`.
- An RPC that must stay public checks the caller itself, and the check fails closed: `if auth.uid() is not null and not has_role(...)` lets every logged-out caller through.

```sql
create schema if not exists private;

create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = (select auth.uid()) and role = 'admin'
  );
$$;

revoke execute on function private.is_admin() from public, anon;
grant usage on schema private to authenticated;
grant execute on function private.is_admin() to authenticated;
```

False-positive notes: trigger functions, functions that check `auth.uid()` or `auth.jwt()` (directly or through a guard helper), functions revoked from public, anon and authenticated, and a later `alter function ... set search_path` are not reported. A definer function that returns only public, aggregate data on purpose is fine; read-only helpers such as `has_role()` are grouped as low.

## Views and RLS

A view created by `postgres` runs with the creator's rights and skips the RLS of the tables it reads. On Postgres 15 and later:

```sql
create view public.order_summary with (security_invoker = true) as
  select id, total, created_at from public.orders;

-- or for an existing view
alter view public.order_summary set (security_invoker = true);
```

- Never expose `auth.users` through a view. Copy the fields you need into `public.profiles` with a trigger.
- Materialized views cannot enforce RLS. Keep them out of exposed schemas or `revoke select ... from anon, authenticated`.

False-positive note: a view over data that is public anyway is fine; confirm what it selects.

## Service role key

Key types (2026): `sb_publishable_...` (public, RLS applies), `sb_secret_...` (server only, bypasses RLS, Supabase rejects it when sent with a browser User-Agent), and the legacy `anon` and `service_role` JWTs (deprecated, removal planned for late 2026). The service role or secret key belongs only in Edge Functions (`Deno.env.get`), API routes, Server Actions and backends. Never behind `NEXT_PUBLIC_`, `VITE_`, `EXPO_PUBLIC_` or `PUBLIC_`.

```ts
// lib/supabase/admin.ts
import 'server-only'
import { createClient } from '@supabase/supabase-js'

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SECRET_KEY!, // no public prefix
  { auth: { persistSession: false } },
)
```

If the key was ever in a bundle, an app binary or git history, rotate it before anything else: for `sb_secret_` create a new secret key, deploy it, then delete the leaked one; for a legacy `service_role` key move to the new key types, deactivate the legacy keys, then revoke the legacy JWT secret. Rebuilding is not enough, old bundles and caches keep the value.

False-positive notes: in Next.js a non-public env var reads as undefined in the browser, so a reference in a client file is broken rather than leaked, but the admin client still belongs on the server. Edge Functions and files with `import 'server-only'` are correct.

## Edge Functions and seed accounts

`verify_jwt` (on by default) only proves the request carries some project JWT, and the public anon key is one; `verify_jwt = false` drops even that. With the service role client nothing else checks the caller:

- User-facing functions build the client from the anon key plus the caller's `Authorization` header (RLS applies), or call `supabase.auth.getClaims()` / `getUser()` first and use the caller's id, never an id from the body.
- Cron and internal functions compare the `Authorization` header to the service role key or a dedicated `CRON_SECRET` and return 403 otherwise.
- Webhooks set `verify_jwt = false` and verify the provider's signature.
- TanStack Start (newer Lovable projects): every `createServerFn` is a public endpoint, protected only by `.middleware([requireSupabaseAuth])` or a check inside it. Routes under `src/routes/api/public/` are meant to be called without a login, so each needs a shared secret or signature check. A service key in a `*.server.ts` file stays on the server as long as no client file imports it.
- Demo accounts inserted into `auth.users` belong in `supabase/seed.sql` (local only), never in a migration: migrations run in production, so a known password goes live.

## getClaims over getSession

`supabase.auth.getSession()` reads the session out of the cookie without verifying it. In server code (proxy, middleware, route handlers, Server Components, Server Actions) use `getClaims()`, which verifies the JWT signature, or `getUser()`, which asks the Auth server:

```ts
const supabase = await createClient() // createServerClient from @supabase/ssr
const { data, error } = await supabase.auth.getClaims()
if (error || !data?.claims) redirect('/login')
const userId = data.claims.sub
```

Middleware or proxy checks stay optimistic. The real control is RLS plus a verified user in the code that touches data.

False-positive note: `getSession()` in browser code is fine. A file that also calls `getUser()` or `getClaims()` (the SvelteKit `safeGetSession` pattern) is not reported.

## Prove it on your own project

This skill sends no requests: give the user this command, or hand the check to the live-exposure-check skill. With their own project URL and the anon key the app already ships, logged out, a private table must return `[]` or a permission error:

```
curl -s "https://<your-ref>.supabase.co/rest/v1/profiles?select=*" -H "apikey: <anon-key>" -H "Authorization: Bearer <anon-key>"
```

An empty array only proves the logged-out path. Repeat with test user B's access token against user A's row id; B must not see it. The live-exposure-check skill runs this check for you.

LAST-VERIFIED: 2026-10-06
