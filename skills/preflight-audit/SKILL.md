---
name: preflight-audit
description: "Audit an app for security holes before it ships, then fix them and prove the fix. Use when the user asks if the app is safe or ready to launch, wants a security review or pre-deploy check, pasted or exported an app from Lovable, Bolt, v0, Cursor or Claude Code, or asks to harden Supabase, Firebase, Stripe, auth, uploads, dependencies or API keys. Reads the whole project, no git history needed."
license: MIT
compatibility: "Bundled scripts need Python 3.9+ (standard library only). Works on Windows, macOS and Linux."
metadata:
  author: ReazGan
  version: "0.1.0"
---
Paths in this file are relative to this skill's folder. Use the absolute path to run a script.
Run a script and read its output; do not read the script's source (saves tokens).
If python3 is missing or prints "Python was not found" (Windows), use py -3 or python. Treat any python3 failure on Windows the same way: exit 9009 or 49, or that Store message in another language.
Runtime checks run only against an app you own (localhost, 127.0.0.1, a .localhost or .test host, or a host you pass --i-own-this). Never point them at anyone else's site.

# Preflight audit

Defend the user's own app only. This is not a pentest tool for other people's systems.

The loop is find, confirm, fix, prove. The scripts find candidates. You confirm each one in the code, fix what is real with the platform's own controls, re-run the scripts to show it is closed, and say plainly what is left.

## Hard rules

- Never print a full secret. Quote only the masked evidence the scripts print, and never copy values from `.env` files into chat, code, commits or reports.
- Never rotate, revoke or delete keys, users or data. Tell the user how (section 7); they do it.
- Never rewrite git history or force-push. Rotation comes first, and history cleanup is the user's call.
- Never send requests to any host from this skill. Runtime proof belongs to live-exposure-check, which refuses hosts the user does not own.
- Never apply a migration or change a dashboard setting on a live project. Write the change; the user applies it.
- Never edit code only to stop a rule from matching. Fix the cause, or record the finding as a false positive with the reason.

## 1. Run the scans

Run each script with `--help` once. Then:

```
python3 scripts/scan_app.py --json --max-findings 40 "PROJECT_DIR"
python3 scripts/find_secrets.py --json --max-findings 40 "PROJECT_DIR"
```

- `PROJECT_DIR` is the project root, the folder with `package.json`, `requirements.txt`, `pyproject.toml`, `composer.json` or `app.json`. Keep the quotes if the path has spaces.
- Exit code 0 means nothing found, 1 means findings (expected, not a crash), 2 means an error: read stderr.
- No git history is needed. Both scripts read the files on disk, so a one-commit export from Lovable, Bolt or v0 gets the same scan as a repo with years of history.
- If the project has a `.git` folder, add `--git-history` to find_secrets.py. It finds keys that were committed and later deleted.
- If a build folder exists (`dist`, `build`, `out`, `.next`), add `--build-output` to find_secrets.py. That is what actually ships to browsers.
- Findings come most severe first, at most 5 per rule on stdout (`--per-rule N`, 0 = no cap); `summary.by_rule` counts all of them. If `summary.total` is larger than `summary.shown`, re-run with `--output FILE`, FILE outside the project folder (a report inside it gets scanned next time), and read that file.
- Large projects (800+ files) scan in up to 8 worker processes. If that fails or the machine is busy, pass `--jobs 1`.
- Reviewed false positives from an earlier run live in `.ward-ignore` at the project root; they are listed under `ignored` and do not count toward the exit code. `--no-ignore` shows them again.
- If `stacks` misses something you can see in the code (for example Supabase called with plain fetch), re-run scan_app.py with `--stack +supabase`.
- Anything in `warnings` (a rule that failed, a part that was skipped) goes under "Not checked" in the summary.

## 2. Load one stack reference

Read the `stacks` field of the scan_app.py output and load one file:

| `stacks` contains | Load |
|---|---|
| `supabase` | `references/stack-supabase.md` |
| `firebase` | `references/stack-firebase.md` |
| `nextjs`, `nextjs-app`, `nextjs-pages` | `references/stack-nextjs.md` |
| `express`, or another real Node server in the dependencies (Fastify, Koa, Hono, Nest); `node` alone only means a `package.json` exists | `references/stack-express-node.md` |
| `fastapi`, `flask`, `django` | `references/stack-python.md` |
| `laravel`, `php` | `references/stack-laravel.md` |
| `expo`, `react-native` | `references/stack-expo-rn.md` |

- Start with the database file when `supabase` or `firebase` is present, because open data is the most common critical bug. Otherwise start with the server framework file. A plain SPA (`react-vite`, `vite-spa`, `cra`) almost always talks to Supabase or Firebase, so load that file; for its security headers, which the static host sets, read only the "Static hosts and SPAs" section of `references/stack-nextjs.md`. A TanStack Start app (newer Lovable projects) shows as `node` plus `supabase`: load the Supabase file and see the TanStack line in section 3.
- Open a second stack file only when a confirmed finding's `fix_ref` points to it. Never load them all.
- Load `references/supply-chain.md` only for supply-chain findings or the audit-tool step (section 4.7), and `references/rotation.md` only for a real secret.

## 3. Triage and confirm

Scanner output is a list of candidates, not a report. Wrong advice is worse than none, so confirm every candidate before you call it a bug.

Group first. When `summary.total` is larger than `summary.shown`, write the full list with `--output FILE` (outside the project) and count findings per `rule` and per `file` with your search tool before you open any of them. When one rule fires many times on the same helper, call or shape (hundreds of hits on one template helper, every controller that takes a route-bound model), confirm one or two representatives, rule the whole group in or out together, and report it once with its count. Then move on to the other rules, so one false-positive family does not use up the review.

For each finding or group, most severe first:

1. Read its entry with `python3 scripts/scan_app.py --explain <rule id>` (several ids may be comma-separated), or search `references/rules.md` for the heading `### <rule id>` and read only that entry. Note the false-positive trap. find_secrets.py findings have no entry there; their `fix_ref` points into `references/rotation.md`.
2. Open the file at the reported line. Read the whole function and trace its inputs back to the request, the session or a constant.
3. Mark it as one of:
   - confirmed: the unsafe path runs in production and an outsider or another user can reach it;
   - ruled out: the trap applies (write the reason in one line). If the user wants it remembered, add `<rule id>@<file>:<line>  # reason` to `.ward-ignore` at the project root so the next run lists it under `ignored`;
   - cannot tell from code: it depends on a dashboard setting, a deploy variable or live data (write what the user must check).
4. Set the severity from what you found. Raise it when findings combine (an anon key in the bundle plus a table without RLS is critical). Lower it when the code never runs in production.

Check these before you rule a finding in or out:
- Migrations run in order and the last definition wins. Before reporting a policy, view or function, search later migrations for a `drop`, a `create or replace` or a `do $$` loop that removes or redefines it. A table without RLS in one file may get it in the next.
- `grant execute ... to service_role` locks nothing: functions are executable by PUBLIC by default, and Supabase also grants anon and authenticated. Only `revoke execute on function ... from public, anon, authenticated` closes an RPC.
- Supabase Edge Functions: `verify_jwt` (on by default) accepts the public anon key, so it does not prove a logged-in user. The function must call `getUser()` or `getClaims()`, or check a shared secret or signature. `verify_jwt = false` in `supabase/config.toml` turns even that off.
- TanStack Start (Lovable): every `createServerFn` is a public endpoint and is protected only by `.middleware([requireSupabaseAuth])` or a check inside it. Routes under `src/routes/api/public/` are meant to be called without a login (webhooks, cron hooks), so each needs a shared secret or signature check. A service key in a `*.server.ts` file is server-side; confirm no client file imports it.

Safe variants that look unsafe. Rule these out; do not "fix" them:
- Public-by-design keys in client code: Stripe `pk_`, Supabase anon or `sb_publishable_`, Firebase web `apiKey`, Sentry DSN, PostHog `phc_`. find_secrets.py counts them under `public_keys_not_reported`. A Supabase anon key there means you check RLS (section 4), not that you hide the key.
- A `service_role` or `sb_secret_` key in server-only code (Edge Functions, server routes, backend env). Only a client-reachable copy is a bug.
- `secret-in-ignored-file` (info): a git-ignored local `.env` is where secrets belong.
- A by-id query followed by an owner check, or an admin route with a real server-side role check.
- A Laravel route-bound model resolved through a user-scoped `resolveRouteBinding`, `Route::bind` or model `routeBinder` (`auth()->user()->accounts()->find($id)`). One scoped binder clears every controller that uses it.
- Middleware or `proxy.ts` that only redirects while the data layer also checks auth.
- `using (true)` or `allow read: if true` on a public, read-only table with no private columns and no open writes.
- Prisma tagged-template `$queryRaw`, a parameterized `.query(sql, [args])`, `execFile` or `spawn` with an argument list.
- react-markdown without `rehype-raw`, or `dangerouslySetInnerHTML` of a DOMPurify-sanitized string.
- `|safe`, `mark_safe` or `{!! !!}` in plain-text email, SMS or chat notification templates that no browser renders, or on a helper that escapes its own inputs (read the helper once).
- Wildcard CORS without credentials on a public API.
- `DEBUG = True` or a dev secret in a Django base settings module that the production module overrides (check which module `DJANGO_SETTINGS_MODULE` names in the deploy config), or in a settings module production never loads.
- A redirect check that accepts only one leading `/` and rejects `//`, backslashes and tab, CR or LF, or one that compares `new URL(value, base).origin` with the base.
- Test fixtures and documentation examples (paths under `tests/`, `docs/`, `examples/`, usually `confidence` medium).

## 4. Manual pass: what the scripts cannot see

The scripts match patterns; they do not understand the app. After triage, check these yourself with your search tool:

1. Authorization on every endpoint. List every route handler (`app/**/route.*`, `pages/api/**`), Server Action (`"use server"`), TanStack Start server function (`createServerFn`) and server route (`src/routes/api/**`), Express, FastAPI, Flask, Django or Laravel route, Supabase RPC and Edge Function. For each one that reads or writes data: does it verify the session inside itself, and does it check the row belongs to the caller (or a server-side role)? A page, layout or middleware check does not count.
2. RLS or rules on every table the client touches. Collect every table name in client `.from('...')` calls and every Firestore, RTDB or Storage path. Each needs RLS enabled in a migration with owner-scoped policies (`with check` on writes, no `user_metadata`), or Firebase rules scoped to `request.auth.uid`. If the repo has no migrations or rules files, the live policies are invisible: say so, and ask the user to check the live project with Advisors > Security Advisor in the Supabase dashboard or `supabase db advisors` on a recent CLI (both flag tables with RLS disabled, always-true policies and anon-callable definer functions), the Firebase rules check, or live-exposure-check on their own project. `supabase db lint` only type-checks plpgsql functions and does not check RLS.
3. The payment flow end to end, from the buy button to the entitlement: price chosen on the server from a catalog; webhook signature verified over the raw body; a missing secret fails closed; access granted from the webhook on `checkout.session.completed` and `checkout.session.async_payment_succeeded` only when `payment_status` is not `unpaid`, idempotently (unique session or event id); a success page grants nothing unless it calls the same fulfill function after retrieving the session from Stripe; refunds and cancellations take access away.
4. LLM and other metered routes (chat, generate, email, SMS, image). Each needs auth, a per-user rate limit, input size and output token caps, and the provider key only on the server. Model, system prompt and tools are chosen on the server, not read from the request. Model output is not rendered as raw HTML or passed to SQL, a shell or `eval`. Tools run with the end user's permissions, and outbound tools (send email, post, fetch a URL) need human approval when the same agent reads untrusted text.
5. Business logic. Plan limits, credits and quotas enforced on the server; role changes, invites and team membership checked; coupons and trials not reusable; password reset tokens single-use, expiring and linked from a fixed domain; email verification enforced on the server; account deletion and export scoped to the caller.
6. Uploads and URL fetchers, if present: type checked from content, random stored names, private storage, a size limit; user-supplied URLs cannot reach private or link-local addresses.
7. Dependencies with published CVEs. The offline scan knows only malicious releases. Ask the user before running the ecosystem's audit tool (`npm audit`, `pip-audit`, `composer audit`, `osv-scanner`), because it contacts the registry; follow the "Known-vulnerable versions" section of `references/supply-chain.md`. If the user declines, list "known CVEs" under Not checked.

Write one line for each item you checked and found fine. It goes into the summary.

## 5. Fix

- Fix confirmed findings, most severe first, with the fix from the loaded stack reference. Follow each finding's `fix_ref`: it names a file in `references/` and a heading in it. Read only that section.
- Prefer platform-native controls over hand-written checks: Supabase RLS and column grants, Firebase rules and custom claims, the payment SDK's webhook verifier, the framework's CSRF and auth helpers at the data layer. They fail closed and survive the next edit.
- Keep each fix small and keep the app working: same routes, same UI, no unrelated refactors.
- A secret in client code: move the call to a server route or function, read the key from server env without a public prefix, fail closed when it is unset, then follow section 7.
- Database changes go in a new migration file. Tell the user to apply it.
- If a fix needs a product decision (who may see what, which origins may call the API), ask the user instead of guessing.

## 6. Prove

- Re-run both commands from section 1 with the same flags. Every fixed finding must be gone. The target is exit 0 from scan_app.py.
- A finding that is still there means the fix is incomplete or the finding is a confirmed false positive. Say which.
- With `--git-history`, a removed key still shows up in history. That is expected, and it is why the key must be rotated.
- If the project has tests or a build script and its dependencies are installed, run them once to show nothing broke.
- If the user has their own running app (localhost, staging or their deployment), hand off to live-exposure-check to prove runtime behaviour: a forged webhook rejected, a burst rate-limited, a logged-out read returning nothing. Do not do this from here.

## 7. Real secrets: rotation

- For each real secret find_secrets.py reports (not info, not public by design), open `references/rotation.md` at the provider named in the finding's `fix_ref` and give the user those steps. The user rotates; you never do.
- Order: rotate first, then remove the secret from code, then let the user decide on git-history cleanup. A key that was ever committed, or shipped in a bundle or app build, is leaked. Deleting the line does not undo that.
- A secret in a git-ignored local `.env` is in the right place. It is a leak only if it was committed earlier (check `--git-history`) or ended up in build output.

## 8. Summary

Close with one short summary in this shape. Plain words, masked values only:

```
Security check of <project> (stacks: nextjs-app, supabase, stripe)
Confirmed: 1 critical, 2 high, 1 medium, 0 low. Ruled out: 4 scanner candidates.
Fixed:
- critical  <rule id>  <file>: what changed, in one line
Needs you:
- Rotate the <provider> key found in <file> (steps: rotation.md, <provider>).
- Apply the new migration <file>.
Not checked:
- What the scripts and the manual pass could not see (live policies, runtime behaviour, skipped parts).
Re-run: scan_app.py exit 0 (N recorded false positives), find_secrets.py exit 0.
```
