# ward

[![CI](https://github.com/ReazGan/ward/actions/workflows/ci.yml/badge.svg)](https://github.com/ReazGan/ward/actions/workflows/ci.yml)

Security skills for the app your coding agent just built. They find the holes,
fix them, and prove they are closed.

On a demo app with 20 planted bugs, the same agent closed 19 on its own and
all 20 with ward, without breaking a feature and without "fixing" safe code.
[Numbers and method](bench/).

```
npx skills add ReazGan/ward
```

## The three skills

1. `secure-by-default`: rules the agent follows while it writes code. Login and
   data access, secrets, payments, uploads, server-side fetch and LLM routes.
2. `preflight-audit`: audits the whole project before launch, fixes what is
   real, then runs the same checks again to show each fix holds. It needs no
   git history, so a fresh Lovable, Bolt or v0 export works.
3. `live-exposure-check`: checks what your own running app exposes. Keys in
   the shipped JavaScript, a reachable `.env` or `.git`, source maps, headers,
   cookie flags, CORS, debug mode, and on request an unverified Stripe
   webhook, a missing rate limit, or a Supabase or Firebase table anyone can
   read.

You do not have to name them. Ask "is this ready to launch?" or "check
http://localhost:3000 for leaks" and the agent loads the right one. With the
Claude Code plugin they are also `/ward:preflight-audit` and so on.

The scripts are Python 3.9+ with the standard library only, so there is
nothing to install. The audit runs offline. The live check only talks to the
URLs you give it.

## Benchmark

`bench/` holds a small Next.js + Supabase + Stripe app with an LLM chat, built
the way an app builder would build it, with 20 planted bugs, 5 hold-outs that
no skill text names, and 10 decoys that look risky but are safe. A bug counts
as closed only when its exploit stops working and all 10 feature checks still
pass. Same model and prompt in both arms, two runs each:

```
                planted   hold-out   safe code changed
alone, run 1    19/20     3/5        1 decoy
alone, run 2    19/20     4/5        1 decoy
ward, run 1     20/20     4/5        none
ward, run 2     20/20     5/5        none
```

On its own the agent missed npm install hardening and a bad pinned version in
both runs, and rewrote a component that was already sanitized. Two runs per
arm is a small sample, and a strong model finds most of these bugs anyway.
Method, every miss and how to reproduce: [bench/](bench/).

## The bugs coding agents ship most

1. Row level security never turned on. A Supabase anon key is public by
   design and only safe behind row level security. CVE-2025-48757 covers
   Lovable apps where it was off: a researcher found 170 projects whose tables
   could be read or written with the public key alone. The vendor disputes the
   CVE. [Write-up](https://mattpalmer.io/posts/CVE-2025-48757/)
2. Open means writable too. Moltbook shipped its Supabase key in a
   production JavaScript chunk with no row level security. Wiz read the
   database without logging in and confirmed write access by editing live
   posts. [Wiz](https://www.wiz.io/blog/exposed-moltbook-database-reveals-millions-of-api-keys)
3. A storage bucket left open. Tea left a legacy Firebase Storage bucket
   unsecured, exposing about 72,000 images, 13,000 of them selfies and photo
   IDs.
   [Statement](https://simonwillison.net/2025/Jul/26/official-statement-from-tea/)
4. A paid API key in the frontend, with no auth and no rate limit.
   EnrichLead's attackers bypassed subscriptions and maxed out its API keys
   within days, and the app shut down.
   [Indie Hackers](https://www.indiehackers.com/post/vibe-coding-has-a-security-problem-vLxyPTrTlZVwDo76oqvr)

## What /security-review skips, by design

Claude Code's built-in `/security-review` reviews the pending changes on your
branch. Its [prompt](https://github.com/anthropics/claude-code-security-review/blob/main/.claude/commands/security-review.md)
leaves out, on purpose, "Rate limiting concerns or service overload
scenarios", "A lack of hardening measures" and "Vulnerabilities related to
outdated third-party libraries". It also treats missing auth checks in
client-side code as not a vulnerability, because a server is assumed to
enforce them. In a Supabase or Firebase app the browser talks to the database
directly, and row level security or security rules are the only gate.

It is read-only by design, and an export that lands as one big commit leaves
it no diff to review. That is a sensible scope for a pull request reviewer.
ward looks at the whole project and the live deploy instead. Use both, along
with the official security-guidance plugin if you have it.

## Install

```
npx skills add ReazGan/ward
```

It asks which skills and agents to install. `--all` installs every skill for
every agent without asking, `--skill preflight-audit` installs one. On
Windows, add `--copy` if symlinks fail. Run it again to update.

Claude Code plugin, inside a session:

```
/plugin marketplace add ReazGan/ward
/plugin install ward@ward
```

or from a shell:

```
claude plugin marketplace add ReazGan/ward
claude plugin install ward@ward
```

Add `--scope project` to the install to enable it for the current project
only.

Pick one method. A plugin install next to an `npx skills` install gives you
every skill twice.

<details>
<summary>Codex, Cursor, Gemini CLI, GitHub Copilot, or any other agent</summary>

Codex:

```
npx skills add ReazGan/ward -a codex
```

Cursor:

```
npx skills add ReazGan/ward -a cursor
```

Gemini CLI:

```
gemini skills install https://github.com/ReazGan/ward.git --path skills
```

GitHub CLI (Copilot and others):

```
gh skill install ReazGan/ward --all
```

Any agent that reads skill folders, paste this:

```
Install the skills in the skills/ folder of https://github.com/ReazGan/ward where you load skills from.
```

The scripts need Python 3.9 or newer. If `python3` is missing, or on Windows
prints "Python was not found" (in any language) or exits with 9009 or 49, use
`py -3` or `python`.

</details>

## Run the checks yourself

The scripts work without an agent, so they also fit in CI:

```
python3 skills/preflight-audit/scripts/scan_app.py --json .
python3 skills/preflight-audit/scripts/find_secrets.py --git-history .
python3 skills/live-exposure-check/scripts/check_live.py http://localhost:3000
```

Exit codes: 0 clean, 1 findings, 2 error, 3 refused (a host you have not said
you own). Secret values are always masked in the output. Reviewed false
positives go in a `.ward-ignore` file at the project root, one
`RULE@PATH[:LINE]  # reason` per line; `scan_app.py --explain RULE` prints
what a rule looks for and when it is safe.

## What this is not

- Not a pentest tool. The live check refuses any host that is not local
  unless you pass `--i-own-this` for it, and its requests are read-only apart
  from the opt-in webhook and rate-limit probes to your own endpoints.
- Not a replacement for a professional audit.
- It does not rotate keys. When a live secret turns up, it tells you how to
  rotate it with the provider, and you do that yourself.
- It does not test anyone else's host, and it never sends a key it finds to
  any provider.
- It cannot see a business-logic bug that leaves no trace in the code. The
  scanner reports candidates, and the agent confirms each one before it
  changes anything.

## Related

Small security CLIs by the same author: [leakscan](https://github.com/ReazGan/leakscan),
[spill](https://github.com/ReazGan/spill), [wraith](https://github.com/ReazGan/wraith),
[jwtlint](https://github.com/ReazGan/jwtlint), [depsweep](https://github.com/ReazGan/depsweep),
[sift](https://github.com/ReazGan/sift).

## License

MIT
