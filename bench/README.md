# ward benchmark

A measured test of whether a security skill pack actually makes a vibe-coded app
safe before it ships. The benchmark is an ordinary-looking Next.js 14 SaaS app
(notes, orders, a chat assistant, an admin page) with real security holes planted
in it, three local mocks that make those holes exploitable without any network,
and an oracle that proves each hole open or closed by exploiting it.

Nothing here is tailored to the skills. The app is held separate from the skill
text so the benchmark measures general skill, not teaching to the test.

## What is in the app

The ground truth is `ground_truth.json`: one record per item with its file, class,
severity, how it is checked (`exploit` = a runtime check proves it; `static` =
a config-only check reads the source), and whether it is a hold-out or a decoy.

- 20 planted bugs (V01-V20): the common classes AI agents ship - missing RLS,
  a service key in the client bundle, an LLM proxy with no auth, an unverified
  Stripe webhook, client-trusted prices, IDOR, mass assignment, SQL injection,
  stored XSS, SSRF, an open redirect, broken CORS, weak cookies, and an
  unhardened dependency set.
- 5 hold-outs (H01-H05): the same real classes placed on files no skill text
  names (a GraphQL resolver, the image optimizer, a RAG endpoint that reaches an
  outbound tool, webhook replay, a Python manifest). Reported separately.
- 10 decoys (D01-D10): safe code that looks risky (the anon key, a publishable
  Stripe key, a Firebase web key, a public read-only table, DOMPurify-sanitized
  HTML, a parameterized Prisma query, an ownership check right after a lookup,
  react-markdown without raw HTML, wildcard CORS without credentials, an
  optimistic middleware redirect backed by a data-access layer). Flagging or
  "fixing" one of these is a false positive.

## The mocks (standard library Python, no network)

- `mock/mock_supabase.py` - a PostgREST-ish server that enforces RLS by reading
  the app's `supabase/migrations/*.sql` at startup. A table with RLS disabled is
  open to the anon key; with RLS enabled it evaluates a small policy grammar
  (`using/with check` of `true`, `auth.uid() = col`, `auth.role() = '...'`,
  a `user_metadata` role claim). Unknown policy expressions deny and are logged.
  The service role key bypasses RLS. Seeded from JSON.
- `mock/mock_stripe.py` - checkout session create/retrieve, a webhook sender that
  signs events with the Stripe signature scheme using a local `whsec`, and a way
  for the oracle to post a forged, unsigned event.
- `mock/mock_llm.py` - an OpenAI-compatible `/v1/chat/completions` with canned
  replies and a call counter. Deterministic for the RAG hold-out: a prompt that
  carries a planted instruction gets back a tool call the app may execute.
- `mock/mock_internal.py` - stands in for link-local/internal services an SSRF
  would reach and for an attacker collector an exfiltration would post to; it
  records every hit so the oracle can tell whether a request was made.

## The oracle

`oracle/` is pytest + stdlib `urllib`. `test_exploits.py` has one check per
planted and hold-out item; each decides whether the bug is `exploitable` or
`closed` and records it. `test_functional.py` proves the features still work:
login, listing your own notes and orders, placing an order, chat, admin for a
real admin, public stats, public posts, search, and viewing a note. A bug counts
closed only when its exploit check can no longer exploit it and every
functional check still passes, so a "fix" that breaks a feature or a decoy is
caught. The model never grades itself.

## Reproduce

```
cd bench/app && npm install          # node_modules is gitignored
cd .. && python run_oracle.py        # against the vulnerable app
```

`run_oracle.py` builds the fixtures, starts the four mocks, builds and starts the
app, runs the oracle, tears everything down (even on failure), and writes
`result.json`: `{"items": {id: exploitable|closed|error}, "functional": {...}}`.
On the vulnerable app every planted and hold-out item is `exploitable` and every
functional check passes.

To prove the fixes close every bug without breaking a feature:

```
python apply_solution.py --target /path/to/solved
python run_oracle.py --app-dir /path/to/solved --expect closed
```

`solution/` is an overlay of fixed files at the same relative paths as `app/`;
`apply_solution.py` copies the app and lays the overlay on top. On the solution
every planted and hold-out item is `closed` and every functional check passes.

Secrets are built at run time by `make_fixtures.py` into an untracked
`.env.local`; every value is an obviously invalid, shape-only token. Nothing real
is ever written.

## Eval protocol

Two arms, same model, same prompt, two runs each:

- alone: the agent with no extra skills.
- ward: the same agent with the three ward skills installed in the project.

The prompt both arms got: "This app is about to launch. Check it for security
problems and fix what you find, without breaking any features." It asks for a
security check on purpose, so the comparison measures what the skills add,
not whether the agent thought about security at all.

Each run starts from a clean copy of `app/` with one commit and no `.env`
file. The agent edits that copy, then `run_oracle.py` scores it. Claude Code's
`/security-review` was not run as a third arm: it reviews the pending diff and
does not edit code, so it cannot close anything on a one-commit export.

## Results

Run on 2026-10-06 with Claude Opus 5.5 in Claude Code. In the ward arm the
skills sat in `.claude/skills/` and their names and descriptions were listed
to the agent the way Claude Code lists installed skills; it loaded each
SKILL.md on its own.

```
arm      run    planted   hold-out  features  decoys edited   not closed
alone    A1     19/20     3/5       ok        D05             H02,H05,V20
alone    A2     19/20     4/5       ok        D05             H05,V20
ward     C1     20/20     4/5       ok        none            H05
ward     C2     20/20     5/5       ok        none            -
```

"features ok" means all 10 functional checks passed after the agent's
changes. Raw results are in `results/`; `python score.py` prints the table.

What the agent missed on its own, in both runs: npm install hardening and the
known-bad pinned version (V20), and the Python requirements file with a
known-bad litellm release, an http URL dependency and no install hardening
(H05; both runs fixed litellm, neither closed the rest). One run also left the
wildcard image optimizer host (H02).

What it missed with ward: H05 in one run. The agent moved the internal package
from http to https but left it as a URL dependency and flagged it for the
user. The other ward run closed everything.

Decoys: on its own the agent rewrote the DOMPurify-sanitized HTML component
(D05) in both runs, treating safe code as a bug. The ward runs changed no
decoy file. One ward run mentioned the users route (D06) as a low-risk email
enumeration issue without touching it.

Both arms also found a bug that was not planted: the session cookie was
decoded without checking its signature, so anyone could forge a login. All
four runs fixed it.

Read this as a small sample. Two runs per arm cannot give a tight number, and
a strong model already finds most of these bugs without help. What ward added
here was the supply-chain fixes and leaving safe code alone.

### Oracle fixes made after the runs

The first scoring pass marked correct fixes as failures, so the oracle was
fixed and every run, plus the vulnerable app and the solution, was scored
again with the same code:

- the Supabase mock ignored `drop policy`, so a new migration that drops a bad
  policy did not take effect;
- the user_metadata check matched the word in comments and in old migrations
  instead of the policies left after all migrations run;
- the image optimizer check matched `"**"` inside a comment;
- the mock had no `GET /auth/v1/user` and the fixtures had no
  `SUPABASE_JWT_SECRET`, so a fix that verifies session tokens could not log
  anyone in;
- the oracle logged in again for every check, which tripped a login rate
  limit that one run had correctly added;
- the mock returned booleans as 0 and 1, which hid public notes from a correct
  `is_public === true` check;
- the mock did not enforce primary keys, so webhook replay protection that
  relies on a duplicate-key error (the usual way) looked broken.

After these fixes the vulnerable app still scores 25 of 25 exploitable with
every feature working, and the solution scores 25 of 25 closed.

## Reproduce with any agent

```
cd bench/app && npm install
```

Copy `app/` (without `node_modules`, `.next` and `.env.local`) to a new folder
and commit it once. For the ward arm, install the skills into that copy. Give
the agent the prompt above. Then score the copy and print the table:

```
python run_oracle.py --app-dir /path/to/copy --expect closed --out results/run.json
python score.py
```

Add `"run"`, `"arm"`, `"decoys_edited"` and `"decoys_flagged"` to the result
file by hand after reading the agent's diff and report.
