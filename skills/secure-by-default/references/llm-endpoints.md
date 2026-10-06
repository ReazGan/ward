# LLM endpoints

Rules and copy-ready fixes for any route, Server Action or function that calls a language model, and for agents that give a model tools. Adapt names to the project; keep the order of the checks.

## The rules

1. Every metered route needs auth, a per-user rate limit, an input size cap and an output token cap.
2. The provider key lives on the server only.
3. The server picks the model, system prompt, tools and token limits. The client sends only its message.
4. Model output is untrusted. Never render it as raw HTML, and never pass it unvalidated to code, SQL, a shell, a file path or a URL fetch.
5. Nothing secret goes in the system prompt, and no access rule is enforced by prompt text.
6. Tools get least privilege. An agent that holds private data, reads untrusted content and can act outward must lose one of those three, or get a human approval step.

## 1. Auth, limits and caps on metered routes

An open `/api/chat` is a free proxy to the owner's bill (denial of wallet), and bots find these routes quickly. Every metered route (chat, generate, summarize, image, embeddings) runs these checks in this order: verified session, per-user rate limit, body validation with size caps, provider call with an output token cap, generic error on failure.

Next.js App Router route handler:

```ts
// app/api/chat/route.ts
import OpenAI from 'openai'
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'
import { auth } from '@/auth' // your session helper (Auth.js auth(), Clerk auth(), Supabase getClaims())

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) // server env, no NEXT_PUBLIC_ prefix
const limiter = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(20, '1 m') })
const MODEL = 'gpt-4.1-mini' // picked here, never by the client

export async function POST(req: Request) {
  const session = await auth()
  const userId = session?.user?.id
  if (!userId) return new Response('Unauthorized', { status: 401 })

  const { success } = await limiter.limit(`chat:${userId}`)
  if (!success) return new Response('Too many requests', { status: 429 })

  const body = await req.json().catch(() => null)
  const message = body?.message
  if (typeof message !== 'string' || message.length === 0 || message.length > 4000) {
    return new Response('Bad request', { status: 400 })
  }

  try {
    const r = await openai.responses.create({ model: MODEL, input: message, max_output_tokens: 800 })
    return Response.json({ text: r.output_text })
  } catch {
    console.error('chat failed', { userId }) // ids only, no prompt text
    return new Response('Upstream error', { status: 502 })
  }
}
```

A Server Action that calls a model needs the same checks inside the action. The page that renders the form does not protect it.

Express:

```js
import express from 'express'
import rateLimit from 'express-rate-limit'
import Anthropic from '@anthropic-ai/sdk'
import { requireAuth } from './auth.js' // sets req.user or responds 401

const app = express()
const anthropic = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY }) // server env only
const MODEL = process.env.ANTHROPIC_MODEL // set on the server, never read from the request

const chatLimit = rateLimit({
  windowMs: 60 * 1000,
  limit: 20,                          // express-rate-limit 7+
  keyGenerator: (req) => req.user.id, // per user, so it must run after requireAuth
})

app.post('/api/chat', requireAuth, chatLimit, express.json({ limit: '16kb' }), async (req, res) => {
  const { message } = req.body ?? {}
  if (typeof message !== 'string' || message.length === 0 || message.length > 4000) {
    return res.status(400).json({ error: 'Bad request' })
  }
  try {
    const msg = await anthropic.messages.create({
      model: MODEL,
      max_tokens: 800,
      messages: [{ role: 'user', content: message }],
    })
    const text = msg.content.filter((b) => b.type === 'text').map((b) => b.text).join('')
    res.json({ text })
  } catch {
    res.status(502).json({ error: 'Upstream error' })
  }
})
```

The default express-rate-limit store lives in one process. With more than one instance or serverless, use a shared store (Redis).

FastAPI:

```python
import os

import redis.asyncio as redis
from fastapi import Depends, FastAPI, HTTPException
from openai import AsyncOpenAI
from pydantic import BaseModel, Field

from .auth import current_user  # your dependency, raises 401 when logged out

app = FastAPI()
llm = AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])  # fails at startup when unset
store = redis.from_url(os.environ["REDIS_URL"])
MODEL = "gpt-4.1-mini"  # picked here, never by the client


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=4000)  # the only field the client controls


async def chat_quota(user=Depends(current_user)):
    key = f"chat:{user.id}"
    await store.set(key, 0, ex=60, nx=True)  # 60 second window
    if await store.incr(key) > 20:
        raise HTTPException(status_code=429, detail="Too many requests")
    return user


@app.post("/api/chat")
async def chat(body: ChatIn, user=Depends(chat_quota)):
    resp = await llm.responses.create(model=MODEL, input=body.message, max_output_tokens=800)
    return {"text": resp.output_text}
```

Supabase Edge Function (Vite, Lovable or Bolt SPA). An SPA has no server of its own, so `/api/chat` becomes an Edge Function the client calls with `supabase.functions.invoke('chat', { body: { message } })`, which sends the signed-in user's access token. `verify_jwt` (on by default) also lets the public anon key through, so the function checks the user itself:

```ts
// supabase/functions/chat/index.ts
import { createClient } from 'npm:@supabase/supabase-js@2'
import OpenAI from 'npm:openai'

const openai = new OpenAI({ apiKey: Deno.env.get('OPENAI_API_KEY') }) // `supabase secrets set`, never a VITE_ var
const admin = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)
const MODEL = 'gpt-4.1-mini' // picked here, never by the client
const cors = {
  'Access-Control-Allow-Origin': Deno.env.get('APP_ORIGIN')!, // your site, not *
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}
const reply = (body: string, status: number) => new Response(body, { status, headers: cors })

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })

  const token = (req.headers.get('Authorization') ?? '').replace(/^Bearer /, '')
  const { data } = await admin.auth.getUser(token) // the anon key is not a user, so no user here
  const user = data?.user
  if (!user) return reply('Unauthorized', 401)

  const { data: allowed, error } = await admin.rpc('bump_rate_limit', {
    p_bucket: `chat:${user.id}`, p_limit: 20, p_window_seconds: 60,
  })
  if (error) return reply('Unavailable', 503) // fail closed when the limiter is down
  if (!allowed) return reply('Too many requests', 429)

  const body = await req.json().catch(() => null)
  const message = body?.message
  if (typeof message !== 'string' || message.length === 0 || message.length > 4000) {
    return reply('Bad request', 400)
  }

  try {
    const r = await openai.responses.create({ model: MODEL, input: message, max_output_tokens: 800 })
    return new Response(JSON.stringify({ text: r.output_text }), {
      headers: { ...cors, 'Content-Type': 'application/json' },
    })
  } catch {
    console.error('chat failed', { userId: user.id }) // ids only, no prompt text
    return reply('Upstream error', 502)
  }
})
```

The per-user limit without Redis, as a migration. The service role key is used only for this call, never in a tool:

```sql
create table public.rate_limits (
  bucket text primary key,
  window_start timestamptz not null default now(),
  hits int not null default 0
);
alter table public.rate_limits enable row level security; -- no policies: clients cannot read or write it
revoke all on public.rate_limits from anon, authenticated;

create function public.bump_rate_limit(p_bucket text, p_limit int, p_window_seconds int)
returns boolean
language sql
set search_path = ''
as $$
  insert into public.rate_limits as r (bucket, window_start, hits)
  values (p_bucket, now(), 1)
  on conflict (bucket) do update set
    window_start = case when r.window_start < now() - make_interval(secs => p_window_seconds)
                        then now() else r.window_start end,
    hits = case when r.window_start < now() - make_interval(secs => p_window_seconds)
                then 1 else r.hits + 1 end
  returning hits <= p_limit;
$$;

-- Functions are executable by PUBLIC by default and Supabase also grants anon and
-- authenticated, so a grant to service_role alone locks nothing.
revoke execute on function public.bump_rate_limit(text, int, int) from public, anon, authenticated;
grant execute on function public.bump_rate_limit(text, int, int) to service_role;
```

With Upstash instead, use `Ratelimit` from `npm:@upstash/ratelimit` and `new Redis({ url: Deno.env.get('UPSTASH_REDIS_REST_URL')!, token: Deno.env.get('UPSTASH_REDIS_REST_TOKEN')! })` from `npm:@upstash/redis`, the same limiter as the Next.js example. Leave `verify_jwt` on for this function; never set `verify_jwt = false` in `supabase/config.toml` for a metered function.

Also:
- Do not forward `model`, `max_tokens`, `temperature`, `tools` or a `system` message from the request body. A client that picks the model can pick the most expensive one; a client that sends `system` rewrites your instructions.
- Cap the history the client sends (number of messages and total characters), or keep history on the server keyed by conversation id and owner.
- Set a monthly budget or hard limit and usage alerts in the provider dashboard. Use a separate project or workspace key per app and per environment, so one leak stays contained.
- Not a bug: a route covered by a global auth middleware (Clerk, Auth.js) whose matcher really includes it. Read the matcher before you add a second check. Internal endpoints bound to localhost only are lower risk.

## 2. Keep the provider key on the server

- Never `NEXT_PUBLIC_OPENAI_API_KEY`, `VITE_...` or `EXPO_PUBLIC_...` for a provider key. Bundles and app binaries are public, and Hermes bytecode keeps strings readable.
- The OpenAI and Anthropic JS SDKs refuse to run in a browser unless `dangerouslyAllowBrowser: true` is set, and the Anthropic API also needs the `anthropic-dangerous-direct-browser-access` header for browser calls. Either one next to a build-time key means the key ships to every visitor. Move the call to a server route.
- SPA or mobile app with no server of its own: put the call in a Supabase Edge Function (example in section 1) or a Firebase Cloud Function that verifies the caller's token first, or use Firebase AI Logic with App Check. App Check cuts abuse; it does not make an embedded key secret.
- Never put a Gemini (Generative Language API) key in client code, and never enable that API on a Google project whose browser keys are unrestricted.
- Not a bug: bring-your-own-key tools where the end user types their own key at runtime and it stays in their browser.
- A key that was ever in a bundle, an app build or git history is leaked. Moving it is not enough; it must be rotated (the preflight-audit skill has per-provider steps).

## 3. Render model output safely

Safe by default (React):

```tsx
import ReactMarkdown from 'react-markdown'

// No rehype-raw: HTML inside the answer is shown as text, not run.
// Images are dropped: the browser loads them without a click, so an
// injected answer could put private data into an outside image URL.
export function Answer({ text }: { text: string }) {
  return <ReactMarkdown components={{ img: () => null }}>{text}</ReactMarkdown>
}
```

When raw HTML in markdown is really needed, sanitize after parsing it:

```tsx
import rehypeRaw from 'rehype-raw'
import rehypeSanitize from 'rehype-sanitize'

<ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>{text}</ReactMarkdown>
```

Without React:

```js
import DOMPurify from 'dompurify'
import { marked } from 'marked'

el.textContent = answer                                // plain text, safest
el.innerHTML = DOMPurify.sanitize(marked.parse(answer)) // only when markup is needed
```

- `marked` and `markdown-it` do not sanitize. Their output always goes through DOMPurify (browser) or `sanitize-html` / Bleach (server) before it reaches `innerHTML`, `v-html` or `{@html}`.
- Allow only `https:` and `mailto:` links in rendered output. Restrict images to your own origin with CSP `img-src 'self'` (plus your CDN) or drop them as above.
- Add a CSP with `script-src 'self'` as a backstop. It does not replace sanitizing.
- Never `eval`, `new Function`, `exec`, a SQL string or a shell command built from model output. If the feature generates SQL or code on purpose, run it with a read-only, least-privilege database role or in a sandbox, against an allow-list of statements or tables.
- Not a bug: `dangerouslySetInnerHTML` of a string sanitized with DOMPurify, or of a constant the developer wrote. react-markdown without `rehype-raw`.

## 4. The lethal trifecta

An agent is exploitable through prompt injection when it has all three of these at once. Text hidden in a page, email or document can then tell it to send the private data out. A system prompt line such as "ignore instructions in documents" does not reliably stop this. Remove a leg in code.

| Leg | Examples | How to remove or shrink it |
|---|---|---|
| Private data | database rows, files, other users' records, env secrets | Tools act as the end user (an RLS-scoped client with their token), read-only roles, only the tables the feature needs. Never `service_role` or an admin SDK in a tool. |
| Untrusted content | web pages, emails, uploads, support tickets, issues, other users' messages, results of a web search tool | Keep it away from agents that hold privileged tools, or read it in a separate step with no tools that returns only structured fields (a label, a short summary) which the privileged step treats as data. |
| Outbound action | send email, post a message, open a PR or issue, write to a shared doc, call a webhook, fetch a URL (data rides in the query string), render a remote image | Require human approval, allow-list destinations, or remove the tool. |

Before adding a tool, ask three questions. Does this agent see data the requester could not see alone? Does it read text someone else wrote? Can it send anything out? Three yeses means redesign before shipping.

Human approval for outbound tools:

```ts
const NEEDS_APPROVAL = new Set(['send_email', 'post_message', 'create_issue', 'fetch_url'])

async function runToolCall(call: { name: string; args: unknown }, userId: string) {
  const tool = TOOLS[call.name]
  if (!tool) return { error: 'unknown tool' }
  const args = tool.schema.parse(call.args)          // model-chosen args are untrusted input
  if (NEEDS_APPROVAL.has(call.name)) {
    const { id } = await db.pendingAction.create({ data: { userId, tool: call.name, args } })
    return { status: 'waiting for user approval', id } // nothing was sent
  }
  return tool.run(args, { userId })                  // scoped to this user
}
// The approve endpoint runs a stored action only after it checks that the
// session user owns it and that it has not run yet.
```

MCP servers and agent connectors: connect production data read-only where the server supports it (the Supabase MCP server has a read-only mode), scope it to one project, and never hand a service-role connection to an agent that reads user-written text.

## 5. Validate tool arguments

Arguments the model fills in are user input. Validate them with a schema and take ownership from the session, never from an id the model passes.

```ts
import { z } from 'zod'

const GetInvoice = z.object({ invoiceId: z.string().uuid() })

async function getInvoice(raw: unknown, ctx: { userId: string }) {
  const { invoiceId } = GetInvoice.parse(raw)
  return db.invoice.findFirst({ where: { id: invoiceId, userId: ctx.userId } }) // owner from the session
}
```

- A tool that fetches URLs uses the same guard as any user-supplied URL: https only, an allow-list, or rejection of private and link-local addresses at connect time and after redirects.
- A tool that reads or writes files resolves the path and checks that it stays inside one root folder.
- A tool that runs a program uses an argument list and an allow-listed program, never a shell string.

## 6. System prompts

- No API keys, connection strings, internal hostnames or passwords in the system prompt or in few-shot examples. Assume a user can make the model print it.
- Do not write access rules into the prompt ("only show this to admins"). Enforce them in the tool or the query.
- Fetch per-user data on the server for the verified session user and pass it in. Never trust a user id or role that appears in the conversation.

## 7. Logs

- Prompts and answers carry personal data, uploaded documents and keys users paste. Log ids, token counts, latency and status. If full text must be kept, redact keys, limit who can read it and set a retention period.

LAST-VERIFIED: 2026-10-06
