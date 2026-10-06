# Data access and auth

Rules for writing auth and data code that denies by default. The question every check answers is "is this row this user's", not "is someone logged in". Each item ends with the case that looks wrong but is fine.

## RLS and Firebase rules first

When the browser talks to Supabase or Firebase directly, the database rules are the only gate. The public key is not the problem; missing rules are.

```sql
alter table public.notes enable row level security;
create policy "own notes" on public.notes for all to authenticated
  using ( (select auth.uid()) = user_id )
  with check ( (select auth.uid()) = user_id );
```

```
match /notes/{noteId} {
  allow read, delete: if request.auth != null && resource.data.ownerUid == request.auth.uid;
  allow update: if request.auth != null && resource.data.ownerUid == request.auth.uid
                && request.resource.data.ownerUid == resource.data.ownerUid;
  allow create: if request.auth != null && request.resource.data.ownerUid == request.auth.uid;
}
```

- Write the enable-RLS line in the same migration that creates the table.
- Keep roles where users cannot write them: Supabase `app_metadata` or a roles table, Firebase custom claims. Never `user_metadata` or a field on the user's own document.
- Supabase `security definer` functions go in a schema the API does not expose, with `set search_path = ''`. Views use `with (security_invoker = true)`.
- The service role or `sb_secret_` key stays on the server (Edge Functions, API routes, `import 'server-only'` modules).

Fine: the anon or publishable key and the Firebase `apiKey` in client code; `using (true)` or `allow read: if true` on data that is public by design, with writes locked.

## Ownership checks

Every lookup by an id from the URL, body or action arguments also proves ownership. Either filter by the session user in the query, or load the row and compare its owner. Return 404 (or 403) otherwise.

```ts
// Next.js route handler
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const { userId } = await verifySession()
  const order = await db.order.findFirst({ where: { id, userId } })
  if (!order) return new Response(null, { status: 404 })
  return Response.json(order)
}
```

```js
// Express + Mongoose
router.delete('/notes/:id', requireAuth, async (req, res) => {
  const note = await Note.findOneAndDelete({ _id: req.params.id, owner: req.user.id })
  if (!note) return res.sendStatus(404)
  res.sendStatus(204)
})
```

```python
# FastAPI
@app.get("/items/{item_id}")
def get_item(item_id: int, user=Depends(current_user), db=Depends(get_db)):
    item = db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()
    if not item:
        raise HTTPException(404)
    return item

# Django / DRF
invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)

class NoteViewSet(viewsets.ModelViewSet):
    serializer_class = NoteSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Note.objects.filter(owner=self.request.user)
```

```php
// Laravel: a policy per model (OrderPolicy::view returns $user->id === $order->user_id)
public function show(Order $order) { $this->authorize('view', $order); return $order; }
```

```ts
// Supabase with the service role key (Edge Function): RLS is off, so the query carries the owner
const { data } = await supabaseAdmin.from('orders').update({ status: 'paid' })
  .eq('id', id).eq('user_id', user.id).eq('status', 'pending').select().maybeSingle()
if (!data) return new Response(null, { status: 404 })  // take related ids (restaurant_id) from data, not the body
```

Put these queries in one data access layer so a new route cannot forget the owner filter. With Supabase and the user's session (anon key plus the caller's token), RLS already scopes every by-id query; that is the strongest version of this rule.

Fine: admin-only routes behind a real server-side role check; public resources (published articles, products); queries through a tenant-scoped client that injects the owner.

## Server Actions are public endpoints

Every exported function in a `'use server'` file is a POST endpoint anyone can call with any arguments. A check in the page or layout does not cover it.

```ts
'use server'
export async function deletePost(id: unknown) {
  if (typeof id !== 'string') throw new Error('bad id') // arguments are hostile
  const { userId } = await verifySession()
  const post = await db.post.findUnique({ where: { id } })
  if (!post || post.authorId !== userId) throw new Error('forbidden')
  await db.post.delete({ where: { id } })
}
```

Fine: Next.js already checks the Origin header for Server Actions, so they need no extra CSRF token. Route handlers do not get that check.

## Client-side checks

Client checks hide buttons; the server decides. Anything in the bundle (a role flag in localStorage, a password string, a `VITE_ADMIN_PASSWORD`) is readable and changeable in devtools.

```ts
// server: route handler, Server Action or API
const session = await verifySession()
if (session.role !== 'admin') return new Response(null, { status: 403 })
```

- Read the role from the database or verified token claims on the server, never from the request or client storage.
- Every admin route checks the role itself (or sits behind a wrapper or middleware that does); "is signed in" is not enough.
- No password, PIN or admin code ever goes into client code or a public env var. Use the auth provider's sign-in, then check the role on the server.

Fine: `localStorage` role values used only to choose what to render, when every API route, Server Action and table behind the screen enforces the same rule.

## Middleware and proxy

Next.js middleware (renamed `proxy.ts` with a `proxy` function in Next.js 16; `middleware.ts` still works but is deprecated) is for optimistic redirects. It is not the only line of defense:

```ts
// proxy.ts: cheap cookie check, redirect only
export default async function proxy(req: NextRequest) {
  const session = await decrypt(req.cookies.get('session')?.value)
  if (!session && req.nextUrl.pathname.startsWith('/dashboard'))
    return NextResponse.redirect(new URL('/login', req.nextUrl))
  return NextResponse.next()
}

// lib/dal.ts: real check, called by every page, action and route that touches data
export const verifySession = cache(async () => {
  const session = await decrypt((await cookies()).get('session')?.value)
  if (!session?.userId) redirect('/login')
  return { userId: session.userId, role: session.role }
})
```

- Check `config.matcher`: a matcher like `/dashboard/:path*` or `/((?!api|...).*)` leaves every `/api` route ungated.
- With Supabase, server code verifies the user with `supabase.auth.getClaims()` or `getUser()`. `getSession()` reads the cookie without verifying it and is for browser code only.

Fine: middleware that redirects while every route and action also verifies the user is the recommended pattern. A matcher that skips `/_next/static` and images is normal.

## CVE-2025-29927

On Next.js 11.1.4 to 12.3.4, 13.0.0 to 13.5.8, 14.0 to 14.2.24 and 15.0 to 15.2.2, one `x-middleware-subrequest` request header makes Next.js skip middleware entirely, along with any auth it does. Patched in 12.3.5, 13.5.9, 14.2.25 and 15.2.3, but those are floors for this CVE only. CVE-2024-51479 (pathname-based middleware checks) is fixed only from 14.2.15, so 12.x and 13.x stay exposed, and later critical advisories (GHSA-9qr9-h5gf-34mp, GHSA-2xp9-vwfh-vxw4, GHSA-p293-qw3h-jr36) hit every release below 15.5.24 / 16.3.3; GHSA-vcvr-r3jv-pc5j needs 16.3.6 on 16.x.

- Upgrade to the latest patch of 15.x or 16.x (as of 2026-10 at least 15.5.24 or 16.3.6) and commit the lockfile so the installed version is the patched one.
- Self-hosted apps (your own Node server, Docker, a VPS behind Nginx) are the exposed ones.
- Even after the upgrade, keep the checks in the data access layer above.

Fine: apps hosted on Vercel were shielded at the edge; upgrade anyway.

## Mass assignment

Never pass the whole request body to a create or update. Name the writable fields and set owner, role, price and credits on the server.

```ts
const { title, content } = PostInput.parse(await req.json()) // zod drops unknown keys
await db.post.create({ data: { title, content, authorId: session.userId } })
```

```python
class ProfileIn(BaseModel):          # FastAPI request schema without role or credits
    name: str
    bio: Optional[str] = None

class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ["name", "bio"]     # never "__all__"
        read_only_fields = ["owner"]
```

Laravel: `protected $fillable = ['name', 'bio'];` on the model, then `Profile::create($request->validated())`. Supabase: `revoke update on public.profiles from authenticated; grant update (name, bio) on public.profiles to authenticated;` so clients can only change those columns.

Fine: a body already rebuilt from an allow-list, a schema parse that strips unknown keys, a Laravel model with a safe `$fillable` (the default guarded model refuses mass assignment).

## Password hashing

Prefer the auth provider (Supabase Auth, Firebase Auth, Clerk, Auth.js) over hand-rolled passwords. If you must store them, use a slow password hash, never MD5 or SHA:

- Argon2id with m=19456 KiB, t=2, p=1 (OWASP minimum).
- scrypt with N=2^17, r=8, p=1, or bcrypt with cost 10 or more (bcrypt reads only the first 72 bytes).
- PBKDF2-HMAC-SHA256 with 600,000 iterations where nothing else is available.

In Node: `await bcrypt.hash(password, 12)` to store, `await bcrypt.compare(input, hash)` to check. In Python: `argon2.PasswordHasher().hash(password)`.

Fine: SHA-256 of a random reset token or API key before storing it, and SHA-1 of a password for a haveibeenpwned range check.

## Sessions and JWTs

- Keep the session in an `httpOnly`, `secure`, `sameSite: 'lax'` cookie with an expiry, signed or opaque. Never read the user id or role from a plain cookie (`user_id`, `role`): the browser can rewrite it.
- No fixed login or OTP bypass (a reviewer phone number with code 123456) in server code; use the provider's test numbers or a flag that is off in production.
- Verify every JWT with the key and a pinned algorithm (`jwt.verify(token, secret, { algorithms: ['HS256'] })`, `jwtVerify(token, key, { algorithms: ['RS256'] })`). `decode()` only reads the claims and proves nothing. Never accept `alg: none`.
- Short expiry, secret from the environment, only minimal claims (user id, role), never personal data.
- Reset tokens: random from a CSPRNG, stored hashed, single use, short lifetime, link built from a fixed domain (not the Host header), same response whether or not the account exists, other sessions ended after the reset.
- OAuth: verify `state`, key accounts on the provider's `sub`, not the email claim.

Fine: decoding a token in browser code to read `exp` for the UI, and reading the header before a real verify call.

LAST-VERIFIED: 2026-10-06
