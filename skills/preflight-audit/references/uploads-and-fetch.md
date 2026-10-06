# Uploads, server-side fetch and other input sinks

Anything a request carries (body, query, headers, file names, uploaded bytes, a URL) and anything a model writes is untrusted at every sink below. Each item gives the safe pattern, then a false-positive note: when a scanner candidate is not a real problem.

## File uploads

### Validate by content

The extension and the `Content-Type` header both come from the client. Check the bytes, and re-encode images so a file that is also HTML or script loses everything that is not pixels.

```js
import { fileTypeFromBuffer } from 'file-type'
const type = await fileTypeFromBuffer(buf)
if (!type || !['image/png', 'image/jpeg', 'image/webp'].includes(type.mime)) throw new Error('unsupported file')
const clean = await sharp(buf).rotate().webp().toBuffer()   // re-encode
```

- Python: `Image.open(f).verify()`, then open again and re-save with Pillow; or `filetype.guess(data)`.
- PHP: `(new finfo(FILEINFO_MIME_TYPE))->file($tmp)` plus `getimagesize($tmp)`.
- Laravel: `'avatar' => 'required|image|mimes:jpg,png,webp|max:5120'`. `image` and `mimes` read the content, and `max` is in kilobytes. From Laravel 12, `image` rejects SVG unless you write `image:allow_svg`; on Laravel 11 and older it accepts SVG, so keep an explicit `mimes:` list without svg.

False positive: a `mimetype` check is only cosmetic, not a hole, when the file is stored under a random name with an extension the server picked and is served with `nosniff`.

### Server-side file names

Never store a file under the name the client sent. Generate one, and add an extension only after you checked the content.

```js
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => cb(null, crypto.randomUUID()),   // no client name, no client extension
})
// if a name from outside must become a path, resolve it and check it stays inside the folder
const target = path.resolve(UPLOAD_DIR, name)
if (!target.startsWith(UPLOAD_DIR + path.sep)) throw new Error('bad path')
```

- Python: `secure_filename(f.filename)` (Werkzeug) or `uuid4().hex`. Django `FileField` with `default_storage.save()` validates the path. FastAPI `UploadFile.filename` is raw client input.
- PHP: `bin2hex(random_bytes(16)) . '.' . $ext`. Laravel: `$request->file('avatar')->store('avatars')` (uses `hashName()`), not `getClientOriginalName()`.

False positive: the original name kept only for display, in a database column, or as a quoted `Content-Disposition` filename is fine.

### Size limits

```js
multer({ storage, limits: { fileSize: 5 * 1024 * 1024, files: 1 } })   // multer has no limit by default
```

- Flask: `app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024` (no limit by default).
- Next.js Server Actions: `experimental.serverActions.bodySizeLimit` in next.config (default 1 MB). Route handlers that call `req.formData()` need their own check.
- nginx: `client_max_body_size 10m;`. Laravel: the `max:` validation rule.

False positive: a limit set at the reverse proxy or the platform also works (nginx defaults to 1 MB). Check the deploy config before reporting.

### Storage and serving

- Keep user uploads outside the web root. Do not write them into Next.js `public/`, which is only served for files present at build time. Prefer private object storage and short-lived signed URLs (Supabase private bucket plus `createSignedUrl()`, S3 presigned GET).
- Serve user files with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`. For images shown inline, send the type you detected, never the client's.
- Convert SVG to PNG, or serve it from a separate domain with a strict CSP.
- Firebase Storage: `allow write: if request.auth != null && request.auth.uid == userId && request.resource.size < 5 * 1024 * 1024 && request.resource.contentType.matches('image/(png|jpeg|webp)');`. `image/.*` would also let SVG in, and `contentType` is metadata the client declares; if the type matters, check the bytes in a Cloud Function on finalize.

False positive: a public bucket for genuinely public assets (marketing images) is fine. The risk is private user content in a public bucket.

## File paths from the request

```js
app.get('/files/:name', (req, res) => {
  res.sendFile(path.basename(req.params.name), { root: FILES_DIR })   // with root, send() refuses ../
})
```

- Flask: `send_from_directory(DIR, name)` joins safely. FastAPI: `p = (BASE / name).resolve()`, then `if not p.is_relative_to(BASE.resolve()): raise HTTPException(404)`.
- PHP: `$p = realpath(BASE . '/' . basename($name));` and refuse unless `$p !== false && str_starts_with($p, BASE . '/')`. Never `include` a path built from input; map an allowlisted key to a file instead.
- Archives (zip slip): entry names inside an uploaded zip or tar (`entry.path`, `entryName`, tar member names) are client input. Resolve each target and refuse it unless it starts with the destination folder plus `path.sep`; an `includes()` or `indexOf()` check is not enough. Python: `tar.extractall(dest, filter='data')` (3.12 and patched older releases; the default from 3.14). `zipfile`'s `extract()` and `extractall()` already drop `..` and absolute names; a loop that opens `os.path.join(dest, info.filename)` itself does not.

False positive: FastAPI `{name}` and Flask `<name>` path parameters cannot contain `/` (`<path:name>` and query parameters can), but they can contain `\`, which is a separator on Windows. On a Windows host, or when the value is joined without `send_from_directory` or a resolve-and-contain check, still treat it as a path.

## Server-side fetch

The server can reach what the visitor cannot: the cloud metadata service, localhost ports, the private network. Treat every URL from a request, a document or a model as hostile.

1. Prefer an allowlist: https only, exact host match, no redirects.

```js
const ALLOWED = new Set(['images.example.com', 'api.partner.com'])
const u = new URL(input)
if (u.protocol !== 'https:' || !ALLOWED.has(u.hostname)) return res.status(400).end()
const r = await fetch(u, { redirect: 'error', signal: AbortSignal.timeout(5000) })
```

2. If any public URL must work (link previews), refuse private, loopback, link-local and reserved addresses at connect time, so a DNS answer cannot change between the check and the request, and check again on every redirect. Node: `request-filtering-agent` with a client that accepts an `http.Agent` (got, axios, node-fetch 2). The built-in `fetch` (undici) takes no `http.Agent`: pass an undici `Agent` as `dispatcher` whose `connect.lookup` resolves the name, rejects private results and returns only the checked address, and use `redirect: 'manual'` and check each `Location` again. Do not resolve the name yourself and then call `fetch(url)` with the host name: that second lookup can return another address. Python: `socket.getaddrinfo()` plus `ipaddress.ip_address(ip).is_global`, then connect to that IP while TLS still checks the original name (urllib3 `server_hostname` and `assert_hostname`), never with `verify=False`. Use a Python with the CVE-2024-4032 fix (3.8.20, 3.9.20, 3.10.15, 3.11.10, 3.12.4, any 3.13, or newer in that line); older ones give wrong `is_private` / `is_global` answers.
3. Cap response size and time. Block 169.254.169.254 at the network layer and require IMDSv2 on AWS.

False positive: a fixed host where the request fills only the path or query (`https://api.github.com/users/${encodeURIComponent(user)}`) is not SSRF. Calls to your own hardcoded API are fine, and a `fetch` that runs in the browser is not SSRF.

### Image optimizer remote patterns

```js
images: { remotePatterns: [{ protocol: 'https', hostname: 'images.example.com', pathname: '/avatars/**' }] }
```

Never `hostname: '**'`: the optimizer then fetches any URL a visitor names. An allowed host that redirects still sends it elsewhere: Next.js 16 follows up to `images.maximumRedirects` (default 3) without checking `remotePatterns` again, so set `maximumRedirects: 0` when your image hosts do not redirect, and never trust a host where users upload content. Never set `images.dangerouslyAllowLocalIP: true` (Next.js 16+), which lets it fetch private addresses. Keep Next.js on a patched release.

False positive: with `images.unoptimized: true` or a custom loader, the Next.js optimizer does not fetch.

## Other sinks for the same input

### SQL queries

Bind values. Identifiers (columns, `ORDER BY`, table names) cannot be bound, so pick them from an allowlist.

```js
await pool.query('SELECT * FROM users WHERE email = $1', [email])               // pg
await conn.execute('SELECT * FROM users WHERE email = ?', [email])             // mysql2
await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`            // tagged: parameterized
await prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE email = $1', email)
await knex('users').whereRaw('LOWER(email) = ?', [email.toLowerCase()])
await sequelize.query('SELECT * FROM users WHERE id = :id', { replacements: { id } })   // Sequelize 6.19.1+
const SORT = { name: 'name', newest: 'created_at' }
const col = SORT[req.query.sort] ?? 'created_at'
```

```php
DB::select('SELECT * FROM users WHERE email = ?', [$email]);
$q->whereRaw('LOWER(email) = ?', [strtolower($email)]);
$col = in_array($request->sort, ['name', 'created_at'], true) ? $request->sort : 'created_at';
$q->orderBy($col);
$stmt = $pdo->prepare('SELECT * FROM posts WHERE id = ?'); $stmt->execute([$id]);
```

- Python: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`. The comma passes a parameter; a `%` operator formats the string and is injectable.
- supabase-js: use `.eq()` / `.in()`; build `.or()` only from validated enum values.

False positive: tagged templates (`sql` from postgres or `@vercel/postgres`, `Prisma.sql`) are already parameterized. An interpolated ALL_CAPS constant or a generated placeholder list (`$1, $2`) is not user input.

### NoSQL filters

A JSON body can carry an object with a query operator where you expected a string. Force scalars before you query.

```js
const { email, password } = LoginBody.parse(req.body)          // zod: both must be strings
const user = await User.findOne({ email: { $eq: email } })
mongoose.set('sanitizeFilter', true)    // Mongoose 6.13.9, 7.8.9, 8.22.1, 9.1.6 or newer
```

Express 5 makes `req.query` a getter, so `express-mongo-sanitize` (which assigns it) throws or does nothing. Validate with a schema instead. Python: check `isinstance(value, str)`, or use a Pydantic model.

False positive: `req.params` values and Express 5 `req.query` values are strings (or arrays of strings), and schema-validated bodies are safe. Form fields are strings only with `express.urlencoded({ extended: false })`: Express 4's default (`extended: true`, qs), any `extended: true`, and Express 4's default query parser turn `email[$ne]=x` into an object.

### Shell commands

```js
execFile('ffmpeg', ['-i', inputPath, outPath])     // no shell: the value is one argument
spawn('git', ['clone', '--', repoUrl])             // "--" ends option parsing
```

- Python: `subprocess.run(["convert", src, dst], check=True)`.
- PHP: `escapeshellarg($x)` on every value, or `proc_open([...])` with an array (PHP 7.4+).
- Check the value against a strict pattern (a UUID, an enum) first. For "fetch this URL" features use an HTTP client, not `curl` in a shell.

False positive: an argument list without `shell: true` / `shell=True` is not command injection, even with user input in it. Still check file paths for `..`.

### Code evaluation

Never pass request or model text to `eval()`, `new Function()`, `vm.runIn*Context()`, Python `eval()` / `exec()`, or PHP `eval()`. For math use a parser (`mathjs` `evaluate` with a limited scope, Python `ast.literal_eval` for literals). In Flask, `render_template_string(f"<p>{name}</p>")` runs Jinja inside `name`; keep the template fixed and pass the value: `render_template_string("<p>{{ name }}</p>", name=name)`.

Deserializers that rebuild objects run code too. Never give request, cookie or upload data to `pickle` / `dill` / `marshal` loads, `jsonpickle.decode`, `yaml.load` without `SafeLoader` (use `yaml.safe_load`), node-serialize `unserialize()`, js-yaml `load()` before version 4, or PHP `unserialize()` (its manual says so even with `allowed_classes`). Accept JSON, validate it with a schema, and sign anything you round-trip through the client.

False positive: evaluating a constant the developer wrote is not injection, and unpickling the app's own cache or model files is not deserialization of user input.

### Rendering HTML

```tsx
<p>{post.content}</p>                                               // React escapes this
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
```

- Vue: `{{ text }}`, or `v-html="clean"` with `const clean = computed(() => DOMPurify.sanitize(raw.value))`. Svelte: `{@html DOMPurify.sanitize(html)}`.
- Plain JS: `el.textContent = text`, or build nodes with `createElement`. If you must use `innerHTML`, escape every value.
- On the server use `isomorphic-dompurify` or `sanitize-html`. Add a CSP (`script-src 'self'`) as a backstop.
- HTML built in a response: Express `res.send()` and a Flask route returning a `str` both answer as `text/html`. Escape each value (`escape-html`, `markupsafe.escape`, PHP `htmlspecialchars($x, ENT_QUOTES)`) or render a template with autoescape; return JSON with `res.json()` / `jsonify()`.
- JSON-LD: `JSON.stringify(data).replace(/</g, '\\u003c')` before it goes into a script tag.

False positive: fixed developer strings and already sanitized output are fine. Plain `{}` / `{{ }}` interpolation is escaped.

### Markdown and model output

Treat model output like user input. `marked` does not sanitize. `react-markdown` is safe until you add `rehype-raw`; if you need raw HTML, put `rehype-sanitize` after it.

```tsx
<ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>{text}</ReactMarkdown>
const html = DOMPurify.sanitize(marked.parse(md))
```

markdown-it is safe with its default `html: false`; `html: true` needs a sanitizer. Allow only http, https and mailto links, and consider not loading remote images in chat output, since an image URL can carry data out.

False positive: markdown from a trusted author, rendered with raw HTML off, is fine.

### Server templates

- Blade: `{{ }}` escapes, `{!! !!}` does not. Use `{!! !!}` only for `clean($html)` (mews/purifier) or fixed markup.
- Jinja and Django: keep autoescape on. Use `|safe` and `mark_safe()` only on sanitized (`nh3`, `bleach`) or fixed HTML; `format_html()` escapes its arguments.
- EJS `<%= %>`, Handlebars `{{ }}`, Pug `#{}`, Nunjucks and Twig `{{ }}` escape. `<%-`, `{{{ }}}`, `!=` / `!{}`, `|safe` / `|raw` and `autoescape: false` do not.

False positive: `{!! csrf_field() !!}` and `{{ data|tojson }}` are fine. `{!! json_encode($x) !!}` is fine only inside a `<script>` block (it escapes `/`, so `</script>` cannot close it). Elsewhere it leaves `"`, `'`, `<`, `>` and `&` as they are; use `@json($x)` or `{{ Js::from($x) }}`, or pass `JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP`.

LAST-VERIFIED: 2026-10-06
