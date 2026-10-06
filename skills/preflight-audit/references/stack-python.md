# Python: FastAPI, Flask, Django

Fixes for the Python findings from `scan_app.py`. Each item gives the change, then a false-positive note: when the candidate is not a real problem.

## Django DEBUG

```python
# settings.py: off unless the environment turns it on
DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
ALLOWED_HOSTS = [h for h in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",") if h]
```

Run `python manage.py check --deploy` with the production settings module in CI, and serve with gunicorn or uvicorn, never `manage.py runserver`. The debug page hides settings named like KEY, SECRET, TOKEN or PASS, but not a `DATABASE_URL` with a password in it, and not local variables; mark sensitive views with `@sensitive_variables()` and `@sensitive_post_parameters()`.

False positive: `DEBUG = True` in `settings/dev.py` or `local.py` that production never imports. Check `DJANGO_SETTINGS_MODULE` in the Procfile, Dockerfile or host settings.

## Flask debug

Never `app.run(debug=True)` or `FLASK_DEBUG=1` in deployed code. The Werkzeug debugger runs any code it is sent, and its PIN is not a security boundary. Run `gunicorn app:app` (or `waitress-serve app:app`) with `FLASK_DEBUG` unset.

False positive: `debug=True` under `if __name__ == "__main__":` is fine only when production starts the app through gunicorn and never runs that block.

## FastAPI debug

Keep `FastAPI(debug=False)` (the default) and drop `--reload` from production start commands. Do not put `str(e)` or `traceback.format_exc()` into `HTTPException(detail=...)`; log the error and return a generic message:

```python
@app.exception_handler(Exception)
async def unhandled(request, exc):
    logger.exception("unhandled error", extra={"path": request.url.path})
    return JSONResponse({"error": "Internal server error"}, status_code=500)
```

Decide on purpose whether `/docs` is public.

False positive: FastAPI's own 422 validation responses are fine.

## CORS

`allow_origins=["*"]` together with `allow_credentials=True` makes Starlette echo every Origin back with credentials. List exact origins:

```python
ALLOWED_ORIGINS = [o for o in os.environ.get("CORS_ORIGINS", "").split(",") if o]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True,
                   allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Authorization", "Content-Type"])
```

Django (django-cors-headers): `CORS_ALLOWED_ORIGINS = ["https://app.example.com"]`, never `CORS_ALLOW_ALL_ORIGINS = True` with `CORS_ALLOW_CREDENTIALS = True`. Flask-CORS: `CORS(app, origins=["https://app.example.com"], supports_credentials=True)`.

False positive: a wildcard without credentials on a public API that takes a token in a header.

## Config endpoints

Never return `dict(os.environ)`, `settings.__dict__` or the whole `app.config`, and never render `{{ config }}` in a Jinja template (it includes `SECRET_KEY`). Return the few public values by name: `return {"siteName": settings.SITE_NAME, "stripePublishableKey": settings.STRIPE_PUBLISHABLE_KEY}`.

False positive: an endpoint that returns explicitly named public values (a publishable key, a site name).

## Secret keys

Read the key from the environment with no fallback, so startup fails when it is missing:

```python
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]                  # Django
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]    # Flask
```

With pydantic-settings, declare `jwt_secret: str` with no default. Generate one key per environment with `python -c "import secrets; print(secrets.token_urlsafe(64))"`. A `django-insecure-...` key, `"dev"`, or the key from the FastAPI tutorial is public. A key that was ever committed or shown is burned: replace it, and do not keep it in `SECRET_KEY_FALLBACKS`.

False positive: throwaway keys in test settings or `conftest.py` that production never loads.

## Cookies

```python
# Django production settings
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SECURE_HSTS_SECONDS = 31536000
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")   # only behind a proxy that sets it
```

Flask: `app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")`. FastAPI: `response.set_cookie("session", token, httponly=True, secure=True, samesite="lax")`. Security headers: `flask-talisman`, an `after_request` hook, or Django's `SECURE_*` settings.

False positive: `secure=False` in a config that only runs on localhost.

## Logging

Do not print or log `os.environ`, `Authorization` headers, tokens, cookies, or a whole `request.json` / `request.POST` on login, signup or payment routes. Logs land in hosted viewers that more people can read than the database. Log the event and an id:

```python
logger.info("login failed", extra={"user_id": getattr(user, "id", None)})
logger.debug("api token present: %s", bool(token))     # whether it is set, not the value
```

In Django, `@sensitive_post_parameters("password")` keeps fields out of error reports.

False positive: one named non-secret setting (`os.environ.get("REGION")`), `len(token)`, or whether a value is set.

## Static files

Serve a dedicated folder: Flask's default `static/`, FastAPI `StaticFiles(directory="static")`, Django `STATIC_ROOT` collected outside the code with WhiteNoise or the web server. Never `static_folder="."`, `StaticFiles(directory=".")`, `send_from_directory(".", path)`, or `django.views.static.serve` in production URLs.

False positive: `django.views.static.serve` added only under `if settings.DEBUG:`.

## SQL injection

Pass values as parameters. The comma is what matters:

```python
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))     # parameter: safe
cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)       # string formatting: injectable
User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
Entry.objects.extra(where=["headline = %s"], params=[headline])      # never quote the %s
RawSQL("SELECT col FROM t WHERE x = %s", [x])
db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})   # SQLAlchemy
```

Prefer the ORM: `User.objects.filter(email=email)`, `select(User).where(User.email == email)`. Identifiers cannot be bound, so pick sort columns from an allowlist (`col = SORTABLE.get(sort, "created_at")`) or compose with `psycopg.sql.Identifier`. Never expand a client dict into `.filter(**data)`; Django before 5.2.8, 5.1.14 and 4.2.26 is open to CVE-2025-64459 through that path.

False positive: an f-string that only inserts a constant (an ALL_CAPS table name) or a generated list of `%s` placeholders.

## NoSQL filters

`request.get_json()` values can be dicts, so a dict with an operator key can take the place of a string and change what a filter matches. Check types before querying (with FastAPI, a Pydantic model with `str` fields does this):

```python
data = request.get_json(silent=True) or {}
username, password = data.get("username"), data.get("password")
if not isinstance(username, str) or not isinstance(password, str):
    abort(400)
user = users.find_one({"username": username})
```

False positive: `request.form` and `request.args` values are always strings.

## Command injection

```python
subprocess.run(["convert", src_path, out_path], check=True, timeout=60)    # list, no shell
subprocess.run(f"convert {shlex.quote(src_path)} out.png", shell=True)     # only if a shell is unavoidable
```

Avoid `os.system`, `os.popen` and `shell=True`. Check names against a strict pattern before they reach any command. Deserializers run code too: never `pickle.loads()`, `jsonpickle.decode()` or `yaml.load()` without `SafeLoader` on request or upload data; accept JSON and use `yaml.safe_load()`.

False positive: a list argument without `shell=True` is not injectable even with user input in it. Constant commands are fine. A click or typer command argument comes from the operator, not a visitor.

## Template XSS

Keep autoescape on. `|safe`, `{% autoescape off %}`, `mark_safe()` and `Markup()` turn it off for that value.

```python
from django.utils.html import format_html
link = format_html('<a href="{}">{}</a>', url, name)       # escapes url and name
safe_html = mark_safe(nh3.clean(user_html))               # sanitize first (nh3 or bleach)
html = Markup(nh3.clean(markdown.markdown(text)))         # Python-Markdown passes raw HTML through
```

For JSON in a page use `{{ data|tojson }}` (Jinja) or `{{ data|json_script:"data" }}` (Django).

False positive: `|safe` on sanitized output or on a fixed string the developer wrote, and `|safe` in a plain-text template (an email's text part, an SMS body, a push title) whose output is never parsed as HTML.

## File uploads

```python
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024     # Flask has no size limit by default
f = request.files["file"]
img = Image.open(f.stream)
img.verify()                                             # content check; re-open and re-save to re-encode
name = f"{uuid4().hex}.png"                              # or secure_filename(f.filename)
```

FastAPI: `UploadFile.filename` and `.content_type` are client input; enforce a size limit at the proxy or while reading in chunks. Django: use `FileField(upload_to=...)` and `default_storage.save()`, validate with `FileExtensionValidator` plus a content check, and serve `MEDIA_ROOT` from storage or as attachments.

False positive: `secure_filename()` or a uuid name; the original name stored only in the database.

## File paths from the request

```python
return send_from_directory(DOWNLOAD_DIR, name)          # Flask: joins safely
p = (BASE / name).resolve()                              # FastAPI or plain Python
if not p.is_relative_to(BASE.resolve()):
    raise HTTPException(status_code=404)
return FileResponse(p)
```

False positive: FastAPI `{name}` and Flask `<name>` path parameters cannot contain `/` (`<path:name>` and query parameters can), but they can contain `\`, a separator on Windows. On a Windows host, or when the value is joined without `send_from_directory` or the resolve-and-contain check above, treat it as a path.

## SSRF

Allowlist hosts when you can. If arbitrary public URLs must work, resolve the host, refuse anything that is not a global address, and connect to the address you checked:

```python
import ipaddress, socket
from urllib.parse import urlsplit

def checked_ip(url: str) -> str:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("https URLs only")
    ips = {info[4][0] for info in socket.getaddrinfo(parts.hostname, parts.port or 443)}
    for ip in ips:
        addr = ipaddress.ip_address(ip)
        if not addr.is_global or addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
            raise ValueError("address not allowed")
    return sorted(ips)[0]
```

Connect to that IP but keep TLS tied to the original name, e.g. `urllib3.HTTPSConnectionPool(ip, port=443, server_hostname=hostname, assert_hostname=hostname, headers={"Host": hostname})`, or use a maintained SSRF-filtering transport that checks the address at connect time. Never set `verify=False` to make the IP connection work: TLS then checks nothing. Do not follow redirects without checking each hop again (`requests.get(..., allow_redirects=False)`; httpx does not follow by default). Use a Python with the CVE-2024-4032 fix (3.8.20, 3.9.20, 3.10.15, 3.11.10, 3.12.4, any 3.13, or newer in that line); older ones give wrong `is_private` and `is_global` answers for some ranges.

False positive: a fixed host where the request fills only the path or query is not SSRF.

LAST-VERIFIED: 2026-10-06
