# Laravel

Fixes for Laravel findings. Each item ends with the false-positive check to do before you report it.

## Debug mode

The production `.env` on the server:

```dotenv
APP_ENV=production
APP_DEBUG=false
```

- Keep the default `'debug' => (bool) env('APP_DEBUG', false)` in `config/app.php`. Never hardcode `true` and never default it to `true`.
- Run `php artisan config:cache` on deploy. After that `env()` returns null outside config files, so read settings through `config()`.
- Never upload or commit the local `.env`. Create the server's `.env` on the server and run `php artisan key:generate` there.
- Laravel's docs warn that debug mode in production exposes sensitive configuration values to users.

False positive: `APP_DEBUG=true` in an untracked local `.env` with `APP_ENV=local` is the normal dev setup. `.env.example` is a template.

## Ignition

Ignition is the debug error page. `facade/ignition` below 2.5.2 with debug mode on is CVE-2021-3129 (unauthenticated remote code execution, listed in CISA KEV).

- Keep `spatie/laravel-ignition` (or `facade/ignition`) in `require-dev` and deploy with `composer install --no-dev --optimize-autoloader`.
- Upgrade `facade/ignition` to 2.5.2 or later, or move to Laravel 9+ with `spatie/laravel-ignition`.
- Read the installed version in `composer.lock`, not the constraint in `composer.json`.

False positive: in `require-dev` and installed with `--no-dev`, it never reaches production.

## Web root

The document root must be `<project>/public`. On shared hosting, keep the project outside `public_html` and point (or symlink) only `public/` there. Uploading the whole project into `public_html` makes `.env`, `storage/logs/laravel.log` and `composer.json` downloadable.

```nginx
root /var/www/app/public;
location ~ /\.(?!well-known) { deny all; }
```

False positive: a root `.htaccess` that rewrites every request into `public/` hides most files, but still request `/.env` and `/storage/logs/laravel.log` on the live site.

## Raw queries

`DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw` and `DB::select` put strings straight into SQL. Use bindings.

```php
$users = User::where('email', $email)->get();
$rows = DB::select('select * from orders where user_id = ?', [$userId]);
$query->whereRaw('price > ?', [$min]);
```

Column names cannot be bound, so allowlist sort columns:

```php
$col = in_array($request->sort, ['name', 'created_at'], true) ? $request->sort : 'created_at';
$query->orderBy($col);
```

False positive: raw expressions built only from constants are fine.

## Mass assignment

`Model::create($request->all())` lets a client set any column, such as `role`, `is_admin` or `credits`.

```php
protected $fillable = ['name', 'bio'];

$data = $request->validate(['name' => 'required|string|max:100', 'bio' => 'nullable|string']);
$request->user()->update($data);
```

Set roles, ownership and balances on the server. Route-model binding loads any row by id, so authorize it: `$this->authorize('view', $order);` with a policy that compares `$order->user_id` to the user.

False positive: `$request->all()` into a model whose `$fillable` lists only safe columns is safe. `$guarded = []` is not.

## Cashier webhook secret

Cashier verifies Stripe signatures only when a webhook secret is configured. Without `STRIPE_WEBHOOK_SECRET` anyone can post a fake payment event.

```dotenv
STRIPE_WEBHOOK_SECRET=whsec_...
```

- Use a separate secret per environment, from the Stripe dashboard endpoint.
- Exclude only the webhook path from CSRF: `$middleware->validateCsrfTokens(except: ['stripe/*']);` in `bootstrap/app.php` (Laravel 11+).
- A custom webhook controller must call `\Stripe\Webhook::constructEvent($payload, $signature, $secret)` and fail closed when the secret is empty.

False positive: a secret set in the server env is fine even when `.env.example` shows a placeholder.

## Blade raw output

`{{ $x }}` escapes, `{!! $x !!}` prints raw HTML. Use `{{ }}` for user data. When you must render user HTML, sanitize it first with HTMLPurifier (for example the `mews/purifier` package).

Markdown: `Str::markdown()` and CommonMark pass raw HTML through by default. For user text use `Str::markdown($text, ['html_input' => 'strip', 'allow_unsafe_links' => false])` (or `'escape'`); if some HTML must survive, run the output through HTMLPurifier.

False positive: `{!! !!}` around HTML you built yourself, `@json($data)` which escapes for script context, or Markdown rendered with `html_input` set to `escape` or `strip` and `allow_unsafe_links` false is fine. Read where the value comes from.

## App key

`APP_KEY` encrypts cookies and `Crypt` data. Generate one per environment with `php artisan key:generate`; never copy it between projects or commit it. A leaked key can lead to remote code execution in some setups.

If it leaked: generate a new key and deploy it (everyone is logged out). Use `APP_PREVIOUS_KEYS` only inside a controlled re-encryption job, then remove the old key, because a listed key is still accepted. See rotation.md.

False positive: an empty `APP_KEY=` in `.env.example` is the template.

## CORS

```php
// config/cors.php
'paths' => ['api/*', 'sanctum/csrf-cookie'],
'allowed_origins' => [env('FRONTEND_URL')],
'supports_credentials' => true,
```

Never `'allowed_origins' => ['*']` together with `'supports_credentials' => true`.

False positive: `['*']` with credentials off is fine for a token-only API.

## Session cookies

`config/session.php` keeps `'http_only' => true`, `'same_site' => 'lax'` and `'secure' => env('SESSION_SECURE_COOKIE')`. Set `SESSION_SECURE_COOKIE=true` in the production env; unset means the cookie is not Secure.

False positive: `same_site` none can be needed for an app embedded in another site; it then needs `secure` and CSRF protection.

## Plain PHP cookies

`setcookie()` defaults HttpOnly and Secure to off. Pass the options array (PHP 7.3+) for any session or token cookie:

```php
setcookie('session', $token, [
    'expires' => time() + 3600, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax',
]);
```

For the built-in session, set `session.cookie_httponly=1`, `session.cookie_secure=1` and `session.cookie_samesite=Lax` in `php.ini`, or pass the same keys to `session_set_cookie_params([...])` before `session_start()`. Never turn them off with `ini_set`.

False positive: theme or locale cookies and a CSRF token that JavaScript must read do not need HttpOnly.

## Logging

```php
Log::info('login', ['user_id' => $user->id, 'ip' => $request->ip()]);
Log::info('form', $request->except(['password', 'password_confirmation', 'token']));
```

- Never `Log::info($request->all())` on auth routes, and never log `config()` or `$request->bearerToken()`.
- Remove `dd()` and `dump()` before deploy.
- Telescope and Horizon record requests: keep their gates (`viewTelescope`, `viewHorizon`) limited to admins and never `return true`.

False positive: logging selected non-secret fields is fine.

LAST-VERIFIED: 2026-10-06
