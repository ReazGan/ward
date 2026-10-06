# Rotating a leaked secret

What to do when a real secret reached a repo, a bundle, an app binary or a log. The account owner does these steps in the provider's console. The agent explains them, points at the right section, and never rotates, revokes or deletes keys itself.

## Order of work

1. Contain: revoke or disable the leaked credential now. If production would break, create the replacement first and switch within minutes, not days.
2. Replace: create a new credential with the least privilege that works, keep it in the host's secret store, redeploy every consumer. Env changes on Vercel and Netlify apply only to new deployments.
3. Investigate: read the provider's usage, billing and audit logs for the exposure window. Look for persistence: new keys, users, webhooks, OAuth apps.
4. Remove the cause: the bundle, the committed file, the log line. Then decide on history (last section).
5. Never put a leaked signing key into a "previous keys" or fallback list. That keeps it valid.

Treat a value that was public for one commit, one deploy or one app release as already copied. Rebuilding does not help on its own: old bundles, CDN caches and installed app binaries keep it.

## Stripe

- Secret (`sk_live_...`) or restricted (`rk_live_...`) key: Dashboard > API keys > Rotate key. For a leak pick expiry Now and accept a short outage; the grace period (up to 7 days) is for routine rotation.
- Webhook signing secret (`whsec_...`): Webhooks > endpoint > Roll secret, and expire the old one now (overlap can be up to 24 hours). A `whsec_` from Clerk, Resend or another Svix-based sender: see [Webhook secrets from Svix-based senders](#webhook-secrets-from-svix-based-senders).
- Organization key (`sk_org_...`, one key for several accounts in an organization): organization Dashboard > API keys > rotate now. It reaches every account it was scoped to, so check each one.
- Prefer restricted keys with only the permissions you use, and attach an access policy (IP addresses, or ASN and country) to every live key. Access policies replaced the old IP restrictions.
- Check: request logs per key, recent refunds, payouts and transfers, new webhook endpoints, Connect account changes.
- Breaks: every server still on the old key, and webhook verification until the new `whsec_` is deployed.
- Publishable keys (`pk_...`) are public by design and need no rotation.

## Supabase

- Publishable key (`sb_publishable_...`) or legacy `anon` JWT in the client: not a leak. Fix Row Level Security; rotating does not help while policies are missing.
- Secret key (`sb_secret_...`): Settings > API Keys, create a new secret key, deploy it to every backend and Edge Function, confirm, then delete the leaked one (deletion cannot be undone). Several secret keys can coexist, so there is no downtime and no logout. Fix how it leaked first.
- Legacy `service_role` JWT: it cannot be rotated in place. Create `sb_secret_` and `sb_publishable_` keys, move all code to them, then deactivate the legacy `anon` and `service_role` keys (reversible). The leak is only closed once the legacy JWT secret is revoked (next item).
- Legacy JWT secret (anyone can mint a token for any role): migrate to JWT Signing Keys, create a new asymmetric key and rotate to it, disable the legacy `anon` and `service_role` keys, then revoke the legacy secret. Sessions refresh with their refresh tokens; clients that only hold an old access token must sign in again.
- Self-hosted stack whose keys decode to `iss: supabase-demo`: it still uses the published demo secret. Generate a new JWT secret and keys before exposing it, and change the default database and dashboard passwords.
- Personal access token (`sbp_...`): Account > Access Tokens, revoke it. It acts as you on the Management API for every project you can reach, so also treat those projects' secret keys and database passwords as leaked and rotate them.
- Database password: Settings > Database > reset password. Every direct and pooled connection string breaks until updated.
- GitHub secret scanning sends `sb_secret_` keys and Supabase personal access tokens (`sbp_`) found in public repos to Supabase, which revokes them. Legacy `service_role` JWTs are not covered and cannot be revoked one by one: follow the legacy steps above. Leaks outside public GitHub repos are not covered either.
- Check: Auth and API logs for the window, users with raised roles, changed policies, storage bucket changes.

## OpenAI

- Platform > API keys: create a new project-scoped key with restricted permissions, deploy it, then revoke the old key (immediate).
- An admin key (`sk-admin-...`) manages the organization: rotate it first, then review members, projects and keys created during the window.
- Check: usage per project and key, and the stored data the key could reach (files, vector stores, assistants, batches, fine-tunes).
- Set project budgets. OpenAI disables keys it finds in public GitHub commits, elsewhere on the public internet or inside apps in app stores, without asking first, so a shipped key can stop working at any time. Do not count on that either way: rotate the key yourself.
- Breaks: everything on the old key, at once.

## Anthropic

- Console > API keys: disable or delete the leaked key, create a new one in the right workspace, deploy.
- Use one workspace per app and environment with a spend limit, so a leak stays contained.
- Check: usage and cost for the window, and files uploaded through that workspace.
- Keys found in public GitHub repos are deactivated automatically and the owner is emailed. Other leaks are not covered.

## AWS

- Set the leaked access key to Inactive in IAM now (minutes matter), create the replacement, update consumers, then delete the old key. The owner can use `aws iam update-access-key --status Inactive` and `aws iam delete-access-key`.
- Temporary credentials already minted from that key stay valid until they expire (up to 36 hours). Deleting the key does not end them. Attach a deny-all policy such as `AWSDenyAll` to the IAM user until the investigation is done; that covers `GetSessionToken` and `GetFederationToken` credentials.
- Role sessions are not covered by a policy on the user. If the user could call `sts:AssumeRole`, open each role it could assume and use Revoke active sessions (IAM > Roles > role > Revoke sessions).
- Better: replace long-lived keys with roles or OIDC (GitHub Actions OIDC, instance and task roles).
- Investigate in every region: CloudTrail events for that `AccessKeyId`, new IAM users, keys, roles and login profiles, EC2, Lambda and ECS resources, SES sending, S3 access, billing anomalies.
- AWS may attach a quarantine policy to a key it finds in a public repo. That limits abuse; it does not replace rotation.

## GitHub

- `ghp_`, `github_pat_`, `gho_`, `ghu_` and `ghs_` tokens pushed to a public repo or gist are revoked by GitHub automatically. For any other leak: Settings > Developer settings > Personal access tokens, delete or regenerate.
- GitHub App private key or OAuth app client secret: generate a new one, deploy, delete the old one. Deploy keys: remove and add again.
- Prefer fine-grained tokens scoped to the repos you need, with an expiry. In Actions use `GITHUB_TOKEN` or OIDC.
- Check: the security and audit logs for the token, new deploy keys, webhooks, collaborators, workflow changes, releases and packages.
- Breaks: CI jobs and scripts on the old token.

## Google

- Firebase web `apiKey` in `firebaseConfig`: not a secret. Open the key in Credentials and check its API restrictions: it should list only Firebase APIs. Keys made by hand, and older keys that picked up every API enabled in the project when Firebase restricted them in May 2024, may allow more. If the key is unrestricted or its list includes the Generative Language (Gemini) API, restrict it now and check billing for Gemini use in the exposure window. Firebase AI Logic needs that API enabled in the project, not on this key. Enforce Security Rules and App Check. Rotate only if abuse continues after restricting.
- Service account key JSON (`"type": "service_account"`): critical. IAM > Service accounts > Keys, delete the leaked key (immediate and permanent). Create a new key only if keyless auth (Cloud Run or Functions default credentials, Workload Identity Federation) will not do. Review IAM changes and Cloud Audit Logs.
- Gemini API key: never in client code. Delete and recreate it, and call it from a server or Firebase AI Logic.
- Maps and other browser keys: add application restrictions (HTTP referrer, Android package and SHA-1, iOS bundle ID) and API restrictions (only the APIs you call), one key per app and platform. Credentials > key > Rotate key keeps both values valid until you delete the previous key; for abuse in progress, delete it right after the new key is deployed. Set budgets and quota caps.
- OAuth client secret: add a new secret in the Credentials page, deploy it, then delete the old one.
- Breaks: shipped mobile apps embed the key and fail until users update.

## Database

- Change the database user's password (or create a new user, switch to it, drop the old one), update `DATABASE_URL` everywhere, restart.
- Check the database logs for unknown client IPs, and restrict network access so the database is not open to `0.0.0.0/0`.

## Webhook secrets from Svix-based senders

Clerk, Resend and other senders built on Svix also use `whsec_` secrets. In the sender's webhook settings, rotate the endpoint's signing secret and deploy the new value to your receiver at once. Svix keeps signing with the old secret for 24 hours so nothing breaks, but your receiver stops accepting the leaked one as soon as it has the new value.

## Signing secrets

Changing these logs users out or invalidates issued tokens. For a leak that is the point; do not keep the old value as a fallback.

- Django `SECRET_KEY`: set a new one. `SECRET_KEY_FALLBACKS` is for routine rotation only, never for a leaked key. Passwords are unaffected.
- Laravel `APP_KEY`: `php artisan key:generate` per environment. A new key logs everyone out and makes data encrypted with `Crypt` or encrypted casts unreadable. Use `APP_PREVIOUS_KEYS` only inside a controlled re-encryption job, then remove the old key.
- Flask `SECRET_KEY`: a new value ends all sessions. Flask 3.1+ has `SECRET_KEY_FALLBACKS` for routine rotation.
- JWT secrets and Auth.js `AUTH_SECRET`: a new value invalidates issued tokens and sessions. Auth.js and express-session accept a list of secrets for rotation; a leaked one must not stay in it.
- Generate per environment: `python -c "import secrets; print(secrets.token_urlsafe(64))"` or `openssl rand -base64 48`.

## Private keys

- TLS key: have the certificate reissued with a new key and revoke the old certificate with the CA.
- SSH key: remove the public key from every `authorized_keys` file, deploy-key list and Git host, then create a new pair.
- JWT, push notification or app signing keys: generate a new key at the issuer, deploy it, delete the old one.
- Android upload key (keystore plus its `storePassword` / `keyPassword`): with Play App Signing, create a new upload key and request an upload key reset in Play Console (Manage Play app signing); approval takes a few days. Without Play App Signing the signing key itself leaked: enroll, or plan key rotation, before the next release.

## Other providers

SendGrid, Resend, Postmark, Slack, Mapbox secret tokens, OpenRouter, Groq, xAI, Hugging Face, npm, GitLab, Discord bot tokens and the like:

- Revoke or regenerate the token in the provider's dashboard, store the new one in the secret store, redeploy.
- Check the provider's usage or sending logs for the window. Stolen email keys are often used for spam; stolen npm or GitLab tokens for publishing tampered versions.
- Scope new tokens to the minimum and give them an expiry where the provider supports it.

## Purge git history

Rotate first. A rewrite does not reach existing clones, forks, CI caches, Docker layers, published packages or bots that already copied the value; GitHub's own guide starts with revoking the secret. Rewrite history mainly for data that cannot be rotated, such as personal data.

Needs git-filter-repo 2.47 or newer (`pip install git-filter-repo`). Coordinate with collaborators first. The owner runs, in a fresh clone:

```bash
git clone https://github.com/OWNER/REPO.git
cd REPO
git-filter-repo --sensitive-data-removal --invert-paths --path .env
# or replace values, one rule per line in ../expressions.txt:  regex:sk_live_[A-Za-z0-9]+==>REMOVED
git-filter-repo --sensitive-data-removal --replace-text ../expressions.txt
git log --all -p --no-color | grep -c "sk_live_"      # expect 0
git push --force --mirror origin
```

Side effects to tell the user:

- Commit hashes change, automation that pins hashes breaks, commit signatures are dropped.
- PR diffs that touched rewritten commits stop rendering. Forks keep the old history.
- Collaborators must re-clone or rebase. One push from an old clone brings the secret back.
- Ask GitHub Support to purge cached views and PR refs only when rotation cannot fix the exposure.
- Also clean Actions logs and artifacts, release assets, container images, package versions, wikis, issue comments and mirrors.

Stop new leaks: `.gitignore` with `.env` and `.env.*` (keep `!.env.example`), `git rm --cached .env`, and a pre-commit secret scan.

LAST-VERIFIED: 2026-10-06
