"""Tests for _rules_dataauth.py: every rule fires on its vulnerable sample and
stays quiet on the safe variant next to it."""

import json
import re

import pytest

import _rules_dataauth as da
from conftest import REPO_ROOT

REFS = {
    "stack-supabase.md": REPO_ROOT / "skills" / "preflight-audit" / "references" / "stack-supabase.md",
    "stack-firebase.md": REPO_ROOT / "skills" / "preflight-audit" / "references" / "stack-firebase.md",
    "data-and-auth.md": REPO_ROOT / "skills" / "secure-by-default" / "references" / "data-and-auth.md",
}

SB = {"supabase/config.toml": "project_id = \"demo\"\n"}
NEXT_PKG = {"package.json": json.dumps({"dependencies": {"next": "14.2.30", "react": "18.3.1",
                                                          "@supabase/supabase-js": "2.45.0"}})}
VITE_PKG = {"package.json": json.dumps({"dependencies": {"react": "18.3.1", "react-dom": "18.3.1",
                                                          "@supabase/supabase-js": "2.45.0"},
                                         "devDependencies": {"vite": "5.4.0"}})}
EXPRESS_PKG = {"package.json": json.dumps({"dependencies": {"express": "4.19.2", "mongoose": "8.5.0"}})}
FASTAPI = {"requirements.txt": "fastapi==0.110\nsqlalchemy==2.0\n"}
DJANGO = {"requirements.txt": "django==5.0\ndjangorestframework==3.15\n", "manage.py": "import django\n"}
LARAVEL = {"composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}})}


def _found(tmp_path, write_tree, scan_rules, rule, files, stacks=None):
    write_tree(tmp_path, files)
    res = scan_rules(tmp_path, rule_ids=[rule], stacks=stacks)
    assert not [w for w in res.warnings if "dataauth" in str(w) or rule in str(w)], res.warnings
    return [f for f in res.findings if f.rule == rule]


def _sql(text, name="supabase/migrations/20240101000000_init.sql", extra=None):
    files = dict(SB)
    files[name] = text
    files.update(extra or {})
    return files


# --- Supabase: RLS disabled ---------------------------------------------------------------

PROFILES = "create table public.profiles (\n  id uuid primary key,\n  email text\n);\n"


@pytest.mark.parametrize("files,expected", [
    (_sql(PROFILES, extra={"src/App.tsx": "const { data } = await supabase.from('profiles').select('*')\n"}),
     [("critical", 1)]),
    (_sql("create table notes (id bigint primary key, body text);\n"), [("high", 1)]),
    (_sql("CREATE TABLE IF NOT EXISTS \"public\".\"todos\" (\"id\" bigint);\n"
          "create policy \"own\" on public.todos for select using (auth.uid() = user_id);\n"), [("high", 1)]),
    (_sql(PROFILES + "alter table public.profiles enable row level security;\n"
          "alter table public.profiles disable row level security;\n"), [("high", 1)]),
    (_sql("create table public.orders (id int);\ngrant select on public.orders to anon;\n"), [("critical", 1)]),
])
def test_rls_disabled_fires(tmp_path, write_tree, scan_rules, files, expected):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-rls-disabled", files)
    assert [(f.severity, f.line) for f in got] == expected


def test_rls_disabled_message_mentions_inert_policies(tmp_path, write_tree, scan_rules):
    files = _sql("create table public.todos (id bigint);\n"
                 "create policy \"own\" on public.todos for select using (auth.uid() = user_id);\n")
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-rls-disabled", files)
    assert "policies do nothing" in got[0].message


@pytest.mark.parametrize("files", [
    _sql(PROFILES + "alter table public.profiles enable row level security;\n"),
    _sql("CREATE TABLE IF NOT EXISTS \"public\".\"profiles\" (\"id\" uuid NOT NULL);\n"
         "ALTER TABLE \"public\".\"profiles\" ENABLE ROW LEVEL SECURITY;\n"),
    _sql(PROFILES, extra={"supabase/migrations/20240102000000_rls.sql":
                          "alter table if exists only profiles enable row level security;\n"}),
    _sql("create table private.secrets (id int);\ncreate schema private;\n"),
    _sql("create temp table scratch (id int);\n"),
    _sql(PROFILES + "drop table if exists public.profiles cascade;\n"),
    _sql("create table public.old_name (id int);\nalter table public.old_name rename to new_name;\n"
         "alter table public.new_name enable row level security;\n"),
    _sql(PROFILES + "do $$ declare r record; begin for r in select tablename from pg_tables where "
                    "schemaname = 'public' loop execute format('alter table %I enable row level security', "
                    "r.tablename); end loop; end $$;\n"),
    _sql(PROFILES + "revoke all on table public.profiles from anon, authenticated;\n"),
    _sql("-- create table public.profiles (id uuid);\n/* create table public.x (id int); */\n"),
    _sql("create table api_data (id int);\n", extra={"supabase/config.toml": "[api]\nschemas = [\"api\"]\n"}),
    _sql("create table public.events_2024 partition of public.events for values in ('2024');\n"),
])
def test_rls_disabled_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-rls-disabled", files) == []


def test_rls_rule_needs_supabase_stack(tmp_path, write_tree, scan_rules):
    files = {"db/schema.sql": PROFILES, "package.json": json.dumps({"dependencies": {"pg": "8"}})}
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-rls-disabled", files) == []


# --- Supabase: permissive policies -------------------------------------------------------------

RLS_ON = "alter table public.%s enable row level security;\n"


@pytest.mark.parametrize("sql,severity", [
    ("create policy \"all\" on public.todos for all using (true);\n", "critical"),
    ("create policy \"edit\" on public.todos for update to authenticated using (true);\n", "high"),
    ("create policy \"Enable insert for authenticated users only\" on \"public\".\"todos\" as permissive "
     "for insert to authenticated with check (true);\n", "medium"),
    ("create policy \"anon insert\" on public.todos for insert to anon with check (true);\n", "high"),
    ("create policy \"del\" on public.todos for delete using (auth.role() = 'authenticated');\n", "high"),
    ("create policy \"read\" on public.messages\n  for select\n  using ( true );\n", "high"),
    ("create table public.profiles (id uuid, username text, email text);\n"
     "create policy \"read\" on public.profiles for select using (true);\n", "high"),
    ("create policy \"read\" on public.invoices for select to authenticated using (true);\n", "medium"),
    ("create policy \"files\" on storage.objects for select using (true);\n", "high"),
])
def test_permissive_policy_fires(tmp_path, write_tree, scan_rules, sql, severity):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql))
    assert [f.severity for f in got] == [severity]


@pytest.mark.parametrize("sql", [
    "create policy \"public read\" on public.products for select using (true);\n",
    "create table public.profiles (id uuid, username text, avatar_url text);\n"
    "create policy \"Public profiles are viewable by everyone.\" on profiles for select using ( true );\n",
    "create policy \"own\" on public.todos for update to authenticated using ((select auth.uid()) = user_id) "
    "with check ((select auth.uid()) = user_id);\n",
    "create policy \"limit\" on public.todos as restrictive for all using (true);\n",
    "create policy \"all\" on public.todos for all using (true);\ndrop policy \"all\" on public.todos;\n",
    "create policy \"all\" on public.todos for all using (true);\n"
    "alter policy \"all\" on public.todos using (auth.uid() = user_id);\n",
    "create policy \"svc\" on public.todos for all to service_role using (true);\n",
    "-- create policy \"all\" on public.todos for all using (true);\n",
])
def test_permissive_policy_safe(tmp_path, write_tree, scan_rules, sql):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql)) == []


def test_policy_line_points_at_statement(tmp_path, write_tree, scan_rules):
    sql = "-- header\n\ncreate policy \"x\"\n  on public.todos\n  for delete\n  using (true);\n"
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql))
    assert [f.line for f in got] == [3]


# --- Supabase: user_metadata ---------------------------------------------------------------------

@pytest.mark.parametrize("files,count", [
    (_sql("create policy \"admins\" on public.reports for select\n"
          "  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');\n"), 1),
    (_sql("create function public.handle_new_user() returns trigger language plpgsql security definer "
          "set search_path = '' as $$\nbegin\n  insert into public.profiles (id, role)\n"
          "  values (new.id, new.raw_user_meta_data->>'role');\n  return new;\nend;\n$$;\n"), 1),
    (dict(SB, **{"package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}}),
                 "app/admin/page.tsx": "if (user.user_metadata.role === 'admin') { show() }\n"}), 1),
    (dict(SB, **{"api/views.py": "if user.user_metadata.get('is_admin'):\n    allow()\n"}), 1),
])
def test_user_metadata_fires(tmp_path, write_tree, scan_rules, files, count):
    assert len(_found(tmp_path, write_tree, scan_rules, "data-supabase-user-metadata-authz", files)) == count


@pytest.mark.parametrize("files", [
    _sql("create function public.handle_new_user() returns trigger language plpgsql security definer "
         "set search_path = '' as $$\nbegin\n  insert into public.profiles (id, full_name)\n"
         "  values (new.id, new.raw_user_meta_data->>'full_name');\n  return new;\nend;\n$$;\n"),
    _sql("create policy \"admins\" on public.reports for select\n"
         "  using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');\n"),
    dict(SB, **{"app/page.tsx": "const role = user.app_metadata.role\nconst name = user.user_metadata.full_name\n"}),
])
def test_user_metadata_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-user-metadata-authz", files) == []


# --- Supabase: security definer --------------------------------------------------------------------

DEFINER = ("create or replace function public.is_admin()\nreturns boolean\nlanguage plpgsql\nsecurity definer\n"
           "as $$\nbegin\n  return exists (select 1 from public.admins where id = auth.uid());\nend;\n$$;\n")


def test_definer_search_path(tmp_path, write_tree, scan_rules):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-search-path", _sql(DEFINER))
    assert [(f.line, f.severity) for f in got] == [(1, "medium")]


@pytest.mark.parametrize("sql", [
    DEFINER.replace("security definer\n", "security definer\nset search_path = ''\n"),
    DEFINER + "alter function public.is_admin() set search_path = '';\n",
    DEFINER.replace("security definer\n", ""),
    "-- " + DEFINER.replace("\n", "\n-- "),
])
def test_definer_search_path_safe(tmp_path, write_tree, scan_rules, sql):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-search-path", _sql(sql)) == []


WIPE = ("create function public.wipe_notes() returns void language sql security definer set search_path = ''\n"
        "as $$ delete from public.notes; $$;\n")


def test_definer_exposed(tmp_path, write_tree, scan_rules):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(WIPE))
    assert len(got) == 1 and "rpc" in got[0].message


@pytest.mark.parametrize("sql", [
    DEFINER,
    WIPE.replace("returns void", "returns trigger"),
    WIPE.replace("public.wipe_notes", "private.wipe_notes"),
    WIPE + "revoke execute on function public.wipe_notes() from public, anon, authenticated;\n",
    "alter default privileges in schema public revoke execute on functions from public, anon, authenticated;\n"
    + WIPE + WIPE.replace("wipe_notes", "wipe_more"),
    WIPE.replace("security definer", "security invoker"),
])
def test_definer_exposed_safe(tmp_path, write_tree, scan_rules, sql):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(sql)) == []


def test_default_privileges_cover_only_later_functions(tmp_path, write_tree, scan_rules):
    # ALTER DEFAULT PRIVILEGES changes functions created after it, not the ones already there
    sql = (WIPE + "alter default privileges in schema public revoke execute on functions from public, anon, "
           "authenticated;\n" + WIPE.replace("wipe_notes", "wipe_more"))
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(sql))
    assert [f.line for f in got] == [1] and "wipe_notes" in got[0].message


# --- Supabase: views ----------------------------------------------------------------------------------

@pytest.mark.parametrize("sql,severity", [
    ("create view public.user_emails as select id, email from auth.users;\n", "critical"),
    ("create or replace view public.order_summary as\n  select o.id, o.total, p.email from orders o join "
     "profiles p on p.id = o.user_id;\n", "high"),
    ("create materialized view public.stats as select id, total from public.orders;\n", "high"),
    ("create view public.v with (\"security_invoker\"='off') as select id, email from public.profiles;\n", "high"),
])
def test_view_fires(tmp_path, write_tree, scan_rules, sql, severity):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-view-bypasses-rls", _sql(sql))
    assert [f.severity for f in got] == [severity]


@pytest.mark.parametrize("sql", [
    "create view public.order_summary with (security_invoker = true) as select id from public.orders;\n",
    "create view public.order_summary as select id from public.orders;\n"
    "alter view public.order_summary set (security_invoker = on);\n",
    "create view private.order_summary as select id from public.orders;\n",
    "create view public.order_summary as select id from public.orders;\n"
    "revoke select on public.order_summary from anon, authenticated;\n",
    "create or replace view public.init_state with (security_invoker = off) as\n"
    "select count(sub.id) as is_initialized from (select id from public.sales limit 1) sub;\n",
    "create materialized view public.stats as select count(*) from public.orders;\n",
])
def test_view_safe(tmp_path, write_tree, scan_rules, sql):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-view-bypasses-rls", _sql(sql)) == []


# --- Supabase: service role key in client code ----------------------------------------------------------

def test_service_key_in_spa_client(tmp_path, write_tree, scan_rules):
    files = dict(VITE_PKG, **{"src/lib/supabase.ts":
                              "import { createClient } from '@supabase/supabase-js'\n"
                              "export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL,\n"
                              "  import.meta.env.SUPABASE_SERVICE_ROLE_KEY)\n"
                              "export const admin = createClient(url, supabaseServiceKey)\n"})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files)
    assert [(f.file, f.line, f.severity) for f in got] == [("src/lib/supabase.ts", 3, "high"),
                                                           ("src/lib/supabase.ts", 4, "high")]


def test_service_key_public_prefix_left_to_secret_rule(tmp_path, write_tree, scan_rules):
    files = dict(VITE_PKG, **{"src/lib/supabase.ts":
                              "export const s = createClient(url, import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY)\n"})
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files) == []


def test_service_key_in_use_client_component(tmp_path, write_tree, scan_rules):
    files = dict(NEXT_PKG, **{"components/AdminTable.tsx":
                              "'use client'\nconst key = process.env.SUPABASE_SERVICE_ROLE_KEY\n"})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files)
    assert [(f.line, f.severity) for f in got] == [(2, "high")]


def test_service_key_in_module_imported_by_client(tmp_path, write_tree, scan_rules):
    files = dict(NEXT_PKG, **{
        "components/Users.tsx": "'use client'\nimport { admin } from '@/lib/admin'\nexport function U() {}\n",
        "lib/admin.ts": "import { createClient } from '@supabase/supabase-js'\n"
                        "export const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!,\n"
                        "  process.env.SUPABASE_SERVICE_ROLE_KEY!)\n",
    })
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files)
    assert [(f.file, f.line, f.severity) for f in got] == [("lib/admin.ts", 3, "high")]
    assert "components/Users.tsx" in got[0].message


@pytest.mark.parametrize("extra", [
    {"components/Users.tsx": "'use client'\nimport { admin } from '../lib/admin'\n",
     "lib/admin.ts": "import 'server-only'\nexport const k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"},
    {"app/api/users/route.ts": "const k = process.env.SUPABASE_SERVICE_ROLE_KEY\nexport async function GET() {}\n"},
    {"supabase/functions/admin/index.ts": "const k = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')\n"},
    {"components/Login.tsx": "'use client'\n// never put the service_role key here\n"
                             "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY\n"},
    {"components/Act.tsx": "'use client'\nimport { save } from '@/app/actions'\n",
     "app/actions.ts": "'use server'\nconst k = process.env.SUPABASE_SERVICE_ROLE_KEY\n"},
])
def test_service_key_safe(tmp_path, write_tree, scan_rules, extra):
    files = dict(NEXT_PKG, **extra)
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files) == []


def test_service_key_literal_left_to_find_secrets(tmp_path, write_tree, scan_rules, fake_token):
    key = fake_token("sb_" + "secret_", 32)
    files = dict(NEXT_PKG, **{"components/X.tsx": "'use client'\nconst k = '%s'\n" % key})
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files) == []


# --- Supabase: getSession on the server -----------------------------------------------------------------

GETSESSION = "const { data: { session } } = await supabase.auth.getSession()\nif (!session) return redirect('/login')\n"


@pytest.mark.parametrize("path,head,severity", [
    ("middleware.ts", "import { createServerClient } from '@supabase/ssr'\n", "high"),
    ("app/dashboard/page.tsx", "import { createClient } from '@/utils/supabase/server'\n", "medium"),
    ("app/api/me/route.ts", "", "medium"),
])
def test_getsession_server_fires(tmp_path, write_tree, scan_rules, path, head, severity):
    files = dict(NEXT_PKG, **{path: head + GETSESSION})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-getsession-server", files)
    assert [f.severity for f in got] == [severity]


@pytest.mark.parametrize("path,text", [
    ("middleware.ts", GETSESSION + "const { data: { user } } = await supabase.auth.getUser()\n"),
    ("app/api/me/route.ts", GETSESSION.replace("getSession()", "getClaims()")),
    ("components/Nav.tsx", "'use client'\n" + GETSESSION),
    ("lib/helpers.ts", GETSESSION),
])
def test_getsession_server_safe(tmp_path, write_tree, scan_rules, path, text):
    files = dict(NEXT_PKG, **{path: text})
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-getsession-server", files) == []


# --- Firebase rules ------------------------------------------------------------------------------------------

def _fs(body):
    return ("rules_version = '2';\nservice cloud.firestore {\n  match /databases/{database}/documents {\n"
            + body + "  }\n}\n")


def _st(body):
    return "rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n" + body + "  }\n}\n"


@pytest.mark.parametrize("files,expected", [
    ({"firestore.rules": _fs("    match /{document=**} {\n      allow read, write: if true;\n    }\n")},
     [(5, "critical")]),
    ({"firestore.rules": _fs("    match /users/{uid} {\n      allow read, write;\n    }\n")}, [(5, "critical")]),
    ({"firestore.rules": _fs("    match /messages/{id} {\n      allow read: if true;\n    }\n")}, [(5, "high")]),
    ({"firestore.rules": _fs("    match /contact/{id} {\n      allow create: if true;\n    }\n")}, [(5, "high")]),
    ({"storage.rules": _st("    match /{allPaths=**} {\n      allow read: if true;\n    }\n")}, [(5, "critical")]),
    ({"database.rules.json": '{\n  "rules": {\n    ".read": true,\n    ".write": true\n  }\n}\n'},
     [(3, "critical"), (4, "critical")]),
    ({"database.rules.json": '{\n  "rules": {\n    "messages": {\n      ".write": "true"\n    }\n  }\n}\n'},
     [(4, "critical")]),
])
def test_firebase_open_fires(tmp_path, write_tree, scan_rules, files, expected):
    got = _found(tmp_path, write_tree, scan_rules, "data-firebase-rules-open", files)
    assert [(f.line, f.severity) for f in got] == expected


@pytest.mark.parametrize("files", [
    {"firestore.rules": _fs("    match /posts/{id} {\n      allow read: if true;\n"
                            "      allow write: if request.auth != null && request.auth.uid == resource.data.uid;\n"
                            "    }\n")},
    {"firestore.rules": _fs("    match /users/{userId} {\n"
                            "      allow read, write: if request.auth != null && request.auth.uid == userId;\n"
                            "    }\n")},
    {"firestore.rules": _fs("    match /{document=**} {\n      allow read, write: if false;\n    }\n")},
    {"firestore.rules": _fs("    // allow read, write: if true;\n    /* match /{document=**} { allow read, write; } */\n")},
    {"database.rules.json": '{"rules": {"users": {"$uid": {".read": "$uid === auth.uid", '
                            '".write": "$uid === auth.uid"}}}}'},
    {"database.rules.json": '{"rules": {"leaderboard": {".read": true, ".write": false}}}'},
    {"storage.rules": _st("    match /public/{file} {\n      allow read: if true;\n    }\n")},
])
def test_firebase_open_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-firebase-rules-open", files) == []


@pytest.mark.parametrize("files,count", [
    ({"firestore.rules": _fs("    match /{document=**} {\n"
                             "      allow read, write: if request.time < timestamp.date(2026, 11, 4);\n    }\n")}, 1),
    ({"database.rules.json": '{"rules": {\n".read": "now < 1767225600000",\n".write": "now < 1767225600000"}}'}, 2),
    ({"firestore.rules": _fs("    match /users/{u} {\n      allow read: if request.auth.uid == u;\n    }\n")}, 0),
])
def test_firebase_test_mode(tmp_path, write_tree, scan_rules, files, count):
    assert len(_found(tmp_path, write_tree, scan_rules, "data-firebase-test-mode", files)) == count


@pytest.mark.parametrize("files,count", [
    ({"firestore.rules": _fs("    match /{document=**} {\n      allow read, write: if request.auth != null;\n"
                             "    }\n")}, 1),
    ({"firestore.rules": _fs("    match /users/{userId} {\n      allow read: if request.auth != null;\n    }\n")}, 1),
    ({"firestore.rules": _fs("    match /posts/{postId} {\n      allow update, delete: if request.auth != null;\n"
                             "    }\n")}, 1),
    ({"firestore.rules": _fs("    function isSignedIn() { return request.auth != null; }\n"
                             "    match /posts/{postId} {\n      allow write: if isSignedIn();\n    }\n")}, 1),
    ({"database.rules.json": '{"rules": {"chats": {".write": "auth != null"}}}'}, 1),
    ({"firestore.rules": _fs("    match /posts/{postId} {\n      allow read: if request.auth != null;\n"
                             "      allow create: if request.auth != null;\n    }\n")}, 0),
    ({"firestore.rules": _fs("    match /users/{userId} {\n"
                             "      allow read: if request.auth != null && request.auth.uid == userId;\n"
                             "    }\n")}, 0),
])
def test_firebase_any_auth(tmp_path, write_tree, scan_rules, files, count):
    assert len(_found(tmp_path, write_tree, scan_rules, "data-firebase-any-auth", files)) == count


ROLE_READ = ("    match /reports/{id} {\n      allow read: if get(/databases/$(database)/documents/users/"
             "$(request.auth.uid)).data.role == 'admin';\n    }\n")


@pytest.mark.parametrize("users_rule,count", [
    ("      allow read, write: if request.auth != null && request.auth.uid == userId;\n", 1),
    ("      allow read: if request.auth.uid == userId;\n"
     "      allow update: if request.auth.uid == userId\n"
     "        && !request.resource.data.diff(resource.data).affectedKeys().hasAny(['role']);\n", 0),
    ("      allow read: if request.auth.uid == userId;\n", 0),
])
def test_firebase_role_field(tmp_path, write_tree, scan_rules, users_rule, count):
    rules = _fs("    match /users/{userId} {\n" + users_rule + "    }\n" + ROLE_READ)
    assert len(_found(tmp_path, write_tree, scan_rules, "data-firebase-role-field", {"firestore.rules": rules})) == count


def test_firebase_custom_claims_not_flagged(tmp_path, write_tree, scan_rules):
    rules = _fs("    match /users/{userId} {\n      allow write: if request.auth.uid == userId;\n    }\n"
                "    match /reports/{id} {\n      allow read: if request.auth.token.admin == true;\n    }\n")
    assert _found(tmp_path, write_tree, scan_rules, "data-firebase-role-field", {"firestore.rules": rules}) == []


# --- Next.js middleware ----------------------------------------------------------------------------------

AUTH_MW = ("import { NextResponse } from 'next/server'\nexport function middleware(req) {\n"
           "  if (!req.cookies.get('session')) return NextResponse.redirect(new URL('/login', req.url))\n}\n")


@pytest.mark.parametrize("ver,fixed", [
    ("14.1.0", "14.2.25"), ("15.2.2", "15.2.3"), ("13.4.19", "13.5.9"), ("12.1.0", "12.3.5"), ("11.1.4", "12.3.5"),
    ("~14.1.0", "14.2.25"), ("^11.1.0", "12.3.5"), ("14.2.25", None), ("15.2.3", None), ("16.0.0", None),
    ("^14.1.0", None), ("~14.2.3", None), ("11.0.0", None), ("latest", None), (">=14", None), (None, None),
])
def test_next_cve_versions(ver, fixed):
    assert da._next_cve(ver) == fixed


def test_next_cve_fires(tmp_path, write_tree, scan_rules):
    files = {"package.json": json.dumps({"dependencies": {"next": "14.1.0"}}, indent=2),
             "middleware.ts": AUTH_MW, "app/page.tsx": "export default function P() {}\n"}
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files)
    assert [(f.file, f.line, f.severity) for f in got] == [("package.json", 3, "critical")]
    # the CVE floor is named as not enough, never as the upgrade target
    assert "14.2.25 closes only this CVE" in got[0].message and "15.5.24" in got[0].message


@pytest.mark.parametrize("mw", [
    # only refreshes the Supabase session cookie
    "import { updateSession } from '@/utils/supabase/middleware'\n"
    "export async function middleware(request) {\n  return await updateSession(request)\n}\n",
    # sends signed-in users from / to their workspace; nobody is turned away
    "export async function middleware(request) {\n  const session = await supabase.auth.getSession()\n"
    "  if (session && request.nextUrl.pathname === '/') return NextResponse.redirect(new URL('/home', request.url))\n"
    "  return NextResponse.next()\n}\n",
])
def test_next_cve_refresh_only_middleware_is_medium(tmp_path, write_tree, scan_rules, mw):
    files = {"package.json": json.dumps({"dependencies": {"next": "14.2.3"}}), "middleware.ts": mw,
             "utils/supabase/middleware.ts": "export async function updateSession(request) {\n"
                                             "  await supabase.auth.getUser()\n  return response\n}\n"}
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files)
    assert [f.severity for f in got] == ["medium"]


def test_next_cve_gate_in_imported_helper_is_critical(tmp_path, write_tree, scan_rules):
    files = {"package.json": json.dumps({"dependencies": {"next": "14.2.3"}}),
             "middleware.ts": "import { updateSession } from '@/utils/supabase/middleware'\n"
                              "export async function middleware(request) {\n  return await updateSession(request)\n}\n",
             "utils/supabase/middleware.ts": "export async function updateSession(request) {\n"
                                             "  const { data: { user } } = await supabase.auth.getUser()\n"
                                             "  if (!user) return NextResponse.redirect(new URL('/login', request.url))\n}\n"}
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files)
    assert [f.severity for f in got] == ["critical"]


def test_next_cve_uses_lockfile_version(tmp_path, write_tree, scan_rules):
    files = {"package.json": json.dumps({"dependencies": {"next": "^15.0.0"}}),
             "package-lock.json": json.dumps({"packages": {"node_modules/next": {"version": "15.1.0"}}}),
             "src/middleware.ts": AUTH_MW}
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files)
    assert len(got) == 1 and "15.1.0" in got[0].message


def test_next_cve_without_auth_is_medium(tmp_path, write_tree, scan_rules):
    files = {"package.json": json.dumps({"dependencies": {"next": "14.0.0"}}),
             "middleware.ts": "export function middleware(req) {\n  return NextResponse.next({ headers: { 'x-a': '1' } })\n}\n"}
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files)
    assert [f.severity for f in got] == ["medium"]


@pytest.mark.parametrize("files", [
    {"package.json": json.dumps({"dependencies": {"next": "14.2.30"}}), "middleware.ts": AUTH_MW},
    {"package.json": json.dumps({"dependencies": {"next": "14.1.0"}}), "app/page.tsx": "x"},
    {"package.json": json.dumps({"dependencies": {"next": "^14.1.0"}}), "middleware.ts": AUTH_MW},
    {"package.json": json.dumps({"dependencies": {"next": "14.1.0", "express": "4"}}),
     "server/middleware.js": "module.exports = function auth(req, res, next) { next() }\n"},
])
def test_next_cve_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-cve", files) == []


NEXTAUTH_MW = "export { default } from 'next-auth/middleware'\nexport const config = { matcher: ['/dashboard/:path*'] }\n"
POST_ROUTE = ("import { prisma } from '@/lib/db'\n\nexport async function POST(req: Request) {\n"
              "  const { title } = await req.json()\n  const post = await prisma.post.create({ data: { title } })\n"
              "  return Response.json(post)\n}\n")


@pytest.mark.parametrize("mw,severity", [
    (NEXTAUTH_MW, "high"),
    (AUTH_MW + "export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] }\n", "high"),
    (AUTH_MW, "medium"),
    (AUTH_MW + "export const config = { matcher: ['/((?!_next/static|_next/image).*)'] }\n", "medium"),
])
def test_middleware_only_auth_fires(tmp_path, write_tree, scan_rules, mw, severity):
    files = dict(NEXT_PKG, **{"middleware.ts": mw, "app/api/posts/route.ts": POST_ROUTE})
    got = _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-only-auth", files)
    assert [(f.file, f.line, f.severity) for f in got] == [("app/api/posts/route.ts", 3, severity)]


@pytest.mark.parametrize("files", [
    {"middleware.ts": NEXTAUTH_MW,
     "app/api/posts/route.ts": POST_ROUTE.replace("export async function POST(req: Request) {\n",
                                                  "export async function POST(req: Request) {\n  const s = await auth()\n")},
    {"middleware.ts": NEXTAUTH_MW, "app/api/webhooks/stripe/route.ts": POST_ROUTE},
    {"app/api/posts/route.ts": POST_ROUTE},
    {"middleware.ts": NEXTAUTH_MW,
     "app/api/posts/route.ts": "import { createClient } from '@/utils/supabase/server'\n"
                               "export async function POST(req) {\n  const supabase = await createClient()\n"
                               "  await supabase.from('posts').insert({ title: 'x' })\n}\n"},
    {"middleware.ts": NEXTAUTH_MW,
     "app/api/posts/route.ts": "export async function GET() {\n  return Response.json(await prisma.post.findMany())\n}\n"},
    # a signed unsubscribe link is its own credential
    {"middleware.ts": NEXTAUTH_MW,
     "app/api/posts/route.ts": POST_ROUTE.replace("const { title } = await req.json()\n",
                                                  "const { title, token } = await req.json()\n"
                                                  "  const email = verifyUnsubscribeToken(token)\n")},
])
def test_middleware_only_auth_safe(tmp_path, write_tree, scan_rules, files):
    files = dict(NEXT_PKG, **files)
    assert _found(tmp_path, write_tree, scan_rules, "data-nextjs-middleware-only-auth", files) == []


# --- IDOR ------------------------------------------------------------------------------------------------

ORDER_ROUTE = ("import { prisma } from '@/lib/db'\nimport { auth } from '@/auth'\n\n"
               "export async function GET(req: Request, { params }: { params: { id: string } }) {\n"
               "  const session = await auth()\n"
               "  if (!session) return new Response(null, { status: 401 })\n"
               "  const order = await prisma.order.findUnique({ where: { id: params.id } })\n"
               "%s"
               "  return Response.json(order)\n}\n")
DELETE_ACTION = ("'use server'\nimport { db } from '@/lib/db'\n\nexport async function deletePost(id: string) {\n"
                 "  await db.post.delete({ where: { id } })\n}\n")
SAFE_ACTION = ("'use server'\nimport { verifySession } from '@/app/lib/dal'\n\n"
               "export async function deletePost(id: unknown) {\n"
               "  if (typeof id !== 'string') throw new Error('bad id')\n"
               "  const { userId } = await verifySession()\n"
               "  const post = await db.post.findUnique({ where: { id } })\n"
               "  if (!post || post.authorId !== userId) throw new Error('forbidden')\n"
               "  await db.post.delete({ where: { id } })\n}\n")
EXPRESS_DELETE = ("const router = require('express').Router()\n"
                  "router.delete('/notes/:id', requireAuth, async (req, res) => {\n"
                  "  await Note.findByIdAndDelete(req.params.id)\n  res.sendStatus(204)\n})\n")


@pytest.mark.parametrize("files,line", [
    (dict(NEXT_PKG, **{"app/api/orders/[id]/route.ts": ORDER_ROUTE % ""}), 7),
    (dict(NEXT_PKG, **{"app/api/orders/[id]/route.ts": ORDER_ROUTE % (
        "  if (!order) return NextResponse.json({ error: 'not found' }, { status: 404 })\n")}), 7),
    (dict(NEXT_PKG, **{"app/orders/[id]/page.tsx":
                       "export default async function Page({ params }: { params: { id: string } }) {\n"
                       "  const order = await db.order.findUnique({ where: { id: params.id } })\n"
                       "  if (!order) notFound()\n  return <Order order={order} />\n}\n"}), 2),
    (dict(NEXT_PKG, **{"app/actions.ts": DELETE_ACTION}), 5),
    (dict(EXPRESS_PKG, **{"routes/notes.js": EXPRESS_DELETE}), 3),
    (dict(NEXT_PKG, **{"pages/api/invoices/[id].ts":
                       "export default async function handler(req, res) {\n  const { id } = req.query\n"
                       "  const inv = await prisma.invoice.findUnique({\n    where: { id: String(id) },\n  })\n"
                       "  res.json(inv)\n}\n"}), 3),
    (dict(SB, **{"supabase/functions/cancel/index.ts":
                 "const supabaseAdmin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)\n"
                 "Deno.serve(async (req) => {\n  const { id } = await req.json()\n"
                 "  await supabaseAdmin.from('orders').delete().eq('id', id)\n  return new Response('ok')\n})\n",
                 "package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}})}), 4),
    (dict(EXPRESS_PKG, **{"routes/orders.js":
                          "router.get('/orders/:id', async (req, res) => {\n"
                          "  const { rows } = await pool.query('SELECT * FROM orders WHERE id = $1', [req.params.id])\n"
                          "  res.json(rows[0])\n})\n"}), 2),
    (dict(EXPRESS_PKG, **{"routes/notes.js":
                          "app.delete('/notes/:id', (req, res) => {\n"
                          "  db.prepare('DELETE FROM notes WHERE id = ?').run(req.params.id)\n  res.sendStatus(204)\n})\n"}), 2),
])
def test_idor_js_fires(tmp_path, write_tree, scan_rules, files, line):
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert [f.line for f in got] == [line]


@pytest.mark.parametrize("files", [
    dict(NEXT_PKG, **{"app/api/orders/[id]/route.ts": ORDER_ROUTE % (
        "  if (order?.userId !== session.user.id) return new Response(null, { status: 403 })\n")}),
    dict(NEXT_PKG, **{"app/api/orders/[id]/route.ts": (ORDER_ROUTE % "").replace(
        "where: { id: params.id }", "where: { id: params.id, userId: session.user.id }")}),
    dict(NEXT_PKG, **{"app/actions.ts": SAFE_ACTION}),
    dict(EXPRESS_PKG, **{"routes/notes.js": EXPRESS_DELETE.replace(
        "Note.findByIdAndDelete(req.params.id)", "Note.findOneAndDelete({ _id: req.params.id, owner: req.user.id })")}),
    dict(EXPRESS_PKG, **{"routes/products.js": "router.get('/products/:id', async (req, res) => {\n"
                                               "  res.json(await Product.findById(req.params.id))\n})\n"}),
    dict(EXPRESS_PKG, **{"routes/posts.js":
                         "router.put('/:id', auth, async (req, res) => {\n"
                         "  let post = await Post.findById(req.params.id)\n"
                         "  if (post.user.toString() !== req.user.id) {\n"
                         "    return res.status(401).json({ msg: 'User not authorized' })\n  }\n"
                         "  post = await Post.findByIdAndUpdate(req.params.id, { $set: fields }, { new: true })\n})\n"}),
    dict(EXPRESS_PKG, **{"routes/me.js": "router.get('/me', auth, async (req, res) => {\n"
                                         "  res.json(await User.findById(req.user.id))\n})\n"}),
    dict(NEXT_PKG, **{"lib/orders.ts": "export async function getOrder(id: string) {\n"
                                       "  return prisma.order.findUnique({ where: { id } })\n}\n"}),
    dict(NEXT_PKG, **{"app/api/orders/[id]/route.ts":
                      "export async function GET(req, { params }) {\n  const supabase = await createClient()\n"
                      "  const { data } = await supabase.from('orders').select('*').eq('id', params.id)\n"
                      "  return Response.json(data)\n}\n"}),
    dict(EXPRESS_PKG, **{"routes/orders.js":
                         "router.get('/orders/:id', async (req, res) => {\n  const { rows } = await pool.query(\n"
                         "    'SELECT * FROM orders WHERE id = $1 AND user_id = $2', [req.params.id, req.user.id])\n"
                         "  res.json(rows[0])\n})\n"}),
    dict(NEXT_PKG, **{"app/api/me/route.ts":
                      "export async function GET() {\n  const session = await auth()\n"
                      "  const user = await prisma.user.findUnique({ where: { id: session.user.id } })\n"
                      "  return Response.json(user)\n}\n"}),
    dict(NEXT_PKG, **{"components/OrderView.tsx":
                      "'use client'\nexport function V({ params }) {\n"
                      "  const o = prisma.order.findUnique({ where: { id: params.id } })\n}\n"}),
    dict(NEXT_PKG, **{"app/api/orders/[id]/route.test.ts": ORDER_ROUTE % ""}),
])
def test_idor_js_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


FASTAPI_READ = ("@app.get(\"/items/{item_id}\")\n"
                "def read_item(item_id: int, user=Depends(current_user), db: Session = Depends(get_db)):\n"
                "    item = db.query(Item).get(item_id)\n%s    return item\n")
FLASK_DELETE = ("@app.route(\"/notes/<int:note_id>\", methods=[\"DELETE\"])\n@login_required\n"
                "def delete_note(note_id):\n    note = Note.query.get_or_404(note_id)\n"
                "    db.session.delete(note)\n    db.session.commit()\n    return \"\", 204\n")


@pytest.mark.parametrize("files,line", [
    (dict(FASTAPI, **{"app/main.py": FASTAPI_READ % ""}), 3),
    (dict(FASTAPI, **{"app.py": FLASK_DELETE}), 4),
    (dict(FASTAPI, **{"app/main.py": FASTAPI_READ.replace("db.query(Item)", "db.query(models.Item)") % ""}), 3),
    (dict(DJANGO, **{"billing/views.py": "def invoice_detail(request, pk):\n"
                                         "    invoice = get_object_or_404(Invoice, pk=pk)\n"
                                         "    return render(request, 'invoice.html', {'invoice': invoice})\n"}), 2),
    (dict(DJANGO, **{"notes/api.py": "class NoteViewSet(viewsets.ModelViewSet):\n    queryset = Note.objects.all()\n"
                                     "    serializer_class = NoteSerializer\n"
                                     "    permission_classes = [IsAuthenticated]\n"}), 1),
    (dict(DJANGO, **{"billing/views.py": "from django.views.generic import DetailView\n\n"
                                         "class InvoiceDetail(LoginRequiredMixin, DetailView):\n    model = Invoice\n"
                                         "    template_name = 'invoice.html'\n"}), 3),
])
def test_idor_python_fires(tmp_path, write_tree, scan_rules, files, line):
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert [f.line for f in got] == [line]


@pytest.mark.parametrize("files", [
    dict(FASTAPI, **{"app/main.py": FASTAPI_READ.replace(
        "db.query(Item).get(item_id)", "db.query(Item).filter(Item.id == item_id, Item.owner_id == user.id).first()")
        % ""}),
    dict(FASTAPI, **{"app/main.py": FASTAPI_READ % (
        "    if item.owner_id != user.id:\n        raise HTTPException(status_code=404)\n")}),
    dict(DJANGO, **{"billing/views.py": "def invoice_detail(request, pk):\n"
                                        "    invoice = get_object_or_404(Invoice, pk=pk, owner=request.user)\n"
                                        "    return render(request, 'x.html', {'invoice': invoice})\n"}),
    dict(DJANGO, **{"billing/services.py": "def load(pk):\n    return Invoice.objects.get(pk=pk)\n"}),
    dict(DJANGO, **{"notes/api.py": "class NoteViewSet(viewsets.ModelViewSet):\n    queryset = Note.objects.all()\n"
                                    "    def get_queryset(self):\n"
                                    "        return Note.objects.filter(owner=self.request.user)\n"}),
    dict(DJANGO, **{"notes/api.py": "class NoteViewSet(viewsets.ModelViewSet):\n    queryset = Note.objects.all()\n"
                                    "    permission_classes = [IsAuthenticated, IsOwner]\n"}),
    dict(DJANGO, **{"shop/api.py": "class ProductViewSet(viewsets.ReadOnlyModelViewSet):\n"
                                   "    queryset = Product.objects.all()\n"}),
    dict(DJANGO, **{"billing/views.py": "class InvoiceDetail(LoginRequiredMixin, DetailView):\n    model = Invoice\n"
                                        "    def get_queryset(self):\n"
                                        "        return Invoice.objects.filter(owner=self.request.user)\n"}),
    dict(DJANGO, **{"billing/views.py": "class InvoiceDetail(UserPassesTestMixin, DetailView):\n    model = Invoice\n"}),
    dict(DJANGO, **{"blog/views.py": "class PostDetail(DetailView):\n    model = Post\n"}),
    dict(FASTAPI, **{"tests/test_items.py": FASTAPI_READ % ""}),
])
def test_idor_python_safe(tmp_path, write_tree, scan_rules, files):
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


def _ctrl(body, name="OrderController"):
    return "<?php\nnamespace App\\Http\\Controllers;\n\nclass %s extends Controller\n{\n%s}\n" % (name, body)


@pytest.mark.parametrize("body,line", [
    ("    public function show(Order $order)\n    {\n        return $order;\n    }\n", 6),
    ("    public function destroy($id)\n    {\n        $note = Note::findOrFail($id);\n"
     "        $note->delete();\n    }\n", 8),
])
def test_idor_laravel_fires(tmp_path, write_tree, scan_rules, body, line):
    files = dict(LARAVEL, **{"app/Http/Controllers/OrderController.php": _ctrl(body)})
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert [f.line for f in got] == [line]


@pytest.mark.parametrize("body", [
    "    public function show(Order $order)\n    {\n        $this->authorize('view', $order);\n"
    "        return $order;\n    }\n",
    "    public function __construct()\n    {\n        $this->authorizeResource(Order::class, 'order');\n    }\n"
    "    public function show(Order $order)\n    {\n        return $order;\n    }\n",
    "    public function show(Product $product)\n    {\n        return view('p', compact('product'));\n    }\n",
    "    public function update(UpdateOrderRequest $request, Order $order)\n    {\n"
    "        $order->update($request->validated());\n    }\n",
    "    public function destroy($id)\n    {\n        $note = $request->user()->notes()->findOrFail($id);\n"
    "        $note->delete();\n    }\n",
])
def test_idor_laravel_safe(tmp_path, write_tree, scan_rules, body):
    files = dict(LARAVEL, **{"app/Http/Controllers/OrderController.php": _ctrl(body)})
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


# --- client-only auth ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("code,fires", [
    ("const isAdmin = localStorage.getItem('isAdmin') === 'true'\n", True),
    ("if (JSON.parse(localStorage.getItem('user') || '{}').role === 'admin') show()\n", True),
    ("const role = sessionStorage.getItem(\"role\")\n", True),
    ("const ok = Cookies.get('role') === 'admin'\n", True),
    ("const theme = localStorage.getItem('theme')\n", False),
    ("const chosen = localStorage.getItem('plan')\n", False),
    ("localStorage.setItem('role', data.role)\n", False),
    ("// const isAdmin = localStorage.getItem('isAdmin')\n", False),
])
def test_client_role_flag(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(VITE_PKG, **{"src/components/AdminRoute.tsx": code})
    got = _found(tmp_path, write_tree, scan_rules, "data-client-role-flag", files)
    assert bool(got) is fires


def test_client_role_flag_ignores_server_code(tmp_path, write_tree, scan_rules):
    files = dict(VITE_PKG, **{"server/index.ts": "const isAdmin = localStorage.getItem('isAdmin')\n"})
    assert _found(tmp_path, write_tree, scan_rules, "data-client-role-flag", files) == []


@pytest.mark.parametrize("path,code,fires", [
    ("src/pages/Admin.tsx", "if (password === 'admin123') setAuthed(true)\n", True),
    ("src/pages/Admin.tsx", "if (pin == \"4821\") unlock()\n", True),
    ("src/pages/Admin.tsx", "if (input === import.meta.env.VITE_ADMIN_PASSWORD) setOk(true)\n", True),
    ("public/admin.html", "<script>\nconst pass = box.value;\nif (pass === 'letmein2024') show();\n</script>\n", True),
    ("src/pages/Admin.tsx", "if ('hunter22' === adminPassword) go()\n", True),
    ("src/pages/Login.tsx", "if (type === 'password') toggle()\n", False),
    ("src/pages/Login.tsx", "const t = input.type === \"password\" ? 'text' : 'password'\n", False),
    ("src/pages/Login.tsx", "if (passwordStrength === 'strong') ok()\n", False),
    ("src/pages/Login.tsx", "if (password === confirmPassword) ok()\n", False),
    ("src/pages/Login.tsx", "if (password.length === 0) return\n", False),
    ("src/pages/Login.tsx", "if (step === 'password') next()\n", False),
    ("src/pages/Login.tsx", "if (password === '') return\n", False),
    ("src/pages/Login.tsx", "if (passwordType === 'text') hide()\n", False),
    ("src/pages/Board.tsx", "if (pinned === 'yes') sortTop()\n", False),
    ("src/pages/Board.tsx", "if (bypass === 'cache') skip()\n", False),
    ("src/pages/Login.tsx", "if (error.code === 'auth/wrong-password') show()\n", False),
    ("src/pages/Login.tsx", "if (typeof password === 'string') go()\n", False),
    ("server/auth.ts", "if (password === 'admin123') ok()\n", False),
])
def test_client_password_check(tmp_path, write_tree, scan_rules, path, code, fires):
    files = dict(VITE_PKG, **{path: code})
    got = _found(tmp_path, write_tree, scan_rules, "data-client-password-check", files)
    assert bool(got) is fires


def test_client_password_evidence_is_masked(tmp_path, write_tree, scan_rules):
    files = dict(VITE_PKG, **{"src/Admin.tsx": "if (password === 'Zq8wPx3mKt7v') ok()\n"})
    got = _found(tmp_path, write_tree, scan_rules, "data-client-password-check", files)
    assert got and "Zq8wPx3mKt7v" not in got[0].evidence


# --- mass assignment ------------------------------------------------------------------------------------------

@pytest.mark.parametrize("path,code", [
    ("routes/users.js", "router.post('/users', async (req, res) => {\n  const user = await User.create(req.body)\n"
                        "  res.json(user)\n})\n"),
    ("app/api/profile/route.ts", "export async function PATCH(req: Request) {\n  const body = await req.json()\n"
                                 "  await supabase.from('profiles').update(body).eq('id', user.id)\n}\n"),
    ("app/api/me/route.ts", "export async function PUT(req: Request) {\n"
                            "  await prisma.user.update({ where: { id: session.user.id }, data: await req.json() })\n}\n"),
    ("app/actions.ts", "'use server'\nexport async function updateProfile(data: ProfileInput) {\n"
                       "  await db.profile.update({\n    where: { id: (await auth()).userId },\n    data,\n  })\n}\n"),
    ("routes/users.js", "router.put('/me', async (req, res) => {\n  Object.assign(req.user, req.body)\n})\n"),
    ("app/api/posts/route.ts", "export async function POST(req: Request) {\n  const body = await req.json()\n"
                               "  await prisma.post.create({ data: { ...body, authorId: session.user.id } })\n}\n"),
])
def test_mass_assignment_js_fires(tmp_path, write_tree, scan_rules, path, code):
    files = dict(NEXT_PKG, **{path: code})
    assert len(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) == 1


@pytest.mark.parametrize("path,code", [
    ("app/api/posts/route.ts", "export async function POST(req: Request) {\n  const { title, content } = await req.json()\n"
                               "  await prisma.post.create({ data: { title, content, authorId } })\n}\n"),
    ("app/api/posts/route.ts", "export async function POST(req: Request) {\n"
                               "  const data = PostSchema.parse(await req.json())\n  await prisma.post.create({ data })\n}\n"),
    ("components/Form.tsx", "'use client'\nexport function F() {\n  const body = await req.json()\n"
                            "  supabase.from('profiles').update(body)\n}\n"),
    ("app/api/x/route.ts", "export async function POST(req: Request) {\n  const body = await req.json()\n"
                           "  throw new Error(body)\n}\n"),
    ("lib/store.ts", "export function save(data) {\n  return db.item.update({ where: { id: 1 }, data })\n}\n"),
    ("routes/hooks.js", "router.post('/hook', express.raw({ type: '*/*' }), (req, res) => {\n"
                        "  const h = crypto.createHmac('sha256', secret)\n  h.update(req.body)\n})\n"),
    ("routes/hooks.js", "router.post('/hook', (req, res) => {\n"
                        "  const sig = crypto.createHmac('sha256', secret).update(req.body).digest('hex')\n})\n"),
    ("app/api/x/route.ts", "export async function POST(req: Request) {\n  const data = await req.json()\n"
                           "  const copy = Object.create(data)\n}\n"),
    ("routes/users.js", "router.get('/me', auth, async (req, res) => {\n  res.json(await User.findById(req.user.id))\n})\n"),
    ("app/api/posts/route.ts", "export async function POST(req: Request) {\n  const data = await req.json()\n"
                               "  const post = await prisma.post.create({ data: { title: data.title } })\n"
                               "  return NextResponse.json({ data })\n}\n"),
])
def test_mass_assignment_js_safe(tmp_path, write_tree, scan_rules, path, code):
    files = dict(NEXT_PKG, **{path: code})
    assert _found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files) == []


@pytest.mark.parametrize("code,fires", [
    ("def create():\n    user = User(**request.json)\n", True),
    ("def create():\n    data = request.get_json()\n    user = User(**data)\n", True),
    ("def create(request):\n    Profile.objects.create(**request.POST.dict())\n", True),
    ("def edit(id):\n    for key, value in request.json.items():\n        setattr(user, key, value)\n", True),
    ("@app.post('/users')\ndef create(payload: dict = Body(...)):\n    return User(**payload)\n", True),
    ("def create(item: ItemCreate):\n    db_item = Item(**item.dict())\n", False),
    ("def create():\n    data = {'name': request.json['name']}\n    user = User(**data)\n", False),
    ("def edit(item, changes: ItemUpdate):\n    for key, value in changes.items():\n        print(key)\n", False),
])
def test_mass_assignment_python(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(FASTAPI, **{"app/routes.py": code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) is fires


@pytest.mark.parametrize("model,line,fires", [
    ("<?php\nclass Post extends Model {\n    protected $guarded = [];\n}\n", "Post::create($request->all());", True),
    (None, "Post::create($request->all());", True),
    ("<?php\nclass Post extends Model {\n    protected $fillable = ['name', 'role'];\n}\n",
     "Post::create($request->all());", True),
    ("<?php\nclass Post extends Model {\n    protected $fillable = ['title', 'body'];\n}\n",
     "Post::create($request->all());", False),
    ("<?php\nclass Post extends Model {\n}\n", "Post::create($request->all());", False),
    ("<?php\nclass Post extends Model {\n    protected $fillable = ['title'];\n}\n",
     "$post->forceFill($request->all())->save();", True),
    ("<?php\nclass Post extends Model {\n    protected $guarded = [];\n}\n", "Post::create($request->validated());", False),
])
def test_mass_assignment_laravel(tmp_path, write_tree, scan_rules, model, line, fires):
    files = dict(LARAVEL, **{"app/Http/Controllers/PostController.php":
                             "<?php\nclass PostController extends Controller {\n    public function store(Request $request) {\n"
                             "        " + line + "\n    }\n}\n"})
    if model:
        files["app/Models/Post.php"] = model
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) is fires


def test_laravel_unguard_makes_models_unsafe(tmp_path, write_tree, scan_rules):
    files = dict(LARAVEL, **{
        "app/Providers/AppServiceProvider.php": "<?php\npublic function boot() { Model::unguard(); }\n",
        "app/Models/Post.php": "<?php\nclass Post extends Model {\n}\n",
        "app/Http/Controllers/PostController.php": "<?php\nPost::create($request->all());\n"})
    assert len(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) == 1


SER = "class NoteSerializer(serializers.ModelSerializer):\n    class Meta:\n        model = Note\n%s"


@pytest.mark.parametrize("code,expected", [
    (SER % "        fields = '__all__'\n", ["medium"]),
    (SER % "        fields = \"__all__\"\n        read_only_fields = ['owner']\n", ["low"]),
    ("class NoteForm(forms.ModelForm):\n    class Meta:\n        model = Note\n        fields = '__all__'\n", ["medium"]),
    (SER % "        fields = ['title', 'body']\n", []),
    ("class NoteFilter(django_filters.FilterSet):\n    class Meta:\n        model = Note\n        fields = '__all__'\n", []),
])
def test_serializer_all_fields(tmp_path, write_tree, scan_rules, code, expected):
    files = dict(DJANGO, **{"notes/serializers.py": code})
    got = _found(tmp_path, write_tree, scan_rules, "data-serializer-all-fields", files)
    assert [f.severity for f in got] == expected


# --- password hashing and JWTs -----------------------------------------------------------------------------

@pytest.mark.parametrize("path,code,fires", [
    ("lib/auth.ts", "const hash = crypto.createHash('sha256').update(password).digest('hex')\n", True),
    ("lib/auth.ts", "const hash = crypto\n  .createHash('md5')\n  .update(password)\n  .digest('hex')\n", True),
    ("app/auth.py", "stored = hashlib.md5(password.encode()).hexdigest()\n", True),
    ("app/User.php", "<?php\n$hash = md5($password);\n", True),
    ("lib/auth.ts", "const h = crypto.createHash('sha256').update(token).digest('hex')\n", False),
    ("lib/auth.ts", "const hash = await bcrypt.hash(password, 12)\n", False),
    ("app/auth.py", "digest = hashlib.sha256(reset_token.encode()).hexdigest()\n", False),
    ("app/auth.py", "h = hashlib.sha1(password.encode()).hexdigest().upper()\n"
                    "requests.get('https://api.pwnedpasswords.com/range/' + h[:5])\n", False),
    ("app/auth.py", "key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)\n", False),
])
def test_weak_password_hash(tmp_path, write_tree, scan_rules, path, code, fires):
    files = dict(NEXT_PKG, **{path: code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-weak-password-hash", files)) is fires


@pytest.mark.parametrize("path,code,fires", [
    ("app/deps.py", "claims = jwt.decode(token, options={\"verify_signature\": False})\n", True),
    ("app/deps.py", "claims = jwt.decode(token, key, algorithms=['none'])\n", True),
    ("routes/admin.js", "const jwt = require('jsonwebtoken')\nrouter.get('/admin', (req, res) => {\n"
                        "  const payload = jwt.decode(req.headers.authorization)\n})\n", True),
    ("middleware.ts", "import { jwtDecode } from 'jwt-decode'\nexport function middleware(req) {\n"
                      "  const c = jwtDecode(req.cookies.get('t').value)\n}\n", True),
    ("routes/admin.js", "const jwt = require('jsonwebtoken')\nrouter.get('/admin', (req, res) => {\n"
                        "  const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] })\n"
                        "  const header = jwt.decode(token, { complete: true })\n})\n", False),
    ("components/Timer.tsx", "'use client'\nimport { jwtDecode } from 'jwt-decode'\nconst exp = jwtDecode(t).exp\n", False),
    ("app/deps.py", "claims = jwt.decode(token, settings.secret, algorithms=[\"HS256\"])\n", False),
])
def test_jwt_not_verified(tmp_path, write_tree, scan_rules, path, code, fires):
    files = dict(NEXT_PKG, **{path: code, "requirements.txt": "pyjwt\n"})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-jwt-not-verified", files)) is fires


# --- Supabase: dumped schemas, dynamic DO blocks, shared tables -----------------------------------------

DUMPED_FN = ('CREATE OR REPLACE FUNCTION "public"."cleanup_notes"() RETURNS "trigger"\n'
             '    LANGUAGE "plpgsql" SECURITY DEFINER\n    SET "search_path" TO \'\'\n'
             '    AS $$\nbegin\n  delete from public.notes where id = old.id;\n  return old;\nend;\n$$;\n')


@pytest.mark.parametrize("rule", ["data-supabase-definer-search-path", "data-supabase-definer-exposed"])
def test_dumped_schema_quoted_keywords(tmp_path, write_tree, scan_rules, rule):
    assert _found(tmp_path, write_tree, scan_rules, rule, _sql(DUMPED_FN)) == []


OPEN_TODOS = "create policy \"open\" on public.todos for all using (true);\n"


@pytest.mark.parametrize("extra,count", [
    ("do $$ declare t text; begin foreach t in array array['todos','notes'] loop "
     "execute format('drop policy if exists \"open\" on public.%I', t); end loop; end $$;\n", 0),
    ("do $$ declare t text; begin foreach t in array array['notes'] loop "
     "execute format('drop policy if exists \"open\" on public.%I', t); end loop; end $$;\n", 1),
    ("do $$ declare t text; begin foreach t in array array['notes','tasks'] loop "
     "execute format('create policy \"shared\" on public.%I for delete using (true)', t); end loop; end $$;\n", 2),
])
def test_policy_changes_in_do_block_loops(tmp_path, write_tree, scan_rules, extra, count):
    files = _sql(OPEN_TODOS, extra={"supabase/migrations/20240102000000_loop.sql": extra})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", files)
    assert len(got) == count
    loop = [f for f in got if f.file.endswith("_loop.sql")]
    # one EXECUTE line creates a policy per table; the finding on that line names every table
    assert all("public.notes" in f.message and "public.tasks" in f.message for f in loop)


SHARED = "".join("create policy \"edit\" on public.%s for update to authenticated using (true) with check (true);\n" % t
                 for t in ("companies", "contacts", "deals"))


@pytest.mark.parametrize("config,severity", [
    ("[auth]\nenable_signup = true\n", "high"),
    ("[auth]\nenable_signup = false\n", "low"),
])
def test_team_shared_tables_reported_once(tmp_path, write_tree, scan_rules, config, severity):
    files = _sql(SHARED, extra={"supabase/config.toml": config})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", files)
    assert [f.severity for f in got] == [severity]
    assert "3 tables" in got[0].message and "sign-ups" in got[0].message


def test_null_owner_branch_opens_rows(tmp_path, write_tree, scan_rules):
    sql = ("create policy \"ins\" on public.notes for insert with check (user_id is null or auth.uid() = user_id);\n"
           "create policy \"upd\" on public.notes for update using (user_id is null or auth.uid() = user_id);\n")
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql))
    assert [f.severity for f in got] == ["high"] and "user_id is NULL" in got[0].message


def test_owner_only_policy_without_null_branch_is_fine(tmp_path, write_tree, scan_rules):
    sql = "create policy \"own\" on public.notes for all using (auth.uid() = user_id) with check (auth.uid() = user_id);\n"
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql)) == []


def test_public_business_address_is_not_private(tmp_path, write_tree, scan_rules):
    sql = ("create table public.shops (id uuid primary key, name text, address text);\n"
           "create policy \"read\" on public.shops for select using (true);\n")
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-policy-allows-all", _sql(sql)) == []


# --- Supabase: definer function grants and severity -----------------------------------------------------

LOOKUP = ("create function public.lookup_email(p_name text) returns text language sql stable security definer "
          "set search_path = '' as $$ select email from public.profiles where name = p_name limit 1; $$;\n")


@pytest.mark.parametrize("sql,severity,text", [
    (LOOKUP + "revoke execute on function public.lookup_email(text) from authenticated;\n"
              "grant execute on function public.lookup_email(text) to anon;\n", "high", "by anon"),
    (WIPE + "revoke execute on function public.wipe_notes() from anon, authenticated;\n", "high", "PUBLIC still"),
    (WIPE + "grant execute on function public.wipe_notes() to service_role;\n", "high", "GRANT TO service_role"),
    ("create function public.get_token(p uuid) returns text language sql security definer set search_path = '' "
     "as $$ select decrypted_secret from vault.decrypted_secrets where name = p::text; $$;\n", "critical", "Vault"),
])
def test_definer_exposed_grants_and_severity(tmp_path, write_tree, scan_rules, sql, severity, text):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(sql))
    assert [f.severity for f in got] == [severity] and text in got[0].message


def test_definer_helpers_grouped_low(tmp_path, write_tree, scan_rules):
    helper = ("create function public.%s(_uid uuid) returns boolean language sql stable security definer "
              "set search_path = '' as $$ select exists (select 1 from public.user_roles where user_id = _uid); $$;\n")
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed",
                 _sql(helper % "has_role" + helper % "is_member"))
    assert [f.severity for f in got] == ["low"] and "2 read-only" in got[0].message


GUARDED = ("create function public.is_platform_admin() returns boolean language sql stable security definer "
           "set search_path = '' as $$ select exists (select 1 from public.admins where user_id = auth.uid()); $$;\n"
           "create function public.list_tenants() returns setof public.tenants language plpgsql security definer "
           "set search_path = '' as $$\nbegin\n  if not public.is_platform_admin() then raise exception 'no'; end if;\n"
           "  return query select * from public.tenants;\nend;\n$$;\n")
FAIL_OPEN = ("create function public.assert_role() returns void language plpgsql stable security definer "
             "set search_path = '' as $$\nbegin\n  if auth.uid() is not null and not public.has_role(auth.uid(), 'admin') "
             "then raise exception 'denied'; end if;\nend;\n$$;\n"
             "create function public.replace_entry(_id uuid) returns void language plpgsql security definer "
             "set search_path = '' as $$\nbegin\n  perform public.assert_role();\n"
             "  delete from public.entries where id = _id;\nend;\n$$;\n"
             "grant execute on function public.replace_entry(uuid) to authenticated;\n")


def test_definer_guard_helper_counts_as_caller_check(tmp_path, write_tree, scan_rules):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(GUARDED)) == []
    sql = WIPE.replace("as $$ delete", "as $$ select public.require_admin(); delete")
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(sql)) == []


def test_definer_fail_open_guard(tmp_path, write_tree, scan_rules):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(FAIL_OPEN))
    assert [(f.severity, "no session skips" in f.message) for f in got] == [("high", True), ("high", True)]
    locked = FAIL_OPEN + "".join("revoke execute on function public.%s from public, anon;\n" % f
                                 for f in ("assert_role()", "replace_entry(uuid)"))
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(locked)) == []


def test_public_form_rpc_granted_to_anon_is_low(tmp_path, write_tree, scan_rules):
    sql = ("create function public.submit_guest_message(_body text) returns uuid language plpgsql security definer "
           "set search_path = '' as $$\nbegin\n  insert into public.messages(body) values (_body);\n  return null;\nend;\n$$;\n"
           "revoke all on function public.submit_guest_message(text) from public;\n"
           "grant execute on function public.submit_guest_message(text) to anon, authenticated;\n")
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-definer-exposed", _sql(sql))
    assert [f.severity for f in got] == ["low"]


# --- Supabase: own-row privileged columns, seeded users, admin email, metadata history --------------------

PROFILES_PRIV = ("create table public.profiles (id uuid primary key, bio text, is_verified boolean default false);\n"
                 "alter table public.profiles enable row level security;\n"
                 "create policy \"upd\" on public.profiles for update to authenticated using (auth.uid() = id) "
                 "with check (auth.uid() = id);\n")


def test_own_row_privileged_column_fires(tmp_path, write_tree, scan_rules):
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-own-row-privileged", _sql(PROFILES_PRIV))
    assert len(got) == 1 and "is_verified" in got[0].message


@pytest.mark.parametrize("sql", [
    PROFILES_PRIV + "revoke update on public.profiles from authenticated;\n"
                    "grant update (bio) on public.profiles to authenticated;\n",
    PROFILES_PRIV + "create function public.keep_flag() returns trigger language plpgsql as $$\nbegin\n"
                    "  new.is_verified := old.is_verified;\n  return new;\nend;\n$$;\n"
                    "create trigger keep_flag before update on public.profiles for each row "
                    "execute function public.keep_flag();\n",
    "create table public.chat_messages (id uuid, user_id uuid, role text, content text);\n"
    "create policy \"own\" on public.chat_messages for all using (auth.uid() = user_id);\n",
])
def test_own_row_privileged_column_safe(tmp_path, write_tree, scan_rules, sql):
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-own-row-privileged", _sql(sql)) == []


SEED_USERS = ("insert into auth.users (id, email, encrypted_password, email_confirmed_at)\n"
              "values ('00000000-0000-0000-0000-000000000001', 'demo@example.com', crypt('demo-pass', gen_salt('bf')), now());\n")


def test_seeded_auth_users_in_migration(tmp_path, write_tree, scan_rules):
    got = _found(tmp_path / "a", write_tree, scan_rules, "data-supabase-seeded-auth-users", _sql(SEED_USERS))
    assert len(got) == 1 and "fixed password" in got[0].message
    for name in ("supabase/seed.sql", "supabase/migrations/20240101000000_seed_demo.sql"):
        assert _found(tmp_path / name.replace("/", "_"), write_tree, scan_rules, "data-supabase-seeded-auth-users",
                      _sql(SEED_USERS, name=name)) == []


def test_admin_by_email_policy(tmp_path, write_tree, scan_rules):
    sql = ("create policy \"owner deletes\" on public.orders for delete to authenticated\n"
           "  using (lower(coalesce(auth.jwt() ->> 'email', '')) = 'owner@example.com');\n")
    assert len(_found(tmp_path, write_tree, scan_rules, "data-supabase-admin-by-email", _sql(sql))) == 1
    safe = "create policy \"a\" on public.orders for delete using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');\n"
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-admin-by-email", _sql(safe)) == []


META_FN = ("create or replace function public.handle_new_user() returns trigger language plpgsql security definer "
           "set search_path = '' as $$\nbegin\n  insert into public.profiles (id, role)\n"
           "  values (new.id, %s);\n  return new;\nend;\n$$;\n")


def test_user_metadata_only_live_function_definition(tmp_path, write_tree, scan_rules):
    old = META_FN % "new.raw_user_meta_data->>'role'"
    files = _sql(old, extra={"supabase/migrations/20240102000000_fix.sql": META_FN % "'member'"})
    assert _found(tmp_path / "fixed", write_tree, scan_rules, "data-supabase-user-metadata-authz", files) == []
    files = _sql(old, extra={"supabase/migrations/20240102000000_again.sql": old})
    got = _found(tmp_path / "again", write_tree, scan_rules, "data-supabase-user-metadata-authz", files)
    assert [f.file.rsplit("/", 1)[-1] for f in got] == ["20240102000000_again.sql"]


def test_user_metadata_backfill_is_low(tmp_path, write_tree, scan_rules):
    sql = "update public.profiles p set role = u.raw_user_meta_data->>'role' from auth.users u where u.id = p.id;\n"
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-user-metadata-authz", _sql(sql))
    assert [f.severity for f in got] == ["low"]


# --- Supabase: client and server code ---------------------------------------------------------------------

def test_service_key_prefix_check_is_not_a_key(tmp_path, write_tree, scan_rules):
    files = dict(VITE_PKG, **{"src/integrations/supabase/client.ts":
                              "function isNewKey(value: string) {\n"
                              "  return value.startsWith('sb_publishable_') || value.startsWith('sb_secret_');\n}\n"})
    assert _found(tmp_path, write_tree, scan_rules, "data-supabase-service-key-client", files) == []


@pytest.mark.parametrize("path,text,expected", [
    ("src/routes/_authenticated/route.tsx",
     "export const Route = createFileRoute('/_authenticated')({ ssr: false,\n"
     "  beforeLoad: async () => { await supabase.auth.getSession() } })\n", []),
    ("middleware.ts", "export async function middleware(req) {\n  const supabase = createMiddlewareClient({ req, res })\n"
                      "  await supabase.auth.getSession()\n  return res\n}\n", ["low"]),
])
def test_getsession_client_route_and_refresh_idiom(tmp_path, write_tree, scan_rules, path, text, expected):
    files = dict(NEXT_PKG, **{path: text})
    got = _found(tmp_path, write_tree, scan_rules, "data-supabase-getsession-server", files)
    assert [f.severity for f in got] == expected


# --- Firebase: OR branches and a fixed admin email ---------------------------------------------------------

def test_firebase_or_with_any_auth_branch(tmp_path, write_tree, scan_rules):
    rules = _fs("    function isSignedIn() { return request.auth != null; }\n"
                "    match /users/{userId} {\n      allow read: if isAdmin() || isSignedIn();\n    }\n")
    got = _found(tmp_path, write_tree, scan_rules, "data-firebase-any-auth", {"firestore.rules": rules})
    assert len(got) == 1


def test_firebase_admin_by_fixed_email(tmp_path, write_tree, scan_rules):
    fn = "    function isOwner() {\n      return request.auth != null && request.auth.token.email == 'owner@example.com'%s;\n    }\n"
    body = "    match /orders/{id} {\n      allow write: if isOwner();\n    }\n"
    got = _found(tmp_path, write_tree, scan_rules, "data-firebase-role-field", {"firestore.rules": _fs(fn % "" + body)})
    assert [f.severity for f in got] == ["high"]
    verified = _fs(fn % " && request.auth.token.email_verified == true" + body)
    assert _found(tmp_path, write_tree, scan_rules, "data-firebase-role-field", {"firestore.rules": verified}) == []


# --- IDOR: wrappers, check-then-act, signed callers ----------------------------------------------------------

ADMIN_WRAPPED = ("import { withAdmin } from '@/lib/auth'\n\n"
                 "export const PATCH = withAdmin(\n  async ({ req, params }) => {\n    const { itemId } = params\n"
                 "    const item = await prisma.item.findUnique({\n      where: { id: itemId },\n    })\n"
                 "    return Response.json(item)\n  },\n)\n")
WORKSPACE_SCOPED = ("export const PATCH = withWorkspace(\n  async ({ req, params, workspace }) => {\n"
                    "    const { id } = params\n    const tag = await prisma.tag.findFirst({\n"
                    "      where: { id, projectId: workspace.id },\n    })\n"
                    "    if (!tag) throw new Error('not found')\n"
                    "    await prisma.tag.update({ where: { id }, data: { name: 'x' } })\n  },\n)\n")
HELPER_SCOPED = ("export const DELETE = withPartner(async ({ partner, params }) => {\n  const { hookId } = params\n"
                 "  await getHookOrThrow({ hookId, partnerId: partner.id })\n"
                 "  await prisma.hook.delete({ where: { id: hookId } })\n})\n")
COMPARED = ("export const GET = withWorkspace(async ({ workspace, searchParams }) => {\n"
            "  const programId = getProgramId(workspace)\n  const { groupId } = schema.parse(searchParams)\n"
            "  const group = await prisma.group.findUnique({ where: { id: groupId } })\n"
            "  if (!group || group.programId !== programId) throw new Error('not found')\n})\n")
SIGNED = ("export async function POST(req) {\n  await verifyQstashSignature({ req })\n"
          "  const { linkId } = await req.json()\n  return Response.json(await prisma.link.findUnique({ where: { id: linkId } }))\n}\n")
TRPC_ADMIN = ("export const deleteThing = adminProcedure\n  .input(schema)\n  .mutation(async ({ input }) => {\n"
              "    await prisma.thing.delete({ where: { id: input.id } })\n  })\n")
SAFE_ACTION_CTX = ("'use server'\nexport const updatePrefs = actionClient\n  .action(\n"
                   "    async ({ ctx: { accountId }, parsedInput: { layout } }) => {\n"
                   "      await prisma.emailAccount.update({\n        where: { id: accountId },\n"
                   "        data: { layout },\n      })\n    },\n  )\n")
PRIVATE_HELPER = ("'use server'\nasync function loadAccount(accountId: string) {\n"
                  "  return prisma.account.findUnique({ where: { id: accountId } })\n}\n")
OWNS_CHECK = ("export default async function Page({ params }) {\n  const { accountId } = await params\n"
              "  await checkUserOwnsAccount({ accountId })\n"
              "  const account = await prisma.account.findUnique({ where: { id: accountId } })\n}\n")
USER_SCOPED_EDGE = ("Deno.serve(async (req) => {\n  const supabase = createClient(Deno.env.get('SUPABASE_URL')!,\n"
                    "    Deno.env.get('SUPABASE_ANON_KEY')!, { global: { headers: { Authorization: auth } } })\n"
                    "  const admin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)\n"
                    "  const body = await req.json()\n"
                    "  const { data } = await supabase\n    .from('proposals')\n    .select('*')\n"
                    "    .eq('id', body.proposalId)\n    .maybeSingle()\n})\n")


@pytest.mark.parametrize("path,code", [
    ("app/api/admin/items/[itemId]/route.ts", ADMIN_WRAPPED),
    ("app/api/tags/[id]/route.ts", WORKSPACE_SCOPED),
    ("app/api/hooks/[hookId]/route.ts", HELPER_SCOPED),
    ("app/api/groups/count/route.ts", COMPARED),
    ("app/api/cron/links/route.ts", SIGNED),
    ("server/admin-router/delete-thing.ts", TRPC_ADMIN),
    ("utils/actions/prefs.ts", SAFE_ACTION_CTX),
    ("utils/actions/accounts.ts", PRIVATE_HELPER),
    ("app/(app)/[accountId]/page.tsx", OWNS_CHECK),
    ("supabase/functions/reparse/index.ts", USER_SCOPED_EDGE),
])
def test_idor_js_wrappers_and_scoping_safe(tmp_path, write_tree, scan_rules, path, code):
    files = dict(NEXT_PKG, **{path: code})
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


@pytest.mark.parametrize("path,code,line", [
    # a user wrapper with no scoping is still reported
    ("app/api/items/[id]/route.ts", "export const DELETE = withSession(async ({ params }) => {\n"
                                    "  await prisma.item.delete({ where: { id: params.id } })\n})\n", 2),
    # two hops from request.json()
    ("app/api/chat/custom/route.ts", "export async function POST(request: Request) {\n"
                                     "  const json = await request.json()\n  const { modelId } = json as {\n"
                                     "    modelId: string\n  }\n"
                                     "  const supabaseAdmin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"
                                     "  const { data } = await supabaseAdmin.from('models').select('*').eq('id', modelId).single()\n}\n", 7),
    # users.length is not an owner check
    ("pages/api/profile/[id].js", "export default async function handler(req, res) {\n  const { id } = req.query\n"
                                  "  const users = await runQuery(`SELECT id, email FROM users WHERE id = ${id}`)\n"
                                  "  if (!users || users.length === 0) return res.status(404).json({})\n}\n", 3),
    # Sequelize find() with a quoted id key
    ("routes/users.js", "module.exports.edit = function (req, res) {\n"
                        "  db.User.find({ where: { 'id': req.body.id } }).then(user => user.save())\n}\n", 2),
])
def test_idor_js_more_shapes_fire(tmp_path, write_tree, scan_rules, path, code, line):
    files = dict(NEXT_PKG, **{path: code})
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert [f.line for f in got] == [line]


@pytest.mark.parametrize("path,code", [
    ("app/api/profile/route.ts", "export async function GET(request: Request) {\n"
                                 "  const userId = new URL(request.url).searchParams.get('user_id')\n"
                                 "  const { data } = await supabaseAdmin.from('profiles').select('id, email, phone')"
                                 ".eq('user_id', userId).maybeSingle()\n}\n"),
    ("app/api/orders/route.ts", "export async function GET(request: Request) {\n  const session = await auth()\n"
                                "  const userId = new URL(request.url).searchParams.get('userId')\n"
                                "  return Response.json(await prisma.order.findMany({ where: { userId: userId! } }))\n}\n"),
    ("routes/alloc.js", "app.get('/allocations/:userId', async (req, res) => {\n  const { userId } = req.params\n"
                        "  res.json(await db.collection('allocations').find({ userId: userId }).toArray())\n})\n"),
])
def test_idor_owner_filter_from_request(tmp_path, write_tree, scan_rules, path, code):
    files = dict(NEXT_PKG, **{path: code})
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert len(got) == 1 and "user id taken from the request" in got[0].message


@pytest.mark.parametrize("code", [
    "export async function GET(request: Request) {\n  const userId = new URL(request.url).searchParams.get('userId')\n"
    "  return Response.json(await prisma.post.findMany({ where: { authorId: userId, published: true } }))\n}\n",
    "export async function GET() {\n  const { userId } = await verifySession()\n"
    "  return Response.json(await prisma.order.findMany({ where: { userId } }))\n}\n",
    "export async function GET(request: Request) {\n  const userId = new URL(request.url).searchParams.get('user_id')\n"
    "  const { data } = await supabaseAdmin.from('profiles').select('username').eq('user_id', userId).single()\n}\n",
])
def test_idor_owner_filter_safe(tmp_path, write_tree, scan_rules, code):
    files = dict(NEXT_PKG, **{"app/api/x/route.ts": code})
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


def test_idor_public_catalog_table_read(tmp_path, write_tree, scan_rules):
    files = dict(SB, **{
        "supabase/migrations/20240101000000_init.sql":
            "create policy \"Restaurants are public\" on public.restaurants for select using (true);\n",
        "supabase/functions/create-order/index.ts":
            "const supabaseAdmin = createClient(url, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)\n"
            "Deno.serve(async (req) => {\n  const { restaurantId } = await req.json()\n"
            "  const { data } = await supabaseAdmin.from('restaurants').select('price').eq('id', restaurantId).single()\n})\n",
        "package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}})})
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


@pytest.mark.parametrize("files,expected", [
    # Flask permission helper
    (dict(FASTAPI, **{"app/views.py": "@bp.route('/move/<int:fid>', methods=['POST'])\ndef move(fid):\n"
                                      "    forum = Forum.query.get_or_404(fid)\n"
                                      "    if not Permission(IsModeratorInForum(forum=forum)):\n        abort(404)\n"
                                      "    db.session.commit()\n"}), []),
    # read-only public profile
    (dict(FASTAPI, **{"app/api/users.py": "@bp.route('/users/<int:id>', methods=['GET'])\n@token_auth.login_required\n"
                                          "def get_user(id):\n    return db.get_or_404(User, id).to_dict()\n"}), []),
    # user = User.query... is not an owner check
    (dict(FASTAPI, **{"app.py": "@app.route('/users/<int:user_id>', methods=['DELETE'])\ndef delete_user(user_id):\n"
                                "    user = User.query.get_or_404(user_id)\n    db.session.delete(user)\n"
                                "    db.session.commit()\n"}), [3]),
    # id from validated serializer data
    (dict(DJANGO, **{"files/apis.py": "class FinishApi(APIView):\n    def post(self, request):\n"
                                      "        serializer = self.InputSerializer(data=request.data)\n"
                                      "        serializer.is_valid(raise_exception=True)\n"
                                      "        file_id = serializer.validated_data['file_id']\n"
                                      "        file = get_object_or_404(File, id=file_id)\n        return Response()\n"}), [6]),
    # two hops from request.json
    (dict(FASTAPI, **{"app.py": "@app.route('/customer', methods=['POST'])\ndef customer():\n"
                                "    content = request.json\n    customer_id = content['id']\n"
                                "    record = Customer.query.get(customer_id)\n    return jsonify(record.to_dict())\n"}), [5]),
])
def test_idor_python_more_shapes(tmp_path, write_tree, scan_rules, files, expected):
    got = _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files)
    assert [f.line for f in got] == expected


MODEL_BINDER = ("<?php\nnamespace App\\Models;\nclass Account extends Model {\n"
                "    public static function routeBinder(string $value): self {\n"
                "        return auth()->user()->accounts()->findOrFail((int) $value);\n    }\n}\n")


@pytest.mark.parametrize("body,extra", [
    ("    public function destroy(Account $account)\n    {\n        $account->delete();\n    }\n",
     {"app/Models/Account.php": MODEL_BINDER}),
    ("    public function destroy(string $id, Authenticatable $user)\n    {\n"
     "        $this->presets->removePresetForUser($user, $id);\n    }\n", {}),
    ("    public function show(?Carbon $start, RecurringRepositoryInterface $repo)\n    {\n        return view('x');\n    }\n",
     {}),
    ("    public function delete(User $user)\n    {\n        return view('admin.delete', compact('user'));\n    }\n",
     {"routes/web.php": "<?php\nRoute::group(['middleware' => 'admin', 'prefix' => 'settings'], static function () {\n"
                        "    Route::get('users/delete/{user}', ['uses' => 'OrderController@delete']);\n});\n"}),
])
def test_idor_laravel_bound_params_safe(tmp_path, write_tree, scan_rules, body, extra):
    files = dict(LARAVEL, **{"app/Http/Controllers/OrderController.php": _ctrl(body)})
    files.update(extra)
    assert _found(tmp_path, write_tree, scan_rules, "data-idor-by-id", files) == []


# --- mass assignment: privileged fields picked from the request ---------------------------------------------

@pytest.mark.parametrize("code,fires", [
    ("export async function POST(req: Request) {\n  const { userId, role } = await req.json()\n"
     "  await supabaseAdmin.from('profiles').update({ role }).eq('id', userId)\n}\n", True),
    ("export async function POST(req: Request) {\n  const body = await req.json()\n  const role = body.role as string\n"
     "  await supabaseAdmin\n    .from('profiles')\n    .update({ role })\n    .eq('user_id', body.user_id)\n}\n", True),
    ("export async function POST(req: Request) {\n  const session = await auth()\n"
     "  if (session.user.role !== 'admin') return new Response(null, { status: 403 })\n"
     "  const { userId, role } = await req.json()\n"
     "  await supabaseAdmin.from('profiles').update({ role }).eq('id', userId)\n}\n", False),
    ("export async function POST(req: Request) {\n  const { role, content } = await req.json()\n"
     "  await supabase.from('messages').insert({ role, content })\n}\n", False),
    ("export async function POST(req: Request) {\n  const { role } = await req.json()\n"
     "  await prisma.emailAccount.update({ where: { id }, data: { role } })\n}\n", False),
])
def test_mass_assignment_privileged_field(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(NEXT_PKG, **{"app/api/promote/route.ts": code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) is fires


GROUPS_VIEW = ("%sdef change_group(request):\n    data = request.POST.dict()\n    level = data['level'].strip()\n"
               "    grp = Group.objects.get(name=level)\n    member = User.objects.get(pk=data['user'])\n"
               "    member.groups.add(grp)\n    member.save()\n")


@pytest.mark.parametrize("code,fires", [
    (GROUPS_VIEW % "", True),
    ("def promote(request):\n    user = request.user\n    user.is_staff = request.POST.get('is_staff') == 'on'\n"
     "    user.save()\n", True),
    ("def edit(request, pk):\n    profile = Profile.objects.get(user=request.user)\n"
     "    setattr(profile, 'role', request.data['role'])\n    profile.save()\n", True),
    (GROUPS_VIEW % "@staff_member_required\n", False),
    ("def promote(request):\n    if not request.user.is_superuser:\n        raise PermissionDenied\n"
     "    user = User.objects.get(pk=request.POST['id'])\n    user.is_staff = request.POST.get('is_staff') == 'on'\n", False),
    ("def signup(request):\n    user = User(username=request.POST['username'])\n    user.role = 'member'\n"
     "    user.groups.add(Group.objects.get(name='members'))\n", False),
])
def test_mass_assignment_python_privileged(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(DJANGO, **{"app/views.py": code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-mass-assignment", files)) is fires


# --- Django forms, password hashers, JWT id_token -------------------------------------------------------------

@pytest.mark.parametrize("code,expected", [
    ("class UserForm(forms.ModelForm):\n    class Meta:\n        model = User\n"
     "        exclude = ['groups', 'user_permissions', 'last_login']\n", ["high"]),
    ("class UserForm(forms.ModelForm):\n    class Meta:\n        model = User\n"
     "        exclude = ['is_superuser', 'is_staff', 'groups']\n", []),
    ("class NoteForm(forms.ModelForm):\n    class Meta:\n        model = Note\n        exclude = ['owner']\n", []),
])
def test_user_form_exclude(tmp_path, write_tree, scan_rules, code, expected):
    files = dict(DJANGO, **{"app/forms.py": code})
    got = _found(tmp_path, write_tree, scan_rules, "data-serializer-all-fields", files)
    assert [f.severity for f in got] == expected


@pytest.mark.parametrize("path,code,fires", [
    ("app/settings.py", "PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']\n", True),
    ("app/settings.py", "if sys.argv[1:2] == ['test']:\n"
                        "    PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']\n", False),
    ("app/settings/test.py", "PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']\n", False),
    ("app/User.php", "<?php\n$fingerprint = hash('sha256', isset($user['password']) ? $user['password'] : '');\n", False),
    ("lib/password.js", "const bcrypt = require('bcryptjs')\nasync function hash(password) {\n"
                        "  password = crypto.createHash('sha512').update(password).digest('hex')\n"
                        "  return bcrypt.hash(password, 12)\n}\n", False),
])
def test_weak_password_hash_more(tmp_path, write_tree, scan_rules, path, code, fires):
    files = dict(DJANGO, **{path: code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-weak-password-hash", files)) is fires


def test_jwt_id_token_from_token_endpoint_is_low(tmp_path, write_tree, scan_rules):
    code = ("TOKEN_URL = 'https://oauth2.example.com/token'\n"
            "def decode_id_token(id_token):\n    return jwt.decode(jwt=id_token, options={\"verify_signature\": False})\n")
    files = dict(NEXT_PKG, **{"app/oauth.py": code, "requirements.txt": "pyjwt\n"})
    got = _found(tmp_path, write_tree, scan_rules, "data-jwt-not-verified", files)
    assert [f.severity for f in got] == ["low"]


@pytest.mark.parametrize("code,fires", [
    ("export const off = import.meta.env.VITE_DISABLE_EMAIL_PASSWORD_AUTHENTICATION === \"true\";\n", False),
    ("if (import.meta.env.VITE_ADMIN_PASSWORD === input) open()\n", True),
])
def test_client_password_env_flag(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(VITE_PKG, **{"src/auth/config.ts": code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-client-password-check", files)) is fires


# --- admin routes, cookies, bypasses, service-role functions --------------------------------------------------

@pytest.mark.parametrize("files,expected", [
    ({"app/api/admin/users/route.ts": "export async function GET() {\n  const session = await getSession()\n"
                                      "  if (!session) return new Response(null, { status: 401 })\n"
                                      "  return Response.json(await db.from('profiles').select('*'))\n}\n"}, ["high"]),
    ({"app/api/admin/users/route.ts": "export async function GET() {\n  const session = await getSession()\n"
                                      "  if (session?.user.role !== 'admin') return new Response(null, { status: 403 })\n"
                                      "  return Response.json([])\n}\n"}, []),
    ({"routes/app.js": "router.get('/admin/users', isAuthenticated, function (req, res) {\n  res.json([])\n})\n"
                       "router.get('/admin/stats', isAuthenticated, requireAdmin, stats.list)\n"}, ["high"]),
    ({"src/routes/admin.py": "".join("@bp.route('/%s')\n@admin_required\ndef %s():\n    return 'x'\n\n" % (n, n)
                                     for n in ("a", "b", "c", "d"))
                             + "@bp.route('/system_info')\ndef system_info():\n    return 'x'\n"}, ["medium"]),
])
def test_admin_route_no_role(tmp_path, write_tree, scan_rules, files, expected):
    files = dict(NEXT_PKG, **files)
    got = _found(tmp_path, write_tree, scan_rules, "data-admin-route-no-role", files)
    assert [f.severity for f in got] == expected


@pytest.mark.parametrize("path,code,fires", [
    ("bac.php", "<?php\n$cookie_id = intval($_COOKIE['user_id']);\nif ($id == $cookie_id) { show(); }\n", True),
    ("routes/admin.js", "router.get('/x', (req, res) => {\n  if (req.cookies.role === 'admin') res.json(all)\n})\n", True),
    ("routes/admin.js", "router.get('/x', (req, res) => {\n  if (req.signedCookies.role === 'admin') res.json(all)\n})\n",
     False),
    ("routes/login.js", "router.post('/login', (req, res) => {\n  res.cookie('role', user.role, { httpOnly: true })\n})\n",
     False),
])
def test_cookie_identity(tmp_path, write_tree, scan_rules, path, code, fires):
    files = dict(EXPRESS_PKG, **{path: code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-cookie-identity", files)) is fires


@pytest.mark.parametrize("code,fires", [
    ("Deno.serve(async (req) => {\n  const { phone, code } = await req.json()\n  let isApproved = false\n"
     "  if (phone === '9000000001' && code === '123456') {\n    isApproved = true\n  }\n})\n", True),
    ("Deno.serve(async (req) => {\n  const { error } = await verifyOtp(code)\n"
     "  if (error.code === '23505') return conflict()\n})\n", False),
])
def test_hardcoded_auth_bypass(tmp_path, write_tree, scan_rules, code, fires):
    files = dict(SB, **{"supabase/functions/verify-otp/index.ts": code})
    assert bool(_found(tmp_path, write_tree, scan_rules, "data-hardcoded-auth-bypass", files)) is fires


SVC_FN = ("Deno.serve(async (req) => {\n  const body = await req.json()\n"
          "  const supabase = createClient(Deno.env.get('SUPABASE_URL')!, Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!)\n"
          "  await supabase.from('inventory').update({ stock: body.stock }).eq('id', body.variantId)\n})\n")


@pytest.mark.parametrize("config,code,expected", [
    ("", SVC_FN, ["high"]),
    ("[functions.push-stock]\nverify_jwt = false\n", SVC_FN, ["critical"]),
    ("", SVC_FN.replace("  const body", "  const { data: { user } } = await supabase.auth.getUser(token)\n  const body"),
     []),
    ("", SVC_FN.replace("  const body", "  if (req.headers.get('x-cron-key') !== Deno.env.get('CRON_SECRET')) "
                                        "return new Response(null, { status: 403 })\n  const body"), []),
])
def test_service_role_no_caller_check(tmp_path, write_tree, scan_rules, config, code, expected):
    files = {"supabase/config.toml": "project_id = \"demo\"\n" + config,
             "supabase/functions/push-stock/index.ts": code,
             "package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}})}
    got = _found(tmp_path, write_tree, scan_rules, "data-service-role-no-caller-check", files)
    assert [f.severity for f in got] == expected


WITH_SB_FN = ("import { withSupabase } from 'npm:@supabase/server@^1'\n"
              "export default {\n  fetch: withSupabase<Database>(%s async (req, ctx) => {\n"
              "    const payload = await req.json()\n"
              "    await ctx.supabaseAdmin.from('embeddings').update({ v: 1 }).eq('id', payload.record.id)\n"
              "    return Response.json({ ok: true })\n  }),\n}\n")


@pytest.mark.parametrize("opts,expected", [
    ("{ auth: 'secret' },", []),
    ("{ auth: \"secret:cron\" },", []),
    ("{ auth: ['user', 'secret'] },", []),
    ("{ cors: false },", []),          # no auth key: defaults to 'user'
    ("", []),                          # handler only: defaults to 'user'
    ("{ auth: 'publishable' },", ["high"]),
    ("{ auth: 'none' },", ["high"]),
    ("{ auth: ['user', 'none'] },", ["high"]),
    ("{ auth: mode },", ["high"]),     # a mode in a variable proves nothing
])
def test_service_role_with_supabase_wrapper(tmp_path, write_tree, scan_rules, opts, expected):
    files = {"supabase/config.toml": "project_id = \"demo\"\n",
             "supabase/functions/generate-embedding/index.ts": WITH_SB_FN % opts,
             "package.json": json.dumps({"dependencies": {"@supabase/supabase-js": "2"}})}
    got = _found(tmp_path, write_tree, scan_rules, "data-service-role-no-caller-check", files)
    assert [f.severity for f in got] == expected


# --- rule metadata and references -----------------------------------------------------------------------------

def _slug(heading):
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path):
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^#{1,6}\s+(.*)$", line)
        if m:
            out.add(_slug(m.group(1)))
    return out


def test_rule_metadata():
    ids = [r.id for r in da.RULES]
    assert len(ids) == len(set(ids))
    for r in da.RULES:
        assert r.id.startswith("data-"), r.id
        assert r.why and r.fp_trap and r.message and r.klass, r.id
        assert r.severity in ("critical", "high", "medium", "low", "info"), r.id
        assert r.confidence in ("high", "medium", "low"), r.id
        assert "#" in r.fix_ref, r.id


def test_fix_refs_point_at_real_headings():
    anchors = {name: _anchors(path) for name, path in REFS.items()}
    for r in da.RULES:
        name, anchor = r.fix_ref.split("#", 1)
        assert name in anchors, r.fix_ref
        assert anchor in anchors[name], "%s: no heading for #%s in %s" % (r.id, anchor, name)


@pytest.mark.parametrize("name", sorted(REFS))
def test_reference_files_shape(name):
    text = REFS[name].read_text(encoding="utf-8")
    lines = text.rstrip("\n").split("\n")
    assert lines[-1].strip() == "LAST-VERIFIED: 2026-10-06"
    assert len(lines) <= 210, len(lines)
    assert chr(0x2014) not in text and chr(0x2013) not in text
    assert not any(0x2600 <= ord(c) <= 0x27BF or ord(c) >= 0x1F000 for c in text)


def test_every_rule_has_a_firing_test():
    src = open(__file__, encoding="utf-8").read()
    for r in da.RULES:
        assert '"%s"' % r.id in src, r.id
