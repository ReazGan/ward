"""Tests for _rules_injection.py: every rule fires on its vulnerable sample and
stays quiet on the safe variant next to it."""

from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

import _rules_injection as inj

REFS = Path(__file__).resolve().parent.parent / "skills"
RULE_IDS = [r.id for r in inj.RULES]
EM, EN = chr(0x2014), chr(0x2013)

PKG_NODE = '{"dependencies": {"express": "^4.19.0"}}'
PKG_MONGO = '{"dependencies": {"express": "^4.19.0", "mongoose": "^8.9.5"}}'
PKG_NEXT = '{"dependencies": {"next": "15.2.4", "react": "19.0.0", "react-dom": "19.0.0"}}'


def d(text: str) -> str:
    return textwrap.dedent(text).lstrip("\n")


def run(tmp_path, write_tree, scan_rules, files, rule, stacks="all"):
    write_tree(tmp_path, files)
    res = scan_rules(tmp_path, rule_ids=[rule], stacks=stacks)
    bad = [w for w in res.warnings if rule in str(w)]
    assert not bad, bad
    return [f for f in res.findings if f.rule == rule]


CASES = []


def case(rule, name, files, fires, severity=None):
    CASES.append(pytest.param(rule, files, fires, severity, id="%s-%s" % (rule, name)))


# --- sqli-prisma-raw-unsafe --------------------------------------------------

R = "sqli-prisma-raw-unsafe"
case(R, "template-from-body", {"package.json": PKG_NODE, "src/users.ts": d("""
    export async function find(req) {
      const { email } = req.body
      return prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`)
    }
""")}, True, "critical")
case(R, "variable-then-call", {"package.json": PKG_NODE, "src/a.ts": d("""
    async function run(id) {
      const sql = `DELETE FROM "Post" WHERE id = ${id}`
      await prisma.$executeRawUnsafe(sql)
    }
""")}, True, "high")
case(R, "concat", {"package.json": PKG_NODE, "src/a.ts": d("""
    const rows = await prisma.$queryRawUnsafe<User[]>('SELECT * FROM "User" WHERE name = ' + name)
""")}, True)
case(R, "tagged-template-is-safe", {"package.json": PKG_NODE, "src/a.ts": d("""
    const rows = await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${req.body.email}`
""")}, False)
case(R, "placeholders-are-safe", {"package.json": PKG_NODE, "src/a.ts": d("""
    const rows = await prisma.$queryRawUnsafe('SELECT * FROM "User" WHERE email = $1', req.body.email)
""")}, False)
case(R, "constant-table-is-safe", {"package.json": PKG_NODE, "src/a.ts": d("""
    const TABLE = '"User"'
    const rows = await prisma.$queryRawUnsafe(`SELECT * FROM ${TABLE} WHERE id = $1`, id)
""")}, False)
case(R, "prisma-sql-is-safe", {"package.json": PKG_NODE, "src/a.ts": d("""
    const q = Prisma.sql`SELECT * FROM "User" WHERE id = ${id}`
    const rows = await prisma.$queryRaw(q)
""")}, False)
case(R, "test-files-ignored", {"package.json": PKG_NODE, "src/__tests__/a.test.ts": d("""
    await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`)
""")}, False)

# --- sqli-js-string-query ----------------------------------------------------

R = "sqli-js-string-query"
case(R, "pg-template-body", {"package.json": PKG_NODE, "server/users.js": d("""
    app.post('/login', async (req, res) => {
      const { rows } = await pool.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
      res.json(rows)
    })
""")}, True, "critical")
case(R, "mysql-concat-params", {"package.json": PKG_NODE, "server/p.js": d("""
    connection.query("SELECT * FROM products WHERE id = " + req.params.id, function (err, rows) {})
""")}, True, "critical")
case(R, "order-by-with-params", {"package.json": PKG_NODE, "server/posts.js": d("""
    async function list(req, res) {
      const { sort, dir } = req.query
      const { rows } = await pool.query(
        `SELECT * FROM posts WHERE user_id = $1 ORDER BY ${sort} ${dir}`,
        [req.user.id]
      )
    }
""")}, True)
case(R, "appended-sqlite", {"package.json": PKG_NODE, "server/s.js": d("""
    function search(req) {
      const name = req.query.name
      let sql = 'SELECT * FROM items WHERE 1=1'
      if (name) sql += ` AND name = '${name}'`
      return db.all(sql)
    }
""")}, True, "critical")
case(R, "knex-raw-param", {"package.json": PKG_NODE, "server/k.js": d("""
    function byId(id) {
      return knex.raw(`select * from users where id = ${id}`)
    }
""")}, True, "high")
case(R, "sequelize-literal-request", {"package.json": PKG_NODE, "server/q.js": d("""
    const rows = await Post.findAll({ order: sequelize.literal(req.query.sort) })
""")}, True)
case(R, "order-fragment", {"package.json": PKG_NODE, "server/o.js": d("""
    function orderClause(req) {
      const clause = `ORDER BY ${req.query.sort}`
      return clause
    }
""")}, True)
case(R, "bare-query-helper", {"package.json": PKG_NODE, "lib/db.js": d("""
    export async function getUser(id) {
      const { rows } = await query(`SELECT * FROM users WHERE id = ${id}`)
      return rows[0]
    }
""")}, True)
case(R, "parameterized-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [req.params.id])
    const r2 = await pool.query(`SELECT * FROM users WHERE email = $1`, [req.body.email])
""")}, False)
case(R, "tagged-sql-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    const users = await sql`SELECT * FROM users WHERE id = ${req.params.id}`
    const r = await db.query(sql`SELECT * FROM users WHERE id = ${id}`)
""")}, False)
case(R, "placeholder-built-where-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    async function search(req) {
      const conditions = []
      const values = []
      if (req.query.name) {
        values.push(req.query.name)
        conditions.push(`name = $${values.length}`)
      }
      const where = conditions.length ? 'WHERE ' + conditions.join(' AND ') : ''
      return pool.query(`SELECT * FROM items ${where}`, values)
    }
""")}, False)
case(R, "allowlisted-sort-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    async function list(req) {
      const { sort } = req.query
      const col = ['name', 'created_at'].includes(sort) ? sort : 'created_at'
      const dir = req.query.dir === 'asc' ? 'ASC' : 'DESC'
      return pool.query(`SELECT * FROM posts ORDER BY ${col} ${dir}`)
    }
""")}, False)
case(R, "guarded-sort-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    async function list(req) {
      const sort = req.query.sort
      if (!SORTABLE.includes(sort)) throw new Error('bad sort')
      return pool.query(`SELECT * FROM posts ORDER BY ${sort}`)
    }
""")}, False)
case(R, "numbers-are-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    const limit = parseInt(req.query.limit) || 20
    const { rows } = await pool.query(`SELECT * FROM posts LIMIT ${limit} OFFSET ${Number(req.query.offset)}`)
""")}, False)
case(R, "non-sql-strings-are-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    const v = await cache.get(`user:${id}`)
    const r = await axios.get(`${API_URL}/users/${id}`)
    app.post('/hook', express.raw({ type: 'application/json' }), handler)
    const m = /select (\\w+) from/.exec(input)
""")}, False)
case(R, "knex-builder-is-safe", {"package.json": PKG_NODE, "server/a.js": d("""
    const user = await knex('users').where({ id: req.params.id }).first()
    const rows = await knex('users').whereRaw('LOWER(name) = ?', [req.query.name.toLowerCase()])
""")}, False)
case(R, "comment-is-ignored", {"package.json": PKG_NODE, "server/a.js": d("""
    // pool.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
    /* db.query("SELECT * FROM t WHERE id = " + req.params.id) */
""")}, False)
case(R, "ts-literal-union-column-is-safe", {"package.json": PKG_NODE, "src/counts.ts": d("""
    const bump = (id: string, field: 'wins' | 'losses', by = 1) =>
      db.prepare(`UPDATE scores SET ${field} = ${field} + ? WHERE id = ?`).run(by, id)
""")}, False)
case(R, "unknown-helper-call-is-not-judged", {"package.json": PKG_NODE, "server/a.js": d("""
    const rows = await db.query(`SELECT * FROM logs WHERE day = '${formatDate(new Date())}'`)
""")}, False)
case(R, "supabase-or-filter", {"package.json": PKG_NEXT, "app/search/route.ts": d("""
    export async function GET(request: Request) {
      const q = new URL(request.url).searchParams.get('q')
      const { data } = await supabase.from('posts').select().or(`title.ilike.%${q}%,body.ilike.%${q}%`)
    }
""")}, True, "high")
case(R, "supabase-or-constant-is-safe", {"package.json": PKG_NEXT, "lib/q.ts": d("""
    const { data } = await supabase.from('posts').select().or('status.eq.draft,status.eq.review')
""")}, False)

# --- sqli-python-string-query ------------------------------------------------

R = "sqli-python-string-query"
FLASK = {"requirements.txt": "flask==3.1.0\n"}
case(R, "fstring-from-request", dict(FLASK, **{"app.py": d("""
    @app.route("/user")
    def user():
        name = request.args.get("name")
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
""")}), True, "critical")
case(R, "percent-operator", dict(FLASK, **{"db.py": d("""
    def get(user_id):
        cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
""")}), True, "high")
case(R, "format-call", dict(FLASK, **{"db.py": d("""
    def delete(item_id):
        cur.execute("DELETE FROM items WHERE id = {}".format(item_id))
""")}), True)
case(R, "traced-variable", dict(FLASK, **{"db.py": d("""
    def find(x):
        query = f"SELECT * FROM t WHERE x = '{x}'"
        cursor.execute(query)
""")}), True)
case(R, "implicit-concat", dict(FLASK, **{"db.py": d("""
    def find(email):
        query = (
            f"SELECT * FROM users "
            f"WHERE email = '{email}'"
        )
        cursor.execute(query)
""")}), True)
case(R, "django-raw", {"manage.py": "import django\n", "app/views.py": d("""
    def profile(request, username):
        return User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{username}'")
""")}, True, "critical")
case(R, "django-extra-quoted", {"manage.py": "", "app/q.py": d("""
    def by_name(name):
        return Entry.objects.extra(where=["headline = '%s'"], params=[name])
""")}, True)
case(R, "django-extra-fstring", {"manage.py": "", "app/q.py": d("""
    def by_name(name):
        return Entry.objects.extra(where=[f"headline = '{name}'"])
""")}, True)
case(R, "rawsql-fstring", {"manage.py": "", "app/q.py": d("""
    def annotate(val):
        return Entry.objects.annotate(x=RawSQL(f"SELECT col FROM t WHERE y = {val}", []))
""")}, True)
case(R, "sqlalchemy-text", {"requirements.txt": "fastapi\nsqlalchemy\n", "main.py": d("""
    from sqlalchemy import text

    @app.get("/users")
    def users(email: str):
        return db.execute(text(f"SELECT * FROM users WHERE email = '{email}'")).all()
""")}, True, "critical")
case(R, "params-are-safe", dict(FLASK, **{"db.py": d("""
    def get(user_id, name):
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        cursor.execute("SELECT * FROM users WHERE name = %(n)s", {"n": name})
        User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
        Entry.objects.extra(where=["headline = %s"], params=[name])
""")}), False)
case(R, "sqlalchemy-bound-is-safe", {"requirements.txt": "sqlalchemy\n", "db.py": d("""
    from sqlalchemy import text
    def find(email):
        return db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email})
""")}, False)
case(R, "psycopg-composition-is-safe", {"requirements.txt": "psycopg\n", "db.py": d("""
    from psycopg import sql
    def cols(col):
        cur.execute(sql.SQL("SELECT {} FROM t").format(sql.Identifier(col)))
""")}, False)
case(R, "constant-table-is-safe", dict(FLASK, **{"db.py": d("""
    TABLE = "users"
    def get(uid):
        cursor.execute(f"SELECT * FROM {TABLE} WHERE id = %s", (uid,))
""")}), False)
case(R, "guarded-sort-is-safe", dict(FLASK, **{"db.py": d("""
    ALLOWED = {"name", "created_at"}
    def listing(sort):
        if sort not in ALLOWED:
            sort = "created_at"
        cursor.execute(f"SELECT * FROM posts ORDER BY {sort}")
""")}), False)
case(R, "orm-is-safe", dict(FLASK, **{"db.py": d("""
    def find(name):
        return User.objects.filter(name=name).order_by("-created")
""")}), False)
case(R, "docstring-is-ignored", dict(FLASK, **{"db.py": d('''
    def helper():
        """Never do cursor.execute(f"SELECT * FROM t WHERE x = '{x}'")."""
        # cursor.execute(f"SELECT * FROM t WHERE x = '{x}'")
        return None
''')}), False)

# --- sqli-php-string-query ---------------------------------------------------

R = "sqli-php-string-query"
LARAVEL = {"composer.json": '{"require": {"laravel/framework": "^11.0"}}', "artisan": ""}
case(R, "db-select-interpolated", dict(LARAVEL, **{"app/Http/Controllers/U.php": d("""
    <?php
    class U {
        public function show(Request $request) {
            $email = $request->input('email');
            return DB::select("SELECT * FROM users WHERE email = '$email'");
        }
    }
""")}), True, "critical")
case(R, "whereraw-concat", dict(LARAVEL, **{"app/S.php": d("""
    <?php
    $rows = Post::query()->whereRaw("title LIKE '%" . $request->q . "%'")->get();
""")}), True, "critical")
case(R, "pdo-query-get", {"index.php": d("""
    <?php
    $rows = $pdo->query("SELECT * FROM posts WHERE id = " . $_GET['id']);
""")}, True, "critical")
case(R, "mysqli-traced", {"list.php": d("""
    <?php
    $id = $_GET['id'];
    $res = mysqli_query($conn, "SELECT * FROM users WHERE id = $id");
""")}, True)
case(R, "static-eloquent-whereraw", dict(LARAVEL, **{"app/Http/Controllers/B.php": d("""
    <?php
    $rows = User::whereRaw("email = '{$request->email}'")->get();
""")}), True, "critical")
case(R, "orderbyraw-request", dict(LARAVEL, **{"app/L.php": d("""
    <?php
    $q->orderByRaw($request->input('sort'));
""")}), True)
case(R, "bindings-are-safe", dict(LARAVEL, **{"app/S.php": d("""
    <?php
    $rows = DB::select('SELECT * FROM users WHERE id = ?', [$id]);
    $rows = Post::query()->whereRaw('title LIKE ?', ["%{$q}%"])->get();
    $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([$_GET['id']]);
    $stmt = $pdo->prepare("SELECT * FROM {$this->table} WHERE id = :id");
    $n = DB::raw('count(*) as total');
    $rows = $pdo->query("SELECT * FROM posts WHERE id = " . (int)$_GET['id']);
    $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM {$wpdb->prefix}posts WHERE ID = %d", $id));
""")}), False)

# --- sqli-laravel-request-column ---------------------------------------------

R = "sqli-laravel-request-column"
case(R, "orderby-request", dict(LARAVEL, **{"app/Http/Controllers/P.php": d("""
    <?php
    return Post::query()->orderBy($request->input('sort', 'created_at'))->paginate();
""")}), True)
case(R, "orderby-traced", dict(LARAVEL, **{"app/Http/Controllers/P.php": d("""
    <?php
    $sort = $request->get('sort');
    return Post::query()->orderBy($sort, 'desc')->get();
""")}), True)
case(R, "static-orderby", dict(LARAVEL, **{"app/Http/Controllers/P.php": d("""
    <?php
    return Post::orderBy($request->query('sort'))->get();
""")}), True)
case(R, "in-array-is-safe", dict(LARAVEL, **{"app/Http/Controllers/P.php": d("""
    <?php
    $sort = in_array($request->sort, ['name', 'created_at'], true) ? $request->sort : 'created_at';
    return Post::query()->orderBy($sort)->orderBy('id', $request->input('dir'))->get();
""")}), False)
case(R, "validated-is-safe", dict(LARAVEL, **{"app/Http/Controllers/P.php": d("""
    <?php
    $data = $request->validate(['sort' => 'in:name,created_at']);
    return Post::query()->orderBy($request->input('sort'))->get();
""")}), False)

# --- nosqli-request-filter ---------------------------------------------------

R = "nosqli-request-filter"
case(R, "login-body-fields", {"package.json": PKG_MONGO, "routes/auth.js": d("""
    router.post('/login', async (req, res) => {
      const user = await User.findOne({ email: req.body.email, password: req.body.password })
    })
""")}, True)
case(R, "destructured-shorthand", {"package.json": PKG_MONGO, "routes/auth.js": d("""
    router.post('/login', async (req, res) => {
      const { email, password } = req.body
      const user = await User.findOne({ email, password })
    })
""")}, True)
case(R, "whole-query-object", {"package.json": PKG_MONGO, "routes/items.js": d("""
    router.get('/items', async (req, res) => res.json(await Item.find(req.query)))
""")}, True)
case(R, "next-route-json", {"package.json": '{"dependencies": {"next": "15.2.4", "mongodb": "^6.0.0"}}',
                            "app/api/login/route.ts": d("""
    export async function POST(req: Request) {
      const { email } = await req.json()
      const user = await db.collection('users').findOne({ email })
    }
""")}, True)
case(R, "pymongo-json", {"requirements.txt": "flask\npymongo\n", "app.py": d("""
    @app.post("/login")
    def login():
        data = request.get_json()
        user = users.find_one({"username": data["username"], "password": data["password"]})
""")}, True)
case(R, "string-cast-is-safe", {"package.json": PKG_MONGO, "routes/a.js": d("""
    const user = await User.findOne({ email: String(req.body.email) })
    const u2 = await User.findOne({ email: { $eq: req.body.email } })
    const u3 = await User.findOne({ _id: req.params.id })
""")}, False)
case(R, "typeof-guard-is-safe", {"package.json": PKG_MONGO, "routes/a.js": d("""
    router.post('/login', async (req, res) => {
      const { email } = req.body
      if (typeof email !== 'string') return res.status(400).end()
      const user = await User.findOne({ email })
    })
""")}, False)
case(R, "schema-parse-is-safe", {"package.json": PKG_MONGO, "routes/a.js": d("""
    router.post('/login', async (req, res) => {
      const { email, password } = LoginSchema.parse(req.body)
      const user = await User.findOne({ email })
    })
""")}, False)
case(R, "array-find-is-safe", {"package.json": PKG_MONGO, "routes/a.js": d("""
    const item = items.find(i => i.id === req.body.id)
""")}, False)
case(R, "sanitize-filter-project-is-skipped", {"package.json": '{"dependencies": {"express": "^4.19.0", "mongoose": "^8.22.1"}}',
                                               "db.js": "mongoose.set('sanitizeFilter', true)\n",
                                               "routes/a.js": "const u = await User.findOne({ email: req.body.email })\n"}, False)
case(R, "express5-query-is-safe", {"package.json": '{"dependencies": {"express": "^5.1.0", "mongoose": "^8.9.5"}}',
                                   "routes/a.js": "const u = await User.find({ name: req.query.name })\n"}, False)
case(R, "no-mongo-is-skipped", {"package.json": PKG_NODE,
                                "routes/a.js": "const u = await repo.findOne({ email: req.body.email })\n"}, False)
case(R, "flask-form-strings-are-safe", {"requirements.txt": "flask\npymongo\n", "app.py": d("""
    def login():
        user = users.find_one({"username": request.form["username"]})
""")}, False)

# --- cmdi-node-shell ---------------------------------------------------------

R = "cmdi-node-shell"
case(R, "exec-request", {"package.json": PKG_NODE, "server/convert.js": d("""
    const { exec } = require('child_process')
    app.post('/convert', (req, res) => {
      exec(`convert ${req.body.file} out.png`, (err) => res.end())
    })
""")}, True, "critical")
case(R, "exec-traced-param", {"package.json": PKG_NODE, "lib/ping.js": d("""
    import { execSync } from 'node:child_process'
    export function ping(host) {
      const cmd = 'ping -c 1 ' + host
      return execSync(cmd).toString()
    }
""")}, True, "medium")
case(R, "promisified", {"package.json": PKG_NODE, "server/git.js": d("""
    const util = require('util')
    const { exec } = require('child_process')
    const execAsync = util.promisify(exec)
    app.post('/clone', async (req, res) => {
      await execAsync(`git clone ${req.body.repo}`)
    })
""")}, True, "critical")
case(R, "spawn-shell-true", {"package.json": PKG_NODE, "lib/ls.js": d("""
    const { spawn } = require('child_process')
    function list(dir) {
      return spawn(`ls -la ${dir}`, { shell: true })
    }
""")}, True)
case(R, "namespace-import", {"package.json": PKG_NODE, "lib/rm.ts": d("""
    import * as cp from 'node:child_process'
    export function clean(p: string) { cp.execSync(`rm -rf ${p}`) }
""")}, True)
case(R, "argument-list-is-safe", {"package.json": PKG_NODE, "server/convert.js": d("""
    const { execFile, spawn, exec } = require('child_process')
    app.post('/convert', (req, res) => {
      execFile('convert', [req.body.file, 'out.png'])
      spawn('git', ['clone', req.body.repo])
      exec('npm run build')
      exec(`node ${path.join(__dirname, 'worker.js')}`)
    })
""")}, False)
case(R, "regex-exec-is-not-a-shell", {"package.json": PKG_NODE, "lib/p.js": d("""
    const m = /(\\d+)/.exec(`value ${input}`)
    const r = pattern.exec(input)
""")}, False)
case(R, "build-scripts-excluded", {"package.json": PKG_NODE, "scripts/release.js": d("""
    const { execSync } = require('child_process')
    execSync(`git tag v${version}`)
""")}, False)

# --- cmdi-python-shell -------------------------------------------------------

R = "cmdi-python-shell"
case(R, "os-system-request", dict(FLASK, **{"app.py": d("""
    import os
    @app.post("/convert")
    def convert():
        name = request.form["name"]
        os.system(f"convert {name} out.png")
""")}), True, "critical")
case(R, "subprocess-shell-true", dict(FLASK, **{"tools.py": d("""
    import subprocess
    def ping(host):
        return subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
""")}), True, "medium")
case(R, "check-output-concat", dict(FLASK, **{"tools.py": d("""
    import subprocess
    def ls(path):
        return subprocess.check_output("ls " + path, shell=True)
""")}), True)
case(R, "bare-popen-traced", dict(FLASK, **{"tools.py": d("""
    from subprocess import Popen
    def run(target):
        cmd = f"nmap {target}"
        Popen(cmd, shell=True)
""")}), True)
case(R, "list-and-quote-are-safe", dict(FLASK, **{"tools.py": d("""
    import os
    import shlex
    import subprocess
    def ping(host, name):
        subprocess.run(["ping", "-c", "1", host])
        subprocess.run(f"echo {shlex.quote(name)}", shell=True)
        subprocess.run("ls " + host, shell=False)
        os.system("clear")
""")}), False)

# --- cmdi-php-shell ----------------------------------------------------------

R = "cmdi-php-shell"
case(R, "shell-exec-get", {"ping.php": d("""
    <?php
    $out = shell_exec("ping -c 1 " . $_GET['host']);
""")}, True, "critical")
case(R, "exec-traced", dict(LARAVEL, **{"app/C.php": d("""
    <?php
    $file = $request->input('file');
    exec("convert $file out.png");
""")}), True, "critical")
case(R, "backticks", {"lib.php": d("""
    <?php
    function listing($dir) {
        return `ls -la $dir`;
    }
""")}, True)
case(R, "escaped-and-constant-are-safe", {"ping.php": d("""
    <?php
    $out = shell_exec("ping -c 1 " . escapeshellarg($_GET['host']));
    $pdo->exec("DELETE FROM sessions WHERE expired = 1");
    exec('composer install --no-dev');
""")}, False)

# --- xss-react-dangerous-html ------------------------------------------------

R = "xss-react-dangerous-html"
case(R, "fetched-field", {"package.json": PKG_NEXT, "app/post/page.tsx": d("""
    export default async function Page() {
      const post = await getPost()
      return <div dangerouslySetInnerHTML={{ __html: post.content }} />
    }
""")}, True, "high")
case(R, "prop-passthrough", {"package.json": PKG_NEXT, "components/Html.tsx": d("""
    export function Html({ html }: { html: string }) {
      return <div dangerouslySetInnerHTML={{ __html: html }} />
    }
""")}, True, "medium")
case(R, "markdown-unsanitized", {"package.json": PKG_NEXT, "components/Msg.tsx": d("""
    import { marked } from 'marked'
    export const Msg = ({ message }) => <div dangerouslySetInnerHTML={{ __html: marked(message.text) }} />
""")}, True, "high")
case(R, "template-with-field", {"package.json": PKG_NEXT, "components/C.tsx": d("""
    export const C = ({ comment }) => <p dangerouslySetInnerHTML={{ __html: `<b>${comment.author}</b>: ${comment.body}` }} />
""")}, True)
case(R, "sanitized-is-safe", {"package.json": PKG_NEXT, "components/Safe.tsx": d("""
    import DOMPurify from 'isomorphic-dompurify'
    export function Safe({ html, post }) {
      const clean = DOMPurify.sanitize(html)
      return (
        <>
          <div dangerouslySetInnerHTML={{ __html: clean }} />
          <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(post.content) }} />
        </>
      )
    }
""")}, False)
case(R, "constants-and-json-ld-are-safe", {"package.json": PKG_NEXT, "app/layout.tsx": d("""
    import iconSvg from './icon.svg?raw'
    const themeScript = `(function(){try{var t=localStorage.getItem('theme');document.documentElement.dataset.theme=t}catch(e){}})()`
    export default function Layout({ jsonLd }) {
      return (
        <html>
          <script dangerouslySetInnerHTML={{ __html: themeScript }} />
          <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
          <span dangerouslySetInnerHTML={{ __html: iconSvg }} />
          <b dangerouslySetInnerHTML={{ __html: '<em>hi</em>' }} />
          <code dangerouslySetInnerHTML={{ __html: highlight(code) }} />
        </html>
      )
    }
""")}, False)

# --- xss-framework-raw-html --------------------------------------------------

R = "xss-framework-raw-html"
case(R, "vue-v-html", {"package.json": '{"dependencies": {"vue": "^3.5.0"}}', "src/Post.vue": d("""
    <template><article v-html="post.body"></article></template>
    <script setup>
    const props = defineProps(['post'])
    </script>
""")}, True)
case(R, "svelte-html-markdown", {"package.json": '{"dependencies": {"svelte": "^5.0.0"}}', "src/Msg.svelte": d("""
    <script>
      import { marked } from 'marked'
      export let content
    </script>
    <div>{@html marked(content)}</div>
""")}, True)
case(R, "angular-bypass", {"package.json": '{"dependencies": {"@angular/core": "^19.0.0"}}', "src/app/c.component.ts": d("""
    export class C {
      constructor(private sanitizer: DomSanitizer) {}
      get html() { return this.sanitizer.bypassSecurityTrustHtml(this.content) }
    }
""")}, True)
case(R, "sanitized-and-escaped-are-safe", {"package.json": '{"dependencies": {"vue": "^3.5.0"}}', "src/Safe.vue": d("""
    <template>
      <article v-html="safeHtml"></article>
      <p>{{ post.body }}</p>
      <i v-html="'<b>static</b>'"></i>
    </template>
    <script setup>
    import DOMPurify from 'dompurify'
    const props = defineProps(['post'])
    const safeHtml = computed(() => DOMPurify.sanitize(props.post.body))
    </script>
""")}, False)
case(R, "svelte-constant-is-safe", {"package.json": '{"dependencies": {"svelte": "^5.0.0"}}', "src/A.svelte": d("""
    <p>{@html '<br>'}</p>
    <p>{@html DOMPurify.sanitize(text)}</p>
""")}, False)

# --- xss-dom-innerhtml -------------------------------------------------------

R = "xss-dom-innerhtml"
case(R, "map-join-template", {"public/app.js": d("""
    async function load() {
      const res = await fetch('/api/items')
      const items = await res.json()
      list.innerHTML = items.map(i => `<li>${i.name}</li>`).join('')
    }
""")}, True)
case(R, "data-field", {"public/chat.js": d("""
    socket.on('message', (data) => {
      bubble.innerHTML = data.message
    })
""")}, True)
case(R, "url-hash", {"public/a.js": "out.innerHTML = location.hash.slice(1)\n"}, True, "high")
case(R, "insert-adjacent", {"public/a.js": d("""
    function add(msg) {
      feed.insertAdjacentHTML('beforeend', `<div class="m">${msg.text}</div>`)
    }
""")}, True)
case(R, "markdown-to-innerhtml", {"public/a.js": "preview.innerHTML = marked.parse(editor.value)\n"}, True, "high")
case(R, "inline-script-in-html", {"index.html": d("""
    <html><body><div id="o"></div>
    <script>
      const q = new URLSearchParams(location.search).get('q')
      document.getElementById('o').innerHTML = `Results for ${q}`
    </script>
    </body></html>
""")}, True)
case(R, "jquery-html", {"public/a.js": d("""
    $.getJSON('/api/msg', (data) => { $('#out').html(data.message) })
""")}, True)
case(R, "safe-assignments", {"public/a.js": d("""
    const ICONS = { link: '<svg></svg>' }
    el.innerHTML = ''
    t.innerHTML = ICONS[name] || ''
    badge.innerHTML = `<span>${items.length} items</span>`
    box.innerHTML = qr.createSvgTag({ cellSize: 8 })
    function setHtml(html) { target.innerHTML = html }
    title.textContent = data.title
    copy.innerHTML = source.innerHTML
    card.innerHTML = item.html
    $('#out').html('<b>static</b>')
    const current = $('#out').html()
    editor.html(data.message)
""")}, False)
case(R, "escaped-template-is-safe", {"public/a.js": "row.innerHTML = `<li>${escapeHtml(item.name)}</li>`\n"}, False)
case(R, "escaping-file-leaves-numbers-alone", {"public/a.js": d("""
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';')
    stats.innerHTML = `<dt>${esc(t('beds'))}</dt><dd>${d.beds} / ${d.total}</dd>`
""")}, False)
case(R, "escaping-file-still-reports-url-input", {"public/a.js": d("""
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => '&#' + c.charCodeAt(0) + ';')
    out.innerHTML = location.hash.slice(1)
""")}, True, "high")
case(R, "vendored-library-skipped", {"public/lib/chart.js": "/*! chart lib v1 | MIT */\nel.innerHTML = data.label\n"}, False)

# --- xss-markdown-rehype-raw -------------------------------------------------

R = "xss-markdown-rehype-raw"
case(R, "raw-without-sanitize", {"package.json": PKG_NEXT, "components/Md.tsx": d("""
    import ReactMarkdown from 'react-markdown'
    import rehypeRaw from 'rehype-raw'
    export const Md = ({ text }) => <ReactMarkdown rehypePlugins={[rehypeRaw]}>{text}</ReactMarkdown>
""")}, True)
case(R, "sanitize-before-raw", {"package.json": PKG_NEXT, "components/Md.tsx": d("""
    import rehypeRaw from 'rehype-raw'
    import rehypeSanitize from 'rehype-sanitize'
    export const Md = ({ text }) => <ReactMarkdown rehypePlugins={[rehypeSanitize, rehypeRaw]}>{text}</ReactMarkdown>
""")}, True)
case(R, "raw-then-sanitize-is-safe", {"package.json": PKG_NEXT, "components/Md.tsx": d("""
    import rehypeRaw from 'rehype-raw'
    import rehypeSanitize from 'rehype-sanitize'
    export const Md = ({ text }) => <ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]}>{text}</ReactMarkdown>
""")}, False)
case(R, "plain-react-markdown-is-safe", {"package.json": PKG_NEXT, "components/Md.tsx": d("""
    import ReactMarkdown from 'react-markdown'
    export const Md = ({ text }) => <ReactMarkdown>{text}</ReactMarkdown>
""")}, False)

# --- xss-blade-unescaped -----------------------------------------------------

R = "xss-blade-unescaped"
case(R, "raw-field", dict(LARAVEL, **{"resources/views/post.blade.php": "<div>{!! $post->body !!}</div>\n"}), True)
case(R, "raw-old-input", dict(LARAVEL, **{"resources/views/f.blade.php": "<input value=\"{!! old('name') !!}\">\n"}), True)
case(R, "safe-forms", dict(LARAVEL, **{"resources/views/ok.blade.php": d("""
    <div>{{ $post->body }}</div>
    {!! csrf_field() !!}
    {!! clean($post->body) !!}
    <script>window.data = {!! json_encode($data) !!}</script>
    {{-- {!! $post->body !!} --}}
    {!! __('messages.welcome') !!}
    {!! $slot !!}
""")}), False)

# --- xss-python-template-safe ------------------------------------------------

R = "xss-python-template-safe"
case(R, "jinja-safe-filter", dict(FLASK, **{"templates/c.html": "<p>{{ comment.text|safe }}</p>\n"}), True)
case(R, "markdown-safe", dict(FLASK, **{"templates/p.html": "<div>{{ post.body | markdown | safe }}</div>\n"}), True)
case(R, "autoescape-off", {"manage.py": "", "app/templates/x.html": "{% autoescape off %}{{ bio }}{% endautoescape %}\n"}, True)
case(R, "mark-safe-fstring", {"manage.py": "", "app/utils.py": d("""
    from django.utils.safestring import mark_safe
    def link(url, name):
        return mark_safe(f"<a href='{url}'>{name}</a>")
""")}, True)
case(R, "markup-markdown", dict(FLASK, **{"app.py": d("""
    import markdown
    from markupsafe import Markup
    def render(text):
        return Markup(markdown.markdown(text))
""")}), True)
case(R, "safe-variants", dict(FLASK, **{"templates/ok.html": d("""
    <script>const data = {{ data|tojson|safe }};</script>
    <p>{{ comment.text }}</p>
"""), "app.py": d("""
    import bleach
    from markupsafe import Markup
    from django.utils.html import format_html
    def ok(name, text):
        a = mark_safe("<br>")
        b = format_html("<b>{}</b>", name)
        c = Markup("<b>{}</b>").format(name)
        d = mark_safe(bleach.clean(text))
        return a, b, c, d
""")}), False)

# --- upload-client-filename --------------------------------------------------

R = "upload-client-filename"
case(R, "multer-originalname", {"package.json": PKG_NODE, "server/upload.js": d("""
    const storage = multer.diskStorage({
      destination: 'uploads/',
      filename: (req, file, cb) => cb(null, file.originalname),
    })
""")}, True)
case(R, "multer-prefixed", {"package.json": PKG_NODE, "server/upload.js": d("""
    const storage = multer.diskStorage({
      filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
      },
    })
""")}, True)
case(R, "next-formdata-file", {"package.json": PKG_NEXT, "app/api/upload/route.ts": d("""
    export async function POST(req: Request) {
      const formData = await req.formData()
      const file = formData.get('file') as File
      const buffer = Buffer.from(await file.arrayBuffer())
      const filePath = path.join(process.cwd(), 'public/uploads', file.name)
      await writeFile(filePath, buffer)
    }
""")}, True)
case(R, "flask-save", dict(FLASK, **{"app.py": d("""
    @app.post("/upload")
    def upload():
        f = request.files["file"]
        f.save(os.path.join(app.config["UPLOAD_FOLDER"], f.filename))
""")}), True)
case(R, "fastapi-open", {"requirements.txt": "fastapi\n", "main.py": d("""
    @app.post("/upload")
    async def upload(file: UploadFile = File(...)):
        with open(f"uploads/{file.filename}", "wb") as out:
            out.write(await file.read())
""")}, True)
case(R, "django-open", {"manage.py": "", "app/views.py": d("""
    def upload(request):
        f = request.FILES["doc"]
        with open(os.path.join(settings.MEDIA_ROOT, f.name), "wb+") as dest:
            for chunk in f.chunks():
                dest.write(chunk)
""")}, True)
case(R, "php-files-name", {"up.php": d("""
    <?php
    move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
""")}, True)
case(R, "laravel-store-as", dict(LARAVEL, **{"app/Http/Controllers/A.php": d("""
    <?php
    $path = $request->file('avatar')->storeAs('avatars', $request->file('avatar')->getClientOriginalName());
""")}), True, "medium")
case(R, "random-names-are-safe", {"package.json": PKG_NODE, "server/upload.js": d("""
    const storage = multer.diskStorage({
      filename: (req, file, cb) => cb(null, crypto.randomUUID() + path.extname(file.originalname)),
    })
    router.post('/up', upload.single('f'), async (req, res) => {
      await db.files.insert({ originalName: req.file.originalname })
      res.json({ name: req.file.originalname })
    })
""")}, False)
case(R, "python-safe", dict(FLASK, **{"app.py": d("""
    def upload():
        f = request.files["file"]
        name = secure_filename(f.filename)
        f.save(os.path.join(app.config["UPLOAD_FOLDER"], name))
        default_storage.save(f.name, f)
""")}), False)
case(R, "express-fileupload-mv", {"package.json": PKG_NODE, "server/up.js": d("""
    app.post('/up', (req, res) => {
      req.files.avatar.mv(`./uploads/${req.files.avatar.name}`)
    })
""")}, True)
case(R, "server-action-write", {"package.json": PKG_NEXT, "app/actions.ts": d("""
    'use server'
    export async function upload(formData: FormData) {
      const file = formData.get('file') as File
      await fs.writeFile(`./public/uploads/${file.name}`, Buffer.from(await file.arrayBuffer()))
    }
""")}, True)
case(R, "php-random-name-is-safe", {"up.php": d("""
    <?php
    $f = $_FILES['file'];
    $ext = strtolower(pathinfo((string)$f['name'], PATHINFO_EXTENSION));
    $name = bin2hex(random_bytes(6)) . '.' . $ext;
    move_uploaded_file($f['tmp_name'], UPLOAD_DIR . '/' . $name);
""")}, False)

# --- upload-client-mime-check ------------------------------------------------

R = "upload-client-mime-check"
case(R, "multer-filter", {"package.json": PKG_NODE, "server/upload.js": d("""
    const upload = multer({
      fileFilter: (req, file, cb) => cb(null, file.mimetype.startsWith('image/')),
    })
""")}, True)
case(R, "includes-mimetype", {"package.json": PKG_NODE, "server/upload.js": d("""
    const ALLOWED = ['image/png', 'image/jpeg']
    function fileFilter(req, file, cb) { cb(null, ALLOWED.includes(file.mimetype)) }
""")}, True)
case(R, "php-files-type", {"up.php": d("""
    <?php
    if ($_FILES['f']['type'] !== 'image/png') { die('bad type'); }
""")}, True)
case(R, "fastapi-content-type", {"requirements.txt": "fastapi\n", "main.py": d("""
    @app.post("/upload")
    async def upload(file: UploadFile):
        if file.content_type not in ("image/png", "image/jpeg"):
            raise HTTPException(400)
""")}, True)
case(R, "content-sniffing-is-safe", {"package.json": PKG_NODE, "server/upload.js": d("""
    import { fileTypeFromBuffer } from 'file-type'
    function filter(req, file, cb) { cb(null, file.mimetype.startsWith('image/')) }
""")}, False)
case(R, "php-finfo-is-safe", {"up.php": d("""
    <?php
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['f']['tmp_name']);
    if ($_FILES['f']['type'] !== 'image/png') { die('bad type'); }
""")}, False)
case(R, "logging-only-is-safe", {"package.json": PKG_NODE, "server/upload.js": d("""
    router.post('/up', upload.single('f'), (req, res) => {
      console.log(req.file.mimetype)
      res.json({ type: req.file.mimetype })
    })
""")}, False)

# --- upload-no-size-limit ----------------------------------------------------

R = "upload-no-size-limit"
case(R, "multer-dest", {"package.json": PKG_NODE, "server/u.js": d("""
    const multer = require('multer')
    const upload = multer({ dest: 'uploads/' })
""")}, True)
case(R, "multer-empty", {"package.json": PKG_NODE, "server/u.js": d("""
    import multer from 'multer'
    const upload = multer()
""")}, True)
case(R, "flask-no-max", dict(FLASK, **{"app.py": d("""
    from flask import Flask, request
    app = Flask(__name__)
    @app.post("/up")
    def up():
        f = request.files["file"]
""")}), True)
case(R, "multer-limited-is-safe", {"package.json": PKG_NODE, "server/u.js": d("""
    const multer = require('multer')
    const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } })
""")}, False)
case(R, "flask-max-elsewhere-is-safe", dict(FLASK, **{"config.py": "MAX_CONTENT_LENGTH = 16 * 1024 * 1024\n", "app.py": d("""
    from flask import Flask, request
    def up():
        f = request.files["file"]
""")}), False)

# --- path-traversal-request --------------------------------------------------

R = "path-traversal-request"
case(R, "sendfile-join", {"package.json": PKG_NODE, "server/files.js": d("""
    app.get('/files/:name', (req, res) => {
      res.sendFile(path.join(__dirname, 'files', req.params.name))
    })
""")}, True)
case(R, "readfile-concat", {"package.json": PKG_NODE, "server/docs.js": d("""
    const fs = require('fs')
    app.get('/doc', (req, res) => res.send(fs.readFileSync('./docs/' + req.query.file, 'utf8')))
""")}, True)
case(R, "promises-traced", {"package.json": PKG_NODE, "server/d.js": d("""
    const fs = require('fs')
    app.get('/d', async (req, res) => {
      const { file } = req.query
      const data = await fs.promises.readFile(path.join(DIR, file))
    })
""")}, True)
case(R, "flask-send-file", dict(FLASK, **{"app.py": d("""
    @app.get("/dl")
    def dl():
        return send_file(os.path.join(BASE, request.args.get("f")))
""")}), True)
case(R, "fastapi-query-param", {"requirements.txt": "fastapi\n", "main.py": d("""
    @app.get("/download")
    def download(name: str):
        return FileResponse(os.path.join(DIR, name))
""")}, True)
case(R, "php-include", {"index.php": d("""
    <?php
    include $_GET['page'] . '.php';
""")}, True, "critical")
case(R, "php-readfile", {"dl.php": "<?php\nreadfile('files/' . $_GET['f']);\n"}, True)
case(R, "safe-variants-node", {"package.json": PKG_NODE, "server/files.js": d("""
    const fs = require('fs')
    app.get('/a/:name', (req, res) => res.sendFile(req.params.name, { root: path.join(__dirname, 'files') }))
    app.get('/b/:name', (req, res) => res.sendFile(path.join(__dirname, 'files', path.basename(req.params.name))))
    app.get('/c', (req, res) => res.send(fs.readFileSync(path.join(__dirname, 'data.json'))))
""")}, False)
case(R, "resolve-startswith-guard", {"package.json": PKG_NODE, "server/files.js": d("""
    const fs = require('fs')
    app.get('/f', (req, res) => {
      const target = path.resolve(ROOT, req.query.file)
      if (!target.startsWith(ROOT + path.sep)) return res.status(400).end()
      res.send(fs.readFileSync(target))
    })
""")}, False)
case(R, "fastapi-path-param-is-safe", {"requirements.txt": "fastapi\n", "main.py": d("""
    @app.get("/files/{name}")
    def get_file(name: str):
        return FileResponse(os.path.join(DIR, name))
""")}, False)
case(R, "python-safe-helpers", dict(FLASK, **{"app.py": d("""
    @app.get("/dl")
    def dl():
        return send_from_directory(DIR, request.args.get("f"))
""")}), False)
case(R, "php-basename-is-safe", {"dl.php": "<?php\nreadfile('files/' . basename($_GET['f']));\nrequire __DIR__ . '/config.php';\n"}, False)
case(R, "server-generated-upload-paths-are-safe", {"package.json": PKG_NODE, "server/u.js": d("""
    const fs = require('fs')
    app.post('/u', upload.single('f'), (req, res) => { const data = fs.readFileSync(req.file.path) })
"""), "u.php": d("""
    <?php
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($_FILES['f']['tmp_name']);
    $h = file_get_contents($_FILES['f']['tmp_name'], false, null, 0, 4);
""")}, False)

# --- ssrf-request-url --------------------------------------------------------

R = "ssrf-request-url"
case(R, "express-fetch-query", {"package.json": PKG_NODE, "server/preview.js": d("""
    app.get('/preview', async (req, res) => {
      const r = await fetch(req.query.url)
      res.send(await r.text())
    })
""")}, True)
case(R, "next-route-json-url", {"package.json": PKG_NEXT, "app/api/import/route.ts": d("""
    export async function POST(req: Request) {
      const { url } = await req.json()
      const res = await fetch(url)
      return Response.json(await res.json())
    }
""")}, True)
case(R, "next-search-params", {"package.json": PKG_NEXT, "app/api/img/route.ts": d("""
    export async function GET(request: NextRequest) {
      const target = request.nextUrl.searchParams.get('src')
      return fetch(target)
    }
""")}, True)
case(R, "axios-body", {"package.json": PKG_NODE, "server/avatar.js": d("""
    app.post('/avatar', async (req, res) => {
      const img = await axios.get(req.body.imageUrl, { responseType: 'arraybuffer' })
    })
""")}, True)
case(R, "host-interpolated", {"package.json": PKG_NODE, "server/h.js": d("""
    app.get('/h', async (req, res) => {
      const r = await fetch(`https://${req.query.host}/status`)
    })
""")}, True)
case(R, "python-requests", dict(FLASK, **{"app.py": d("""
    @app.get("/fetch")
    def fetch():
        r = requests.get(request.args.get("url"), timeout=5)
        return r.text
""")}), True)
case(R, "fastapi-httpx-client", {"requirements.txt": "fastapi\nhttpx\n", "main.py": d("""
    @app.get("/preview")
    async def preview(url: str):
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
        return r.text
""")}, True)
case(R, "php-file-get-contents", {"p.php": "<?php\n$html = file_get_contents($_GET['url']);\n"}, True)
case(R, "php-curl", dict(LARAVEL, **{"app/P.php": "<?php\n$ch = curl_init($request->input('url'));\n"}), True)
case(R, "fixed-host-is-safe", {"package.json": PKG_NODE, "server/gh.js": d("""
    app.get('/gh/:user', async (req, res) => {
      const r = await fetch(`https://api.github.com/users/${req.params.user}`)
      const r2 = await fetch(process.env.API_URL + '/items?q=' + encodeURIComponent(req.query.q))
      const r3 = await fetch('/api/local')
    })
""")}, False)
case(R, "allowlist-is-safe", {"package.json": PKG_NODE, "server/p.js": d("""
    const ALLOWED_HOSTS = new Set(['images.example.com'])
    app.get('/p', async (req, res) => {
      const u = new URL(req.query.url)
      if (!ALLOWED_HOSTS.has(u.hostname)) return res.status(400).end()
      const r = await fetch(u)
    })
""")}, False)
case(R, "python-ip-check-is-safe", dict(FLASK, **{"app.py": d("""
    import ipaddress, socket
    from urllib.parse import urlsplit
    @app.get("/fetch")
    def fetch():
        url = request.args.get("url")
        host = urlsplit(url).hostname
        for info in socket.getaddrinfo(host, 443):
            if not ipaddress.ip_address(info[4][0]).is_global:
                abort(400)
        return requests.get(url, timeout=5, allow_redirects=False).text
""")}), False)
case(R, "client-fetch-is-safe", {"package.json": PKG_NEXT, "components/Preview.tsx": d("""
    'use client'
    export function Preview() {
      const params = useSearchParams()
      useEffect(() => { fetch(params.get('url')) }, [])
    }
""")}, False)
case(R, "unknown-param-is-safe", {"package.json": PKG_NODE, "lib/http.js": d("""
    export async function getJson(url) {
      const r = await fetch(url)
      return r.json()
    }
""")}, False)
case(R, "php-param-is-safe", {"lib.php": d("""
    <?php
    function http_get_json(string $url): ?array {
        $ch = curl_init($url);
        return null;
    }
""")}, False)
case(R, "python-cache-get-is-safe", dict(FLASK, **{"app.py": "def f():\n    return cache.get(request.args['key'])\n"}), False)

# --- xss-reflected-response --------------------------------------------------

R = "xss-reflected-response"
case(R, "express-template", {"package.json": PKG_NODE, "server/hello.js": d("""
    app.get('/hello', (req, res) => res.send(`<h1>Hello ${req.query.name}</h1>`))
""")}, True)
case(R, "express-echo", {"package.json": PKG_NODE, "server/echo.js": "app.get('/e', (req, res) => res.send(req.query.q))\n"}, True)
case(R, "flask-fstring", dict(FLASK, **{"app.py": d("""
    from flask import Flask, request
    app = Flask(__name__)

    @app.route("/hello")
    def hello():
        name = request.args.get("name", "")
        return f"<h1>Hello {name}</h1>"
""")}), True)
case(R, "flask-route-param", dict(FLASK, **{"app.py": d("""
    from flask import Flask
    @app.route("/u/<username>")
    def profile(username):
        return "<h2>" + username + "</h2>"
""")}), True)
case(R, "django-httpresponse", {"manage.py": "", "app/views.py": d("""
    def search(request):
        q = request.GET.get("q", "")
        return HttpResponse(f"<p>Results for {q}</p>")
""")}, True)
case(R, "php-echo", {"s.php": "<?php\necho 'Results for ' . $_GET['q'];\n"}, True)
case(R, "php-short-echo", {"s.php": "<p><?= $_GET['q'] ?></p>\n"}, True)
case(R, "safe-variants-node", {"package.json": PKG_NODE, "server/ok.js": d("""
    app.get('/a', (req, res) => res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`))
    app.get('/b', (req, res) => res.json({ q: req.query.q }))
    app.get('/c', (req, res) => res.send(`<h1>${title}</h1>`))
    app.post('/d', (req, res) => res.send(req.body))
    app.get('/e', (req, res) => res.render('page', { name: req.query.name }))
""")}, False)
case(R, "safe-variants-flask", dict(FLASK, **{"app.py": d("""
    from flask import Flask, request, render_template, jsonify
    from markupsafe import escape

    @app.route("/a")
    def a():
        return render_template("a.html", name=request.args.get("name"))

    @app.route("/b")
    def b():
        return f"<p>{escape(request.args.get('name'))}</p>"

    @app.route("/c")
    def c():
        return jsonify(q=request.args.get("q"))

    def helper(title):
        return f"<h1>{title}</h1>"
""")}), False)
case(R, "safe-variants-php", {"ok.php": d("""
    <?php
    echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');
    echo "Hello";
    print(e($_GET['name']));
"""), "api.php": "<?php\nheader('Content-Type: application/json');\necho json_encode(['q' => $_GET['q']]);\n"}, False)

# --- cmdi-code-eval ----------------------------------------------------------

R = "cmdi-code-eval"
case(R, "js-eval", {"package.json": PKG_NODE, "server/calc.js": d("""
    app.post('/calc', (req, res) => res.json({ value: eval(req.body.expr) }))
""")}, True)
case(R, "js-new-function", {"package.json": PKG_NODE, "server/f.js": d("""
    app.get('/f', (req, res) => { const fn = new Function('x', 'return ' + req.query.formula); res.json(fn(2)) })
""")}, True)
case(R, "python-eval", dict(FLASK, **{"app.py": d("""
    @app.get("/calc")
    def calc():
        return str(eval(request.args.get("expr")))
""")}), True)
case(R, "flask-ssti", dict(FLASK, **{"app.py": d("""
    @app.route("/hi")
    def hi():
        name = request.args.get("name")
        return render_template_string(f"<h1>Hi {name}</h1>")
""")}), True)
case(R, "php-eval", {"e.php": "<?php\neval('$v = ' . $_POST['code'] . ';');\n"}, True)
case(R, "safe-variants", dict(FLASK, **{"app.py": d("""
    import ast, re
    @app.route("/hi")
    def hi():
        x = eval("2 + 2")
        lit = ast.literal_eval(request.args.get("v"))
        pat = re.compile(request.args.get("p"))
        return render_template_string("<h1>Hi {{ name }}</h1>", name=request.args.get("name"))
"""), "package.json": PKG_NODE, "server/ok.js": "const v = eval('1 + 1')\nconst f = new Function('a', 'b', 'return a + b')\n"}), False)

# --- ssrf-next-image-any-host ------------------------------------------------

R = "ssrf-next-image-any-host"
case(R, "wildcard-host", {"package.json": PKG_NEXT, "next.config.js": d("""
    module.exports = {
      images: { remotePatterns: [{ protocol: 'https', hostname: '**' }] },
    }
""")}, True)
case(R, "exact-host-is-safe", {"package.json": PKG_NEXT, "next.config.mjs": d("""
    export default {
      images: { remotePatterns: [{ protocol: 'https', hostname: 'images.example.com', pathname: '/u/**' },
                                 { protocol: 'https', hostname: '**.example.com' }] },
    }
""")}, False)
case(R, "unoptimized-is-skipped", {"package.json": PKG_NEXT, "next.config.ts": d("""
    const config = { images: { unoptimized: true, remotePatterns: [{ hostname: '**' }] } }
    export default config
""")}, False)


# --- regressions from the corpus review: safe shapes stay quiet, missed shapes fire ---

PKG_VITE = '{"dependencies": {"react": "19.0.0", "react-dom": "19.0.0", "vite": "6.0.0"}}'

R = "xss-react-dangerous-html"
case(R, "highlighter-through-state-is-safe", {"package.json": PKG_NEXT, "components/Code.tsx": d("""
    'use client'
    import { codeToHtml } from 'shiki'
    export function Code({ code, log }) {
      const [html, setHtml] = useState('')
      const [bodies, setBodies] = useState(null)
      useEffect(() => { codeToHtml(code, { lang: 'ts', theme: 'nord' }).then((h) => setHtml(h)) }, [code])
      useEffect(() => { setBodies({ response: highlighter.codeToHtml(log.body, { lang: 'json' }) }) }, [log])
      return (
        <>
          <div dangerouslySetInnerHTML={{ __html: html }} />
          <div dangerouslySetInnerHTML={{ __html: bodies.response }} />
          <div dangerouslySetInnerHTML={{ __html: hljs.highlight(code, { language: 'js' }).value }} />
        </>
      )
    }
""")}, False)
case(R, "marked-with-sanitizing-hook-is-safe", {"package.json": PKG_NEXT, "components/Md.tsx": d("""
    import { marked } from 'marked'
    import DOMPurify from 'dompurify'
    marked.use({ breaks: true, hooks: { postprocess: (html) => DOMPurify.sanitize(html) } })
    export const Md = ({ text }) => <div dangerouslySetInnerHTML={{ __html: marked.parse(text) }} />
""")}, False)
case(R, "lazy-state-initializer-is-safe", {"package.json": PKG_NEXT, "components/Preview.tsx": d("""
    export function Preview({ initialHtml }) {
      const [preview] = useState(() => sanitizeEmailHtml(initialHtml))
      return <div dangerouslySetInnerHTML={{ __html: preview }} />
    }
""")}, False)
case(R, "map-over-literal-array-is-safe", {"package.json": PKG_NEXT, "emails/Wrapped.tsx": d("""
    export default function Wrapped() {
      const shipped = [
        { title: 'Links', description: 'Faster <strong>links</strong>' },
        { title: 'Domains', description: 'Free <em>domains</em>' },
      ]
      return shipped.map((item) => <p key={item.title} dangerouslySetInnerHTML={{ __html: item.description }} />)
    }
""")}, False)
case(R, "map-over-fetched-items-fires", {"package.json": PKG_NEXT, "app/feed/page.tsx": d("""
    export default async function Feed() {
      const items = await getItems()
      return items.map((item) => <p key={item.id} dangerouslySetInnerHTML={{ __html: item.description }} />)
    }
""")}, True, "high")
case(R, "mermaid-strict-is-safe", {"package.json": PKG_NEXT, "components/Diagram.tsx": d("""
    export function Diagram({ chart }) {
      const [svg, setSvg] = useState('')
      useEffect(() => {
        const run = async () => {
          const { svg: rendered } = await mermaid.render('d1', chart)
          setSvg(rendered)
        }
        run()
      }, [chart])
      return <div dangerouslySetInnerHTML={{ __html: svg }} />
    }
""")}, False)
case(R, "chart-style-constant-themes-is-safe", {"package.json": PKG_VITE, "src/components/ui/chart.tsx": d("""
    const THEMES = { light: '', dark: '.dark' } as const
    const ChartStyle = ({ id, config }) => {
      const colors = Object.entries(config).filter(([, c]) => c.color)
      return (
        <style dangerouslySetInnerHTML={{ __html: Object.entries(THEMES).map(([theme, prefix]) =>
          `${prefix} [data-chart=${id}] { ${colors.map(([key, c]) => `--color-${key}: ${c.color};`).join('')} }`).join('') }} />
      )
    }
""")}, False)
case(R, "lint-suppression-with-reason-is-low", {"package.json": PKG_NEXT, "components/Block.tsx": d("""
    export function Block({ block }) {
      // biome-ignore lint/security/noDangerouslySetInnerHtml: previewHtml is sanitized where the block is created
      return <div dangerouslySetInnerHTML={{ __html: block.previewHtml }} />
    }
""")}, True, "low")
case(R, "react-email-template-is-low", {"package.json": PKG_NEXT, "packages/email/src/templates/campaign.tsx": d("""
    import { Body, Html } from "@react-email/components";
    export default function CampaignEmail({ campaign }: { campaign: { body: string } }) {
      const styledHtml = `<div style="max-width: 100%;">${campaign.body}</div>`;
      return <Html><Body><div dangerouslySetInnerHTML={{ __html: styledHtml }} /></Body></Html>;
    }
""")}, True, "low")
case(R, "same-component-outside-an-email-template-stays-high", {"package.json": PKG_NEXT,
                                                                "components/Campaign.tsx": d("""
    export default function Campaign({ campaign }: { campaign: { body: string } }) {
      const styledHtml = `<div style="max-width: 100%;">${campaign.body}</div>`;
      return <div dangerouslySetInnerHTML={{ __html: styledHtml }} />;
    }
""")}, True, "high")

R = "upload-client-filename"
case(R, "promise-resolve-is-not-a-path", {"package.json": PKG_NODE, "lib/files.ts": d("""
    export function toAttachment(file: File) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader()
        reader.onload = () => { resolve({ name: file.name, url: reader.result, type: file.type }) }
        reader.onerror = reject
        reader.readAsDataURL(file)
      })
    }
    export function compress(file: File, blob: Blob) {
      return new Promise((resolve) => resolve(new File([blob], file.name.replace(/\\.[^.]+$/, '') + '.webp')))
    }
""")}, False)
case(R, "use-client-file-is-skipped", {"package.json": PKG_NEXT, "components/Upload.tsx": d("""
    'use client'
    export function Upload({ file }: { file: File }) {
      const target = path.join('uploads', file.name)
      return <span>{target}</span>
    }
""")}, False)
case(R, "ui-message-with-name-is-safe", {"package.json": PKG_NODE, "src/app/backup.service.ts": d("""
    export class BackupService {
      restore(backupFile: File) {
        this.snackBar.open('Backup restored from ' + backupFile.name, 'OK', { duration: 3000 })
      }
    }
""")}, False)
case(R, "bare-imported-join-fires", {"package.json": PKG_NODE, "server/up.js": d("""
    import { join } from 'node:path'
    import { writeFile } from 'node:fs/promises'
    app.post('/up', upload.single('f'), async (req, res) => {
      await writeFile(join(UPLOAD_DIR, req.file.originalname), req.file.buffer)
    })
""")}, True)
case(R, "laravel-move-is-medium", dict(LARAVEL, **{"app/Http/Controllers/U.php": d("""
    <?php
    $file = $request->file('doc');
    $file->move(public_path('docs'), $file->getClientOriginalName());
""")}), True, "medium")
case(R, "laravel-move-into-random-folder-is-safe", dict(LARAVEL, **{"app/Http/Controllers/U.php": d("""
    <?php
    $tmpDir = storage_path('tmp/' . Ulid::generate());
    return $request->file('song')->move($tmpDir, $request->file('song')->getClientOriginalName());
""")}), False)
case(R, "php-basename-keeps-extension", {"upload.php": d("""
    <?php
    $target = 'uploads/';
    $target .= basename($_FILES['uploaded']['name']);
    move_uploaded_file($_FILES['uploaded']['tmp_name'], $target);
""")}, True)
case(R, "php-basename-with-extension-allowlist-is-safe", {"upload.php": d("""
    <?php
    $name = basename($_FILES['uploaded']['name']);
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!in_array($ext, ['jpg', 'png'], true)) { exit; }
    move_uploaded_file($_FILES['uploaded']['tmp_name'], 'uploads/' . bin2hex(random_bytes(8)) . '.' . $ext);
""")}, False)

R = "upload-client-mime-check"
case(R, "php-type-through-variable", {"up.php": d("""
    <?php
    $type = $_FILES['uploaded']['type'];
    if ($type == 'image/jpeg' || $type == 'image/png') { move_uploaded_file($_FILES['uploaded']['tmp_name'], $dst); }
""")}, True)

R = "ssrf-request-url"
case(R, "imported-fixed-base-url-is-safe", {"package.json": PKG_NEXT, "lib/constants.ts": d("""
    export const FAVICON_URL = 'https://www.google.com/s2/favicons?sz=64&domain_url='
"""), "app/api/favicon/route.ts": d("""
    import { FAVICON_URL } from '@/lib/constants'
    export async function GET(req: NextRequest) {
      const domain = req.nextUrl.searchParams.get('domain')
      const r = await fetch(`${FAVICON_URL}${domain}`, { method: 'HEAD' })
      return new Response(null, { status: r.status })
    }
""")}, False)
case(R, "unresolved-base-url-is-medium", {"package.json": PKG_NEXT, "app/api/p/route.ts": d("""
    import { UPSTREAM } from '@acme/config'
    export async function GET(req: NextRequest) {
      const r = await fetch(`${UPSTREAM}${req.nextUrl.searchParams.get('path')}`)
      return r
    }
""")}, True, "medium")
case(R, "tanstack-server-fn-data", {"package.json": PKG_VITE, "src/lib/import.functions.ts": d("""
    export const importUrl = createServerFn({ method: 'POST' })
      .inputValidator(z.object({ url: z.string().url() }))
      .handler(async ({ data }) => {
        const res = await fetch(data.url)
        return res.text()
      })
""")}, True)
case(R, "zod-parsed-body", {"package.json": PKG_NODE, "server/preview.js": d("""
    app.post('/preview', async (req, res) => {
      const parsed = Body.safeParse(req.body)
      if (!parsed.success) return res.status(400).end()
      const r = await fetch(parsed.data.url)
      res.send(await r.text())
    })
""")}, True)
case(R, "hostname-regex-guard-is-medium", {"package.json": PKG_NODE, "server/preview.js": d("""
    function isPrivateHost(h) { return /^(localhost|127\\.|10\\.|192\\.168\\.)/.test(h) }
    app.post('/preview', async (req, res) => {
      const url = new URL(req.body.url)
      if (isPrivateHost(url.hostname)) return res.status(400).end()
      const r = await fetch(url.toString(), { redirect: 'follow' })
    })
""")}, True, "medium")
case(R, "guard-words-in-comments-do-not-count", {"package.json": PKG_NODE, "server/avatar.ts": d("""
    // TODO: add an allowlist later
    app.post('/avatar', async (req, res) => {
      req.app.locals.abused_ssrf_bug = true
      const url = req.body.imageUrl
      const r = await fetch(url)
    })
""")}, True)

R = "sqli-js-string-query"
case(R, "loop-over-constant-tuples-is-safe", {"package.json": PKG_NODE, "src/index.ts": d("""
    export async function createTriggers(tx) {
      for (const [event, rows] of [['INSERT', ['NEW']], ['DELETE', ['OLD']]] as const) {
        const target = rows[0]
        await tx.exec(`CREATE TRIGGER t_after_${event.toLowerCase()} AFTER ${event} ON items BEGIN SELECT 1 FROM t WHERE id = ${target}.id; END`)
      }
    }
""")}, False)
case(R, "query-config-name-and-values-are-safe", {"package.json": PKG_NODE, "src/db.js": d("""
    async function count(key, q) {
      const res = await pool.query({
        name: `countLex${q.suffix}`,
        text: `SELECT COUNT(*) FROM items WHERE key = $1`,
        values: [key],
      })
      return res.rows[0]
    }
""")}, False)
case(R, "query-config-text-from-request-fires", {"package.json": PKG_NODE, "server/a.js": d("""
    app.get('/a', async (req, res) => {
      const r = await pool.query({ text: `SELECT * FROM items WHERE name = '${req.query.name}'` })
    })
""")}, True, "critical")
case(R, "custom-query-wrapper", {"package.json": PKG_NODE, "pages/api/posts.js": d("""
    export default async function handler(req, res) {
      const { search } = req.query
      let query = 'SELECT * FROM posts'
      query += ` WHERE title LIKE '%${search}%'`
      res.json(await runQuery(query))
    }
""")}, True, "critical")
case(R, "statement-built-from-request", {"package.json": PKG_NODE, "pages/api/p.js": d("""
    export default async function handler(req, res) {
      const sql = `SELECT * FROM users WHERE id = ${req.query.id}`
      res.json(await store.fetchAll(sql))
    }
""")}, True, "critical")
case(R, "postgrest-or-with-own-user-id-is-safe", {"package.json": PKG_NEXT, "app/api/m/route.ts": d("""
    export async function GET() {
      const { data: { user } } = await supabase.auth.getUser()
      const { data } = await supabase.from('messages').select().or(`sender_id.eq.${user.id},receiver_id.eq.${user.id}`)
      return Response.json(data)
    }
""")}, False)
case(R, "postgrest-or-in-browser-is-low", {"package.json": PKG_VITE, "src/pages/Search.tsx": d("""
    'use client'
    export function Search() {
      const [searchParams] = useSearchParams()
      const q = searchParams.get('q')
      useEffect(() => { supabase.from('items').select().or(`name.ilike.%${q}%,tag.ilike.%${q}%`) }, [q])
    }
""")}, True, "low")
case(R, "postgrest-or-after-webhook-signature-is-safe", {"package.json": PKG_NODE, "supabase/functions/hook/index.ts": d("""
    Deno.serve(async (req) => {
      const raw = await req.text()
      const sig = hmac('sha256', Deno.env.get('SECRET'), raw, 'utf8', 'hex')
      if (sig !== req.headers.get('x-signature')) return new Response('bad', { status: 401 })
      const event = JSON.parse(raw)
      await admin.from('refunds').update({ done: true }).or(`id.is.null,ref.eq.${event.payload.ref}`)
    })
""")}, False)

R = "sqli-prisma-raw-unsafe"
case(R, "typed-number-limit-is-safe", {"package.json": PKG_NODE, "src/stats.ts": d("""
    type Options = { limit: number | null }
    export async function stats(options: Options) {
      const limitClause = options.limit ? `LIMIT ${options.limit}` : ''
      return prisma.$queryRaw`SELECT * FROM stats ${Prisma.raw(limitClause)}`
    }
""")}, False)

R = "sqli-php-string-query"
case(R, "vendored-and-identifier-names-are-safe", {"libs/picodb/Driver/Mysql.php": d("""
    <?php
    $this->pdo->exec('INSERT INTO `'.$this->schemaTable.'` VALUES(0)');
"""), "src/Schema.php": d("""
    <?php
    $this->pdo->exec('INSERT INTO ' . $this->schemaTable . ' VALUES(0)');
"""), "lib/mailer/Mailer.php": "<?php\n/**\n * @license LGPL\n */\n$db->query('SELECT * FROM t WHERE id = ' . $id);\n"}, False)
case(R, "strict-validation-is-safe", {"bac.php": d("""
    <?php
    if (!preg_match('/^\\d+$/', $_GET['user_id'])) {
        die('bad id');
    } else {
        $id = $_GET['user_id'];
        $result = mysqli_query($conn, "SELECT * FROM users WHERE user_id = '$id'");
    }
    $threshold = time() + 60;
    $rows = $pdo->query('SELECT * FROM feeds WHERE checked < ' . $threshold);
    $order = in_array($_GET['order'], ['ASC', 'DESC'], true) ? $_GET['order'] : 'DESC';
    $sort = match ($_GET['sort']) { 'date' => 'e.date', default => 'e.id' };
    $rows = $pdo->query('SELECT * FROM entries ORDER BY ' . $sort . ' ' . $order);
""")}, False)
case(R, "unvalidated-still-fires", {"bac.php": d("""
    <?php
    if (!preg_match('/^\\d+$/', $_GET['page'])) { die('bad page'); }
    $id = $_GET['user_id'];
    $result = mysqli_query($conn, "SELECT * FROM users WHERE user_id = '$id'");
""")}, True, "critical")

R = "cmdi-php-shell"
case(R, "numeric-octets-are-safe", {"ping.php": d("""
    <?php
    $target = $_REQUEST['ip'];
    $octet = explode('.', $target);
    if (is_numeric($octet[0]) && is_numeric($octet[1]) && is_numeric($octet[2]) && is_numeric($octet[3])) {
        $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
        $cmd = shell_exec('ping -c 4 ' . $target);
    }
""")}, False)
case(R, "vendored-library-is-skipped", {"lib/phpmailer/src/Mailer.php": d("""
    <?php
    /**
     * @license LGPL-2.1
     */
    $mail = @popen($sendmail . ' -f' . $sender, 'w');
""")}, False)

R = "path-traversal-request"
case(R, "php-ctype-guard-is-safe", {"api/keys.php": d("""
    <?php
    $key = $_GET['k'] ?? '';
    if (!ctype_xdigit($key)) {
        header('HTTP/1.1 422 Unprocessable Entity');
        die('bad key');
    }
    $data = file_get_contents('keys/' . $key . '.txt');
""")}, False)
case(R, "zip-slip-entry-path", {"package.json": PKG_NODE, "routes/upload.ts": d("""
    import unzipper from 'unzipper'
    import fs from 'fs'
    export function extract(buffer) {
      fs.createReadStream(buffer).pipe(unzipper.Parse()).on('entry', (entry) => {
        const fileName = entry.path
        entry.pipe(fs.createWriteStream('uploads/complaints/' + fileName))
      })
    }
""")}, True)
case(R, "zip-slip-checked-is-safe", {"package.json": PKG_NODE, "routes/upload.ts": d("""
    import unzipper from 'unzipper'
    import fs from 'fs'
    export function extract(stream, dest) {
      stream.pipe(unzipper.Parse()).on('entry', (entry) => {
        const target = path.resolve(dest, entry.path)
        if (!target.startsWith(dest + path.sep)) return entry.autodrain()
        entry.pipe(fs.createWriteStream(target))
      })
    }
""")}, False)
case(R, "tar-extractall-without-filter", dict(FLASK, **{"app.py": d("""
    import tarfile
    @app.post("/import")
    def import_bundle():
        with tarfile.open(fileobj=request.files["bundle"].stream) as tar:
            tar.extractall("data/imports")
        return "ok"
""")}), True)
case(R, "tar-extractall-with-filter-is-safe", dict(FLASK, **{"app.py": d("""
    import tarfile
    @app.post("/import")
    def import_bundle():
        with tarfile.open(fileobj=request.files["bundle"].stream) as tar:
            tar.extractall("data/imports", filter="data")
        return "ok"
""")}), False)

R = "nosqli-request-filter"
case(R, "key-value-helpers-are-not-mongo", {"package.json": PKG_MONGO, "src/controllers/admin.js": d("""
    async function check(req, res) {
      const exists = await posts.exists(req.body.id)
      await blocklist.remove(req.body.domain)
      const ok = await file.exists(req.query.folder)
    }
""")}, False)
case(R, "legacy-collection-update", {"package.json": '{"dependencies": {"express": "^4.19.0", "marsdb": "^0.6.11"}}',
                                     "routes/reviews.ts": d("""
    export function update(req, res) {
      db.reviewsCollection.update({ _id: req.body.id }, { $set: { message: req.body.message } }, { multi: true })
    }
""")}, True)
case(R, "where-built-in-helper", {"package.json": PKG_MONGO, "app/data/allocations-dao.js": d("""
    function searchCriteria(userId, threshold) {
      return { $where: `this.userId == ${userId} && this.stocks > '${threshold}'` }
    }
    allocations.find(searchCriteria(userId, threshold)).toArray(callback)
""")}, True, "high")
case(R, "sequelize-where-is-safe", {"package.json": '{"dependencies": {"express": "^4.19.0", "sequelize": "^6.0.0", "marsdb": "^0.6.11"}}',
                                    "routes/order.ts": d("""
    const wallet = await WalletModel.findOne({ where: { UserId: req.body.UserId } })
""")}, False)
case(R, "sanitize-filter-on-old-mongoose-is-medium", {"package.json": PKG_MONGO, "db.js": "mongoose.set('sanitizeFilter', true)\n",
                                                     "routes/a.js": "const u = await User.findOne({ email: req.body.email })\n"},
     True, "medium")
case(R, "mongo-sanitize-on-express4-is-skipped", {"package.json": '{"dependencies": {"express": "^4.19.0", "mongoose": "^8.9.5", "express-mongo-sanitize": "^2.2.0"}}',
                                                 "app.js": "const mongoSanitize = require('express-mongo-sanitize')\napp.use(mongoSanitize())\n",
                                                 "routes/a.js": "const u = await User.findOne({ email: req.body.email })\n"}, False)
case(R, "mongo-sanitize-listed-but-unused-still-fires", {"package.json": '{"dependencies": {"express": "^4.19.0", "mongoose": "^8.9.5", "express-mongo-sanitize": "^2.2.0"}}',
                                                         "routes/a.js": "const u = await User.findOne({ email: req.body.email })\n"}, True)

R = "cmdi-node-shell"
case(R, "member-require-form", {"package.json": PKG_NODE, "core/handler.js": d("""
    const exec = require('child_process').exec
    module.exports.ping = function (req, res) {
      exec('ping -c 2 ' + req.body.address, function (err, stdout) { res.send(stdout) })
    }
""")}, True, "critical")

R = "cmdi-python-shell"
case(R, "click-argument-is-operator-input", dict(FLASK, **{"app/cli.py": d("""
    import os
    import click
    @translate.command()
    @click.argument('lang')
    def init(lang):
        if os.system('pybabel init -i messages.pot -d app/translations -l ' + lang):
            raise RuntimeError('init failed')
""")}), False)

R = "cmdi-code-eval"
case(R, "pickle-from-form", dict(FLASK, **{"app.py": d("""
    import base64, pickle
    @app.post("/restore")
    def restore():
        data = pickle.loads(base64.b64decode(request.form.get("blob")))
        return str(data)
""")}), True, "critical")
case(R, "yaml-load-on-old-pyyaml", dict(FLASK, **{"requirements.txt": "flask==3.1.0\nPyYAML==3.12\n", "app.py": d("""
    import yaml
    @app.post("/import")
    def import_rules():
        path = save_upload(request.files["rules"])
        with open(path) as fh:
            return str(yaml.load(fh))
""")}), True, "high")
case(R, "yaml-load-unpinned-is-medium", dict(FLASK, **{"app.py": d("""
    import yaml
    def read_config(path):
        with open(path) as fh:
            return yaml.load(fh)
""")}), True, "medium")
case(R, "yaml-safe-loaders-are-safe", dict(FLASK, **{"requirements.txt": "flask==3.1.0\nPyYAML>=6.0.1\n", "app.py": d("""
    import yaml
    def read_config(text):
        a = yaml.safe_load(text)
        b = yaml.load(text, Loader=yaml.SafeLoader)
        c = yaml.load(text)
        return a, b, c
""")}), False)
case(R, "yaml-unsafe-loader-is-reported", dict(FLASK, **{"requirements.txt": "flask==3.1.0\nPyYAML>=6.0.1\n", "app.py": d("""
    import yaml
    @app.post("/import")
    def imp():
        return str(yaml.load(request.files["f"].read(), Loader=yaml.UnsafeLoader))
""")}), True, "critical")
case(R, "node-serialize", {"package.json": PKG_NODE, "core/products.js": d("""
    const serialize = require('node-serialize')
    module.exports.importProducts = function (req, res) {
      const products = serialize.unserialize(req.files.products.data.toString('utf8'))
    }
""")}, True, "critical")
case(R, "php-unserialize-cookie", {"cart.php": "<?php\n$cart = unserialize($_COOKIE['cart']);\n"}, True, "critical")
case(R, "php-unserialize-no-classes-is-medium", {"cart.php": "<?php\n$cart = unserialize($_COOKIE['cart'], ['allowed_classes' => false]);\n"}, True, "medium")
case(R, "ssti-from-request-url", dict(FLASK, **{"app.py": d("""
    @app.errorhandler(404)
    def not_found(e):
        template = '<h3>%s not found</h3>' % request.url
        return render_template_string(template), 404
""")}), True)

R = "xss-framework-raw-html"
case(R, "ejs-raw-output", {"package.json": PKG_NODE, "views/products.ejs": d("""
    <%- include('header') %>
    <p>Results for <%- output.searchTerm %></p>
    <p><%= output.safe %></p>
""")}, True)
case(R, "ejs-include-only-is-safe", {"package.json": PKG_NODE, "views/a.ejs": "<%- include('header') %>\n<p><%= name %></p>\n"}, False)
case(R, "handlebars-triple", {"package.json": PKG_NODE, "views/post.hbs": "<div>{{{post.body}}}</div>\n"}, True)
case(R, "swig-autoescape-off", {"package.json": PKG_NODE, "server.js": d("""
    const swig = require('swig')
    swig.setDefaults({ autoescape: false })
""")}, True)
case(R, "vue-member-assigned-sanitized-is-safe", {"package.json": '{"dependencies": {"vue": "^3.5.0"}}', "src/Podcast.vue": d("""
    <template><div v-html="description.content"></div></template>
    <script setup>
    import DOMPurify from 'dompurify'
    const description = reactive({ content: '' })
    watch(podcast, () => { description.content = DOMPurify.sanitize(podcast.value?.description || '') })
    </script>
""")}, False)
case(R, "vue-with-server-purifier-is-medium", {"composer.json": '{"require": {"laravel/framework": "^11.0", "ezyang/htmlpurifier": "^4.17"}}',
                                               "package.json": '{"dependencies": {"vue": "^3.5.0"}}',
                                               "resources/js/AlbumInfo.vue": d("""
    <template><div v-html="info.wiki.full"></div></template>
    <script setup>
    const props = defineProps(['info'])
    </script>
""")}, True, "medium")

R = "xss-dom-innerhtml"
case(R, "docs-site-is-skipped", {"docs/assets/js/docs.js": "el.insertAdjacentHTML('beforeend', `<b>${i18n.copy}</b>`)\n"}, False)
case(R, "jquery-plugin-with-copyright-banner-is-skipped", {"static/js/jquery.sparkline.js": d("""
    /**
     * jquery.sparkline.js v2.1.2
     * (c) Example, Inc
     * License: New BSD License
     */
    this.group.innerHTML = this.prerender
""")}, False)
case(R, "own-ajax-fragment-is-low", {"static/js/details.js": d("""
    $.ajax({ url: statusUrl, dataType: 'json', success: function (data) {
        $('#log').html(data.events)
        for (var i = 0, el; (el = data.details[i]); i++) {
            $('#' + el.code + ' .last-ping').html(el.last_ping)
        }
    } })
""")}, True, "low")

R = "xss-blade-unescaped"
case(R, "escaping-helpers-and-form-builders-are-safe", dict(LARAVEL, **{"resources/views/s.blade.php": d("""
    <script>var query = "{!! escape_for_js($query) !!}";</script>
    {!! ExpandedForm::text('name', $name) !!}
    {!! Form::open(['route' => 'x']) !!}
""")}), False)
case(R, "project-helper-is-reported-once-and-low", dict(LARAVEL, **{
    "app/Support/helpers.php": d("""
        <?php
        function format_amount($amount) {
            return sprintf('<span class="money">%s</span>', e(number_format($amount, 2)));
        }
    """),
    "resources/views/a.blade.php": "<td>{!! format_amount($a) !!}</td>\n<td>{!! format_amount($b) !!}</td>\n",
}), True, "low")
case(R, "escaping-markdown-helper-is-safe", dict(LARAVEL, **{
    "app/Support/helpers.php": d("""
        <?php
        function parse_markdown(string $text): string {
            $converter = new GithubFlavoredMarkdownConverter(['allow_unsafe_links' => false, 'html_input' => 'escape']);
            return (string) $converter->convert($text);
        }
    """),
    "resources/views/n.blade.php": "<div>{!! parse_markdown($note->text) !!}</div>\n",
}), False)
case(R, "json-encode-in-attribute", dict(LARAVEL, **{"resources/views/j.blade.php": "<div data-user=\"{!! json_encode($user) !!}\"></div>\n"}),
     True, "medium")

R = "xss-python-template-safe"
case(R, "plain-text-templates-are-safe", {"manage.py": "", "templates/emails/alert-body-text.html": "{{ check.name|safe }} is down\n",
                                          "templates/sms_message.html": "{{ check.name|safe }} is {{ check.status }}\n"}, False)
case(R, "html-email-still-fires", {"manage.py": "", "templates/emails/alert-body-html.html": "<p>{{ check.name|safe }} is down</p>\n"},
     True)
case(R, "html-email-is-low", {"manage.py": "", "templates/emails/alert-body-html.html": "<p>{{ check.name|safe }} is down</p>\n"},
     True, "low")
case(R, "same-markup-in-a-page-is-high", {"manage.py": "", "templates/front/alert.html": "<p>{{ check.name|safe }} is down</p>\n"},
     True, "high")
case(R, "constant-cycle-and-escaped-mark-safe-are-safe", {"manage.py": "", "templates/t.html": d("""
    <table><tr>{% for c in checks %}<td>{{ c.name }}</td>{% cycle '' '</tr><tr>' as trtr silent %}{{ trtr|safe }}{% endfor %}</tr></table>
"""), "app/tags.py": d("""
    from django.utils.html import escape
    from django.utils.safestring import mark_safe
    def hc_mark(s):
        escaped = str(escape(s))
        return mark_safe(escaped.replace('*', '<b>'))
"""), "app/helpers.py": d("""
    from typing import Literal
    from markupsafe import Markup
    def time_tag(when, what: Literal['date', 'time']):
        return Markup(f'<time data-what="{what}">{when.isoformat()}</time>')
""")}, False)

R = "xss-reflected-response"
case(R, "php-html-built-into-variable", {"xss.php": d("""
    <?php
    if (array_key_exists('name', $_GET) && $_GET['name'] != NULL) {
        $html .= '<pre>Hello ' . $_GET['name'] . '</pre>';
    }
""")}, True, "medium")

R = "ssrf-next-image-any-host"
case(R, "local-ip-allowed", {"package.json": PKG_NEXT, "next.config.ts": d("""
    const config = { images: { dangerouslyAllowLocalIP: true, remotePatterns: [{ hostname: 'cdn.example.com' }] } }
    export default config
""")}, True)


R = "sqli-php-string-query"
case(R, "plugin-with-license-docblock-still-fires", {"wp-content/plugins/notes/notes.php": d("""
    <?php
    /**
     * Plugin Name: Notes
     * @license GPL-2.0+
     * @copyright 2026 Example
     */
    $rows = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}notes WHERE author = '" . $_GET['author'] . "'");
""")}, True, "critical")

R = "sqli-js-string-query"
case(R, "prose-is-not-a-statement", {"package.json": PKG_NODE, "server/msg.js": d("""
    app.get('/pick', (req, res) => {
      const note = `Select a file from your disk, ${req.query.name}`
      res.json({ note })
    })
""")}, False)

R = "cmdi-code-eval"
case(R, "yaml-of-a-named-file-is-safe", dict(FLASK, **{"app.py": d("""
    import yaml
    def settings():
        with open("config/settings.yml") as fh:
            return yaml.load(fh)
""")}), False)
case(R, "old-js-yaml-on-named-file-is-safe", {"package.json": '{"dependencies": {"express": "^4.19.0", "js-yaml": "3.14.1"}}',
                                              "server.js": d("""
    const yaml = require('js-yaml')
    const doc = yaml.load(fs.readFileSync('./swagger.yml', 'utf8'))
""")}, False)
case(R, "old-js-yaml-on-request-body", {"package.json": '{"dependencies": {"express": "^4.19.0", "js-yaml": "3.14.1"}}',
                                        "server/import.js": d("""
    const yaml = require('js-yaml')
    app.post('/import', (req, res) => res.json(yaml.load(req.body.doc)))
""")}, True, "critical")

R = "xss-react-dangerous-html"
case(R, "state-set-from-fetched-data-stays-high", {"package.json": PKG_NEXT, "components/Post.tsx": d("""
    'use client'
    export function Post({ id }) {
      const [html, setHtml] = useState('')
      useEffect(() => { fetch('/api/posts/' + id).then((r) => r.json()).then((data) => setHtml(data.body)) }, [id])
      return <div dangerouslySetInnerHTML={{ __html: html }} />
    }
""")}, True, "high")


R = "path-traversal-request"
case(R, "python-zip-member-names", dict(FLASK, **{"app.py": d("""
    import os, zipfile
    @app.post("/import")
    def import_zip():
        with zipfile.ZipFile(request.files["bundle"].stream) as zf:
            for info in zf.infolist():
                with open(os.path.join("data", info.filename), "wb") as out:
                    out.write(zf.read(info))
        return "ok"
""")}), True)
case(R, "python-zip-member-checked-is-safe", dict(FLASK, **{"app.py": d("""
    import os, zipfile
    @app.post("/import")
    def import_zip():
        with zipfile.ZipFile(request.files["bundle"].stream) as zf:
            for info in zf.infolist():
                target = os.path.realpath(os.path.join(DEST, info.filename))
                if not target.startswith(DEST + os.sep):
                    abort(400)
                with open(target, "wb") as out:
                    out.write(zf.read(info))
        return "ok"
""")}), False)

R = "sqli-js-string-query"
case(R, "sort-filled-by-literal-callers-is-safe", {"package.json": PKG_NODE, "src/database/sorted.js": d("""
    async function getRank(sort, key, value) {
      const res = await pool.query({
        name: `rank${sort}`,
        text: `SELECT COUNT(*) FROM items WHERE key = $1 AND score < $2 ORDER BY score ${sort}`,
        values: [key, value],
      })
      return res.rows[0]
    }
    module.sortedSetRank = async (key, value) => getRank('ASC', key, value)
    module.sortedSetRevRank = async (key, value) => getRank('DESC', key, value)
""")}, False)

R = "xss-react-dangerous-html"
case(R, "mermaid-loose-is-medium", {"package.json": PKG_NEXT, "components/Diagram.tsx": d("""
    export function Diagram({ chart }) {
      const [svg, setSvg] = useState('')
      useEffect(() => {
        mermaid.initialize({ startOnLoad: false, securityLevel: 'loose' })
        mermaid.render('d1', chart).then(({ svg: out }) => setSvg(out))
      }, [chart])
      return <div dangerouslySetInnerHTML={{ __html: svg }} />
    }
""")}, True, "medium")

R = "xss-python-template-safe"
case(R, "jinja-environment-autoescape-off", dict(FLASK, **{"app/render.py": d("""
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader("templates"), autoescape=False)
""")}), True, "medium")

R = "xss-framework-raw-html"
case(R, "pug-unescaped", {"package.json": PKG_NODE, "views/post.pug": "article\n  h1= post.title\n  div!= post.body\n"}, True)
case(R, "nunjucks-safe-filter", {"package.json": PKG_NODE, "views/post.njk": "<div>{{ post.body | safe }}</div>\n"}, True)

R = "xss-reflected-response"
case(R, "express-original-url", {"package.json": PKG_NODE, "server/404.js": d("""
    app.use((req, res) => res.status(404).send(`<p>No page at ${req.originalUrl}</p>`))
""")}, True)


R = "cmdi-node-shell"
case(R, "ts-import-require-and-member-alias", {"package.json": PKG_NODE, "src/ping.ts": d("""
    import cp = require('child_process')
    const run = cp.exec
    export function ping(req, res) {
      run('ping -c 1 ' + req.query.host, (err, out) => res.send(out))
    }
""")}, True, "critical")

R = "nosqli-request-filter"
case(R, "mongo-sanitize-on-express5-still-fires", {"package.json": '{"dependencies": {"express": "^5.1.0", "mongoose": "^8.9.5", "express-mongo-sanitize": "^2.2.0"}}',
                                                  "app.js": "const mongoSanitize = require('express-mongo-sanitize')\napp.use(mongoSanitize())\n",
                                                  "routes/a.js": "const u = await User.findOne({ email: req.body.email })\n"}, True)


R = "ssrf-request-url"
case(R, "resolved-check-with-redirects-on-is-medium", {"package.json": PKG_NODE, "server/preview.js": d("""
    const dns = require('node:dns/promises')
    app.post('/preview', async (req, res) => {
      const url = new URL(req.body.url)
      const { address } = await dns.lookup(url.hostname)
      if (isPrivateIp(address)) return res.status(400).end()
      const r = await fetch(url, { redirect: 'follow' })
    })
""")}, True, "medium")
case(R, "resolved-check-without-redirects-is-safe", {"package.json": PKG_NODE, "server/preview.js": d("""
    const dns = require('node:dns/promises')
    app.post('/preview', async (req, res) => {
      const url = new URL(req.body.url)
      const { address } = await dns.lookup(url.hostname)
      if (isPrivateIp(address)) return res.status(400).end()
      const r = await fetch(url, { redirect: 'error' })
    })
""")}, False)


@pytest.mark.parametrize("rule,files,fires,severity", CASES)
def test_rule_cases(tmp_path, write_tree, scan_rules, rule, files, fires, severity):
    found = run(tmp_path, write_tree, scan_rules, files, rule)
    if fires:
        assert found, "expected %s to fire" % rule
        if severity:
            assert found[0].severity == severity, [(f.severity, f.message) for f in found]
        for f in found:
            assert f.line > 0 and f.file and f.message and f.fix_ref
    else:
        assert not found, [(f.file, f.line, f.message) for f in found]


def test_every_rule_has_a_firing_and_a_quiet_case():
    firing = {p.values[0] for p in CASES if p.values[2]}
    quiet = {p.values[0] for p in CASES if not p.values[2]}
    assert set(RULE_IDS) <= firing
    assert set(RULE_IDS) <= quiet


def _slug(heading: str) -> str:
    s = heading.strip().lower()
    s = re.sub(r"[^\w\- ]", "", s)
    return s.replace(" ", "-")


def _anchors(path: Path):
    text = path.read_text(encoding="utf-8")
    return {_slug(m.group(1)) for m in re.finditer(r"(?m)^#{1,6}\s+(.+?)\s*$", text)}


def test_fix_refs_point_at_real_headings():
    # a bare file name: this skill's references first, then secure-by-default's
    dirs = (REFS / "preflight-audit" / "references", REFS / "secure-by-default" / "references")
    for r in inj.RULES:
        target, _, anchor = r.fix_ref.partition("#")
        assert "/" not in target and anchor, (r.id, r.fix_ref)
        path = next((dd / target for dd in dirs if (dd / target).is_file()), None)
        assert path is not None, (r.id, r.fix_ref)
        assert anchor in _anchors(path), (r.id, r.fix_ref)


def test_stack_python_has_the_anchors_other_modules_use():
    # deploy rules point at stack-python.md too
    import _rules_deploy
    path = REFS / "preflight-audit" / "references" / "stack-python.md"
    anchors = _anchors(path)
    for r in list(inj.RULES) + list(_rules_deploy.RULES):
        target, _, anchor = r.fix_ref.partition("#")
        if target == "stack-python.md":
            assert anchor in anchors, (r.id, r.fix_ref)


def test_reference_files_are_clean():
    for path in (REFS / "secure-by-default" / "references" / "uploads-and-fetch.md",
                 REFS / "preflight-audit" / "references" / "stack-python.md"):
        text = path.read_text(encoding="utf-8")
        assert EM not in text and EN not in text
        assert text.rstrip().endswith("LAST-VERIFIED: 2026-10-06")
        assert len(text.splitlines()) <= 215
        assert "\r" not in text


def test_rule_metadata():
    for r in inj.RULES:
        assert re.match(r"^(?:sqli|nosqli|cmdi|xss|upload|path|ssrf)-[a-z0-9-]+$", r.id), r.id
        assert r.skill == "injection"
        assert r.why and r.fp_trap and r.message and r.fix_ref
        assert r.confidence in ("high", "medium", "low")
        for text in (r.message, r.why, r.fp_trap):
            assert EM not in text and EN not in text


def test_rules_load_cleanly():
    import scan_app
    rules, warnings = scan_app.load_rules(["_rules_injection"])
    assert not warnings
    assert sorted(r.id for r in rules) == sorted(RULE_IDS)


def test_rules_skip_other_stacks(tmp_path, write_tree, scan_rules):
    # a Node project with a Jinja-looking file, and a Python project with React code
    write_tree(tmp_path / "n", {"package.json": PKG_NODE, "templates/a.html": "{{ x|safe }}\n"})
    assert scan_rules(tmp_path / "n", rule_ids=["xss-python-template-safe"]).findings == []
    write_tree(tmp_path / "p", {"requirements.txt": "flask\n",
                                "web/a.tsx": "export const A = ({ h }) => <div dangerouslySetInnerHTML={{ __html: h }} />\n"})
    assert scan_rules(tmp_path / "p", rule_ids=["xss-react-dangerous-html", "sqli-js-string-query"]).findings == []
    # the same files are reported once the stack is forced
    assert scan_rules(tmp_path / "n", rule_ids=["xss-python-template-safe"], stacks="+python").findings


ODD_INPUTS = [
    "const a = `unterminated ${x",
    "x = f'{",
    "<?php $a = \"$b",
    "'''",
    "/* never closed",
    "<script>el.innerHTML = `${a.b`</script>",
    "query(" * 200,
    "a = (" + "1 + " * 500 + "1)",
    "\x00\x01 binary-ish",
]


@pytest.mark.parametrize("body", ODD_INPUTS)
def test_odd_inputs_do_not_crash(tmp_path, write_tree, scan_rules, body):
    write_tree(tmp_path, {"package.json": PKG_NODE, "a.js": body, "a.py": body, "a.php": body, "a.vue": body,
                          "a.html": body, "a.blade.php": body, "next.config.js": body + " remotePatterns"})
    res = scan_rules(tmp_path, rule_ids=RULE_IDS, stacks="all")
    assert not [w for w in res.warnings if "failed" in str(w)], res.warnings


def test_blade_project_helper_is_reported_once(tmp_path, write_tree, scan_rules):
    files = dict(LARAVEL, **{
        "app/Support/helpers.php": "<?php\nfunction badge($x) { return '<b>' . $x . '</b>'; }\n",
        "resources/views/a.blade.php": "{!! badge($a) !!}\n{!! badge($b) !!}\n",
        "resources/views/b.blade.php": "{!! badge($c) !!}\n",
    })
    found = run(tmp_path, write_tree, scan_rules, files, "xss-blade-unescaped")
    assert len(found) == 1 and found[0].severity == "medium", [(f.file, f.line, f.severity) for f in found]


def test_ajax_fragments_are_low_also_in_list_loops(tmp_path, write_tree, scan_rules):
    files = {"static/js/checks.js": d("""
        $.ajax({ url: '/checks/status/', dataType: 'json', success: function (data) {
            $('#summary').html(data.summary)
            for (var i = 0, el; (el = data.details[i]); i++) {
                $('#' + el.code + ' .last-ping').html(el.last_ping)
            }
        } })
    """)}
    found = run(tmp_path, write_tree, scan_rules, files, "xss-dom-innerhtml")
    assert len(found) == 2 and {f.severity for f in found} == {"low"}, [(f.line, f.severity) for f in found]


def test_vendored_php_needs_a_library_folder():
    banner = "<?php\n/**\n * @license MIT\n */\n"
    assert inj._vendored(banner, "lib/phpmailer/src/PHPMailer.php")
    assert not inj._vendored(banner, "wp-content/plugins/notes/notes.php")
    assert inj._vendored("/*! lib v1 */\n", "public/js/app.js")
