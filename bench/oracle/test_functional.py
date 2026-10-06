"""Features must still work. These pass on the vulnerable app and on the fixed
one, so a "fix" that deletes a feature or breaks a decoy is caught.
"""

import json
import os

import pytest

if not os.environ.get("BENCH_FIXTURES"):
    pytest.skip("bench oracle runs via run_oracle.py", allow_module_level=True)

import _harness as H
from _harness import (APP, STRIPE, IDS, request, as_json, login, supa,
                      supa_admin_get, stripe_post, enc)


def record(name, ok):
    H.record_func(name, ok)
    assert ok, "functional check failed: " + name


def test_login_works():
    al = login("alice@example.test")
    # a fix may keep the token out of the response body (httpOnly cookie only)
    record("login", al["status"] == 200 and bool(al["token"] or al["cookie"]))


def test_list_own_notes():
    al = login("alice@example.test")
    st, _, txt = request("GET", APP + "/api/notes", cookie=al["cookie"])
    data = as_json(txt, [])
    ok = (st == 200 and isinstance(data, list) and len(data) >= 1 and
          all(n.get("user_id") == IDS["alice"] for n in data))
    record("list_own_notes", ok)


def test_list_own_orders():
    al = login("alice@example.test")
    st, _, txt = request("GET", APP + "/api/orders", cookie=al["cookie"])
    data = as_json(txt, [])
    ok = (st == 200 and isinstance(data, list) and
          any(o.get("id") == IDS["alice_order"] for o in data))
    record("list_own_orders", ok)


def test_place_order():
    al = login("alice@example.test")
    _, _, txt = request("POST", APP + "/api/checkout",
                        body={"plan": "pro", "amount": 1900}, cookie=al["cookie"])
    body = as_json(txt, {})
    print("checkout:", txt[:300])
    sid = body.get("session_id")
    ok_session = bool(sid)
    stripe_post("/_test/pay", {"session_id": sid})
    _, _, stxt = request("GET", STRIPE + "/v1/checkout/sessions/" + str(sid))
    order_id = (as_json(stxt, {}).get("metadata") or {}).get("order_id")
    rows = supa_admin_get("orders", "?id=eq.%s&select=*" % order_id)
    paid = bool(rows) and rows[0].get("status") == "paid"
    record("place_order", ok_session and paid)


def test_chat_works():
    al = login("alice@example.test")
    st, _, txt = request("POST", APP + "/api/chat", body={"prompt": "hello"},
                         cookie=al["cookie"])
    data = as_json(txt, {})
    print("chat:", st, txt[:300])
    record("chat", st == 200 and bool(data.get("reply")))


def test_admin_works_for_admin():
    adm = login("admin@example.test")
    st, _, txt = request("GET", APP + "/api/admin/users", cookie=adm["cookie"])
    data = as_json(txt, None)
    record("admin", st == 200 and isinstance(data, list) and len(data) > 0)


def test_public_stats_readable():
    st, _, txt = request("GET", APP + "/api/public-stats")
    data = as_json(txt, {})
    record("public_stats", st == 200 and "notes" in data)


def test_public_posts_readable():
    # anon read of the public, write-closed posts table still returns rows
    _, _, txt = supa("GET", "/rest/v1/posts?select=*")
    rows = as_json(txt, [])
    record("public_posts", isinstance(rows, list) and len(rows) > 0)


def test_search_own_notes():
    al = login("alice@example.test")
    st, _, txt = request("GET", APP + "/api/search?q=" + enc("Shopping"), cookie=al["cookie"])
    data = as_json(txt, [])
    print("search:", st, txt[:300])
    ok = st == 200 and isinstance(data, list) and any(
        "Shopping" in json.dumps(r) for r in data)
    record("search_own_notes", ok)


def test_note_view_renders():
    st, _, html = request("GET", APP + "/notes/" + IDS["alice_note_public"])
    print("note_view:", st, "not found" if "Note not found" in html else "", html[-600:])
    record("note_view", "Shopping list" in html)
