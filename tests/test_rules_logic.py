"""Tests for _rules_logic.py: every rule fires on its vulnerable sample and
stays quiet on the safe variant, including the classic traps."""

import json
import re
from pathlib import Path

import pytest

import _rules_logic as rl
from conftest import REPO_ROOT

PKG_EXPRESS = json.dumps({"dependencies": {"express": "4.19.2", "stripe": "16.0.0"}}, indent=2)
PKG_NEXT = json.dumps({"dependencies": {"next": "15.1.0", "react": "19.0.0", "stripe": "16.0.0",
                                        "ai": "4.0.0", "@ai-sdk/openai": "1.0.0"}}, indent=2)
PKG_SESSION = json.dumps({"dependencies": {"express": "4.19.2", "express-session": "1.18.0"}}, indent=2)
DJANGO = {"manage.py": "import django\n", "requirements.txt": "Django==5.0\nstripe\n"}
LARAVEL = {"composer.json": json.dumps({"require": {"laravel/framework": "^11.0"}}), "artisan": "#!/usr/bin/env php\n"}
FLASK = {"requirements.txt": "flask\nstripe\nopenai\n"}


def hits(tmp_path, write_tree, scan_rules, files, rule_id, stacks=None):
    write_tree(tmp_path, files)
    res = scan_rules(tmp_path, rule_ids=[rule_id], stacks=stacks)
    assert not [w for w in res.warnings if rule_id in str(w)], res.warnings
    return [f for f in res.findings if f.rule == rule_id]


def lines_of(found):
    return sorted(f.line for f in found)


# ---------------------------------------------------------------------------
# Stripe webhooks
# ---------------------------------------------------------------------------

EXPRESS_QUICKSTART = """\
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();
const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

app.post('/webhook', express.raw({ type: 'application/json' }), (request, response) => {
  let event = request.body;
  if (endpointSecret) {
    const signature = request.headers['stripe-signature'];
    try {
      event = stripe.webhooks.constructEvent(request.body, signature, endpointSecret);
    } catch (err) {
      console.log('Webhook signature verification failed.', err.message);
      return response.sendStatus(400);
    }
  }
  switch (event.type) {
    case 'checkout.session.completed':
      grantAccess(event.data.object);
      break;
  }
  response.send();
});
"""

EXPRESS_FAIL_CLOSED = """\
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();

app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) return res.status(500).send('webhook secret not configured');
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } catch (e) {
    return res.status(400).send(`Webhook Error: ${e.message}`);
  }
  if (event.type === 'checkout.session.completed') {
    fulfill(event.data.object.id);
  }
  res.json({ received: true });
});

app.use(express.json());
"""

NEXT_NO_VERIFY = """\
import Stripe from 'stripe';
import { db } from '@/lib/db';

export async function POST(req: Request) {
  const event = await req.json();
  if (event.type === 'checkout.session.completed') {
    await db.user.update({ where: { id: event.data.object.metadata.userId }, data: { plan: 'pro' } });
  }
  return Response.json({ received: true });
}
"""

NEXT_DELEGATED_ROUTE = """\
import { verifyStripeEvent } from '@/lib/stripe';

export async function POST(req: Request) {
  const event = await verifyStripeEvent(req);
  switch (event.type) {
    case 'checkout.session.completed':
      await markPaid(event.data.object.id);
      break;
  }
  return Response.json({ received: true });
}
"""

NEXT_DELEGATED_LIB = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function verifyStripeEvent(req: Request) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature')!;
  return stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
}
"""

FLASK_QUICKSTART = """\
import json
import os
import stripe
from flask import Flask, jsonify, request

endpoint_secret = os.environ.get("STRIPE_WEBHOOK_SECRET")
app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    event = None
    payload = request.data
    try:
        event = json.loads(payload)
    except json.decoder.JSONDecodeError:
        return jsonify(success=False)
    if endpoint_secret:
        sig_header = request.headers.get("stripe-signature")
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, endpoint_secret)
        except stripe.error.SignatureVerificationError:
            return jsonify(success=False)
    if event and event["type"] == "payment_intent.succeeded":
        handle(event["data"]["object"])
    return jsonify(success=True)
"""

FLASK_SAFE = """\
import os
import stripe
from flask import Flask, abort, request

app = Flask(__name__)


@app.route("/webhook", methods=["POST"])
def webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature")
    secret = os.environ["STRIPE_WEBHOOK_SECRET"]
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, secret)
    except (ValueError, stripe.error.SignatureVerificationError):
        abort(400)
    if event["type"] == "checkout.session.completed":
        fulfill(event["data"]["object"]["id"])
    return "", 200
"""

PHP_QUICKSTART = """\
<?php
require 'vendor/autoload.php';
$stripe = new \\Stripe\\StripeClient(getenv('STRIPE_SECRET_KEY'));
$endpoint_secret = getenv('STRIPE_WEBHOOK_SECRET');
$payload = @file_get_contents('php://input');
$event = null;
try {
  $event = \\Stripe\\Event::constructFrom(json_decode($payload, true));
} catch(\\UnexpectedValueException $e) {
  http_response_code(400);
  exit();
}
if ($endpoint_secret) {
  $sig_header = $_SERVER['HTTP_STRIPE_SIGNATURE'];
  try {
    $event = \\Stripe\\Webhook::constructEvent($payload, $sig_header, $endpoint_secret);
  } catch(\\Stripe\\Exception\\SignatureVerificationException $e) {
    http_response_code(400);
    exit();
  }
}
switch ($event->type) {
  case 'payment_intent.succeeded':
    markPaid($event->data->object);
    break;
}
"""

EXPRESS_SWALLOWED = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  let event = JSON.parse(req.body);
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.warn('signature check failed', err.message);
  }
  if (event.type === 'checkout.session.completed') grant(event.data.object);
  res.sendStatus(200);
});
"""

EXPRESS_ELSE_FAILS = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const sig = req.headers['stripe-signature'];
  let event = req.body;
  if (secret) {
    event = stripe.webhooks.constructEvent(req.body, sig, secret);
  } else {
    return res.status(500).send('missing webhook secret');
  }
  if (event.type === 'invoice.paid') extend(event.data.object);
  res.sendStatus(200);
});
"""

EXPRESS_NEGATED_FALLBACK = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  let event;
  if (!secret) {
    event = JSON.parse(req.body);
  } else {
    event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret);
  }
  if (event.type === 'invoice.paid') extend(event.data.object);
  res.sendStatus(200);
});
"""

TERNARY = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const event = endpointSecret ? stripe.webhooks.constructEvent(req.body, sig, endpointSecret) : JSON.parse(req.body);
  res.sendStatus(200);
});
"""

CASHIER_LISTENER = """\
<?php
namespace App\\Listeners;

use Laravel\\Cashier\\Events\\WebhookReceived;

class StripeEventListener
{
    public function handle(WebhookReceived $event): void
    {
        if ($event->payload['type'] === 'invoice.payment_succeeded') {
            // stripe invoice paid
        }
    }
}
"""


def test_webhook_unverified_fires_when_nothing_verifies(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules,
                 {"package.json": PKG_NEXT, "app/api/stripe/webhook/route.ts": NEXT_NO_VERIFY},
                 "pay-webhook-unverified")
    assert lines_of(found) == [6]
    assert found[0].severity == "critical"


@pytest.mark.parametrize("files", [
    {"package.json": PKG_NEXT, "app/api/stripe/webhook/route.ts": NEXT_DELEGATED_ROUTE,
     "lib/stripe.ts": NEXT_DELEGATED_LIB},
    {"package.json": PKG_EXPRESS, "server.js": EXPRESS_FAIL_CLOSED},
    {"package.json": PKG_EXPRESS, "server.js": EXPRESS_QUICKSTART},
    {"package.json": PKG_NEXT, "tests/webhook.test.ts": NEXT_NO_VERIFY},
    {"composer.json": json.dumps({"require": {"laravel/framework": "^11", "laravel/cashier": "^15"}}),
     "app/Listeners/StripeEventListener.php": CASHIER_LISTENER},
    {"composer.json": json.dumps({"require": {"laravel/framework": "^11"}}),
     "app/Listeners/StripeEventListener.php": CASHIER_LISTENER},
    {"requirements.txt": "flask\nstripe\n", "app.py": FLASK_SAFE},
])
def test_webhook_unverified_safe(tmp_path, write_tree, scan_rules, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-unverified") == []


def test_webhook_unverified_ignores_other_providers(tmp_path, write_tree, scan_rules):
    paddle = ("export async function POST(req) {\n  const event = await req.json();\n"
              "  if (event.event_type === 'transaction.completed') grant(event);\n}\n")
    assert hits(tmp_path, write_tree, scan_rules, {"app/api/paddle/route.ts": paddle},
                "pay-webhook-unverified") == []


@pytest.mark.parametrize("name,files,line", [
    ("stripe quickstart", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_QUICKSTART}, 8),
    ("flask quickstart", dict(FLASK, **{"app.py": FLASK_QUICKSTART}), 18),
    ("php quickstart", {"webhook.php": PHP_QUICKSTART}, 13),
    ("swallowed catch", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_SWALLOWED}, 6),
    ("negated guard with fallback", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_NEGATED_FALLBACK}, 5),
    ("ternary", {"package.json": PKG_EXPRESS, "server.js": TERNARY}, 4),
])
def test_webhook_verify_optional_fires(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-verify-optional")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("fail closed", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_FAIL_CLOSED}),
    ("else fails closed", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_ELSE_FAILS}),
    ("flask safe", dict(FLASK, **{"app.py": FLASK_SAFE})),
    ("delegated helper", {"package.json": PKG_NEXT, "lib/stripe.ts": NEXT_DELEGATED_LIB}),
    ("test file", {"package.json": PKG_EXPRESS, "tests/webhook.test.js": EXPRESS_QUICKSTART}),
])
def test_webhook_verify_optional_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-verify-optional") == [], name


APP_ROUTER_JSON = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.json();
  const sig = req.headers.get('stripe-signature')!;
  const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!);
  return Response.json({ ok: true, type: event.type });
}
"""

PAGES_API = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export default async function handler(req, res) {
  const sig = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true, id: event.id });
}
"""

PAGES_API_SAFE = """\
import Stripe from 'stripe';
import { buffer } from 'micro';
export const config = { api: { bodyParser: false } };
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
export default async function handler(req, res) {
  const buf = await buffer(req);
  const event = stripe.webhooks.constructEvent(buf, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true, id: event.id });
}
"""

EXPRESS_GLOBAL_JSON = """\
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();
app.use(express.json());

app.post('/webhook', (req, res) => {
  const event = stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true, id: event.id });
});
"""

EXPRESS_JSON_VERIFY = """\
const express = require('express');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const app = express();
app.use(express.json({ verify: (req, res, buf) => { req.rawBody = buf; } }));

app.post('/webhook', (req, res) => {
  const event = stripe.webhooks.constructEvent(req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET);
  res.json({ received: true, id: event.id });
});
"""

FLASK_GET_JSON = """\
import stripe
from flask import Flask, request
app = Flask(__name__)


@app.post("/webhook")
def webhook():
    payload = request.get_json()
    event = stripe.Webhook.construct_event(payload, request.headers["Stripe-Signature"], SECRET)
    return {"id": event["id"]}
"""


@pytest.mark.parametrize("name,files,line", [
    ("json.stringify", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_QUICKSTART.replace(
        "constructEvent(request.body,", "constructEvent(JSON.stringify(request.body),")}, 11),
    ("app router req.json", {"package.json": PKG_NEXT, "app/api/webhook/route.ts": APP_ROUTER_JSON}, 4),
    ("pages api without bodyParser false", {"package.json": PKG_NEXT, "pages/api/webhook.js": PAGES_API}, 5),
    ("express.json first", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_GLOBAL_JSON}, 7),
    ("flask get_json", dict(FLASK, **{"app.py": FLASK_GET_JSON}), 8),
])
def test_webhook_parsed_body_fires(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-parsed-body")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("express.raw on route", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_QUICKSTART}),
    ("json mounted after route", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_FAIL_CLOSED}),
    ("json with verify callback", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_JSON_VERIFY}),
    ("app router req.text", {"package.json": PKG_NEXT,
                             "app/api/webhook/route.ts": APP_ROUTER_JSON.replace("req.json()", "req.text()")}),
    ("pages api raw buffer", {"package.json": PKG_NEXT, "pages/api/webhook.js": PAGES_API_SAFE}),
    ("flask request.data", dict(FLASK, **{"app.py": FLASK_GET_JSON.replace("request.get_json()", "request.data")})),
])
def test_webhook_parsed_body_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-parsed-body") == [], name


# ---------------------------------------------------------------------------
# Client-sent amounts
# ---------------------------------------------------------------------------

AMOUNT_DESTRUCT = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/create-payment-intent', async (req, res) => {
  const { amount } = req.body;
  const paymentIntent = await stripe.paymentIntents.create({ amount, currency: 'usd' });
  res.json({ clientSecret: paymentIntent.client_secret });
});
"""

AMOUNT_PRICE_DATA = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const body = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{
      price_data: { currency: 'usd', product_data: { name: body.name }, unit_amount: Math.round(body.price * 100) },
      quantity: 1,
    }],
    success_url: `${process.env.APP_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
  });
  return Response.json({ url: session.url });
}
"""

AMOUNT_CART_MAP = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const { items } = await req.json();
  const lineItems = items.map((item) => ({
    price_data: { currency: 'usd', product_data: { name: item.name }, unit_amount: item.price * 100 },
    quantity: item.quantity,
  }));
  const session = await stripe.checkout.sessions.create({ mode: 'payment', line_items: lineItems });
  return Response.json({ url: session.url });
}
"""

AMOUNT_PARAMS_OBJECT = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
router.post('/pay', async (req, res) => {
  const params = {
    amount: Number(req.body.amount),
    currency: 'usd',
  };
  const pi = await stripe.paymentIntents.create(params);
  res.json({ secret: pi.client_secret });
});
"""

AMOUNT_FLASK = """\
import stripe
from flask import Flask, jsonify, request
app = Flask(__name__)


@app.route("/create-payment-intent", methods=["POST"])
def create_payment():
    data = request.get_json()
    intent = stripe.PaymentIntent.create(amount=data["amount"], currency="usd")
    return jsonify(clientSecret=intent.client_secret)
"""

AMOUNT_FASTAPI = """\
import stripe
from fastapi import APIRouter, Depends
router = APIRouter()


@router.post("/pay")
async def pay(body: CheckoutIn, user=Depends(get_current_user)):
    intent = stripe.PaymentIntent.create(amount=body.amount, currency="usd")
    return {"secret": intent.client_secret}
"""

AMOUNT_PHP = """\
<?php
class PayController extends Controller
{
    public function intent(Request $request)
    {
        $amount = $request->input('amount');
        $intent = \\Stripe\\PaymentIntent::create(['amount' => $amount, 'currency' => 'usd']);
        return response()->json(['secret' => $intent->client_secret]);
    }

    public function cashier(Request $request)
    {
        // stripe charge through Cashier
        return $request->user()->charge($request->amount, $request->paymentMethodId);
    }
}
"""

SAFE_CATALOG = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const PRICES = { pro: 'price_123', team: 'price_456' };
app.post('/checkout', requireAuth, async (req, res) => {
  const priceId = PRICES[req.body.plan];
  if (!priceId) return res.status(400).end();
  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    line_items: [{ price: priceId, quantity: req.body.quantity }],
  });
  res.json({ url: session.url });
});
"""

SAFE_CALCULATE = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/create-payment-intent', async (req, res) => {
  const { items } = req.body;
  const paymentIntent = await stripe.paymentIntents.create({
    amount: calculateOrderAmount(items),
    currency: 'usd',
  });
  res.send({ clientSecret: paymentIntent.client_secret });
});
"""

SAFE_DB_PRICE = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
app.post('/buy', async (req, res) => {
  const { productId, quantity } = req.body;
  const product = await db.product.findUnique({ where: { id: productId } });
  const pi = await stripe.paymentIntents.create({ amount: product.price * quantity, currency: 'usd' });
  res.json({ secret: pi.client_secret });
});
"""

SAFE_PHP = """\
<?php
class PayController extends Controller
{
    public function intent(Request $request)
    {
        $price = Product::findOrFail($request->input('product_id'))->price;
        $intent = \\Stripe\\PaymentIntent::create(['amount' => $price, 'currency' => 'usd']);
        return response()->json(['secret' => $intent->client_secret]);
    }
}
"""


@pytest.mark.parametrize("name,files,expected", [
    ("destructured amount", {"server.js": AMOUNT_DESTRUCT}, [4]),
    ("price_data from body", {"app/api/checkout/route.ts": AMOUNT_PRICE_DATA}, [8]),
    ("cart items mapped", {"app/api/checkout/route.ts": AMOUNT_CART_MAP}, [6]),
    ("params object", {"routes/pay.js": AMOUNT_PARAMS_OBJECT}, [4]),
    ("flask", {"app.py": AMOUNT_FLASK}, [9]),
    ("fastapi body model", {"api/pay.py": AMOUNT_FASTAPI}, [8]),
    ("php intent and cashier charge", {"app/Http/Controllers/PayController.php": AMOUNT_PHP}, [7, 14]),
])
def test_client_amount_fires(tmp_path, write_tree, scan_rules, name, files, expected):
    found = hits(tmp_path, write_tree, scan_rules, files, "pay-client-amount")
    assert lines_of(found) == expected, name


@pytest.mark.parametrize("name,files", [
    ("catalog lookup with client quantity", {"server.js": SAFE_CATALOG}),
    ("computed from ids", {"server.js": SAFE_CALCULATE}),
    ("db price times quantity", {"server.js": SAFE_DB_PRICE}),
    ("php db price", {"app/Http/Controllers/PayController.php": SAFE_PHP}),
    ("donation is variable by design", {"app/api/donate/route.ts": AMOUNT_PRICE_DATA}),
    ("test file", {"tests/pay.test.js": AMOUNT_DESTRUCT}),
])
def test_client_amount_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-client-amount") == [], name


# ---------------------------------------------------------------------------
# Fulfillment on the success page and idempotency
# ---------------------------------------------------------------------------

SUCCESS_SERVER = """\
import { db } from '@/lib/db';

export default async function Success({ searchParams }) {
  const sessionId = searchParams.session_id;
  await db.user.update({ where: { stripeSessionId: sessionId }, data: { plan: 'pro' } });
  return <p>Thanks for upgrading!</p>;
}
"""

SUCCESS_CLIENT = """\
import { useEffect } from 'react';
import { supabase } from '../lib/supabase';

export default function PaymentSuccess({ user }) {
  useEffect(() => {
    supabase.from('profiles').update({ is_pro: true }).eq('id', user.id);
  }, []);
  return <h1>Welcome to Pro</h1>;
}
"""

SUCCESS_VERIFIED = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export default async function Success({ searchParams }) {
  const session = await stripe.checkout.sessions.retrieve(searchParams.session_id);
  if (session.payment_status !== 'unpaid') {
    await db.user.update({ where: { id: session.client_reference_id }, data: { plan: 'pro' } });
  }
  return <p>Thanks!</p>;
}
"""

SUCCESS_DISPLAY = """\
export default function Success() {
  return <p>Payment received. Your plan updates in a moment.</p>;
}
"""


@pytest.mark.parametrize("name,files,line", [
    ("server success page", {"package.json": PKG_NEXT, "app/success/page.tsx": SUCCESS_SERVER}, 5),
    ("client success page", {"src/pages/PaymentSuccess.tsx": SUCCESS_CLIENT}, 6),
])
def test_fulfill_on_redirect_fires(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "pay-fulfill-on-redirect")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("retrieve and payment_status", {"app/success/page.tsx": SUCCESS_VERIFIED}),
    ("display only", {"app/success/page.tsx": SUCCESS_DISPLAY}),
    ("webhook handler", {"app/api/stripe/webhook/route.ts": NEXT_NO_VERIFY}),
])
def test_fulfill_on_redirect_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-fulfill-on-redirect") == [], name


WEBHOOK_CREDITS = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);
export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), req.headers.get('stripe-signature')!, secret);
  if (event.type === 'checkout.session.completed') {
    const userId = event.data.object.client_reference_id;
    await db.user.update({ where: { id: userId }, data: { credits: { increment: 100 } } });
  }
  return Response.json({ received: true });
}
"""

WEBHOOK_CREDITS_PY = """\
import stripe


@csrf_exempt
def stripe_webhook(request):
    event = stripe.Webhook.construct_event(request.body, request.META["HTTP_STRIPE_SIGNATURE"], SECRET)
    if event["type"] == "invoice.paid":
        profile = Profile.objects.get(customer=event["data"]["object"]["customer"])
        profile.credits += 500
        profile.save()
    return HttpResponse(status=200)
"""


@pytest.mark.parametrize("name,files,line", [
    ("prisma increment", {"app/api/stripe/webhook/route.ts": WEBHOOK_CREDITS}, 7),
    ("django +=", {"billing/views.py": WEBHOOK_CREDITS_PY}, 9),
])
def test_webhook_no_idempotency_fires(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-no-idempotency")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("event id recorded", {"app/api/stripe/webhook/route.ts": WEBHOOK_CREDITS.replace(
        "    const userId", "    await db.processedEvent.create({ data: { id: event.id } });\n    const userId")}),
    ("boolean entitlement is idempotent", {"app/api/stripe/webhook/route.ts": WEBHOOK_CREDITS.replace(
        "credits: { increment: 100 }", "plan: 'pro'")}),
    ("unique index in a migration", {"app/api/stripe/webhook/route.ts": WEBHOOK_CREDITS,
                                     "supabase/migrations/001_fulfill.sql":
                                         "create table fulfillments (session_id text unique not null);\n"}),
])
def test_webhook_no_idempotency_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-no-idempotency") == [], name


# ---------------------------------------------------------------------------
# LLM routes
# ---------------------------------------------------------------------------

CHAT_ROUTE = """\
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';

export async function POST(req: Request) {
  const { messages } = await req.json();
  const result = streamText({ model: openai('gpt-4o'), messages });
  return result.toDataStreamResponse();
}
"""

CHAT_ROUTE_AUTH = """\
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';
import { auth } from '@/auth';

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { messages } = await req.json();
  const result = streamText({ model: openai('gpt-4o'), messages, maxTokens: 800 });
  return result.toDataStreamResponse();
}
"""

CHAT_ROUTE_LIMIT = """\
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';
import { Ratelimit } from '@upstash/ratelimit';
const rl = new Ratelimit({ redis, limiter: Ratelimit.slidingWindow(20, '1 m') });

export async function POST(req: Request) {
  const { success } = await rl.limit(req.headers.get('x-forwarded-for') ?? 'anon');
  if (!success) return new Response('Too Many Requests', { status: 429 });
  const { messages } = await req.json();
  return streamText({ model: openai('gpt-4o'), messages }).toDataStreamResponse();
}
"""

CLERK_MW = """\
import { clerkMiddleware, createRouteMatcher } from '@clerk/nextjs/server';
const isProtected = createRouteMatcher(['/api(.*)']);
export default clerkMiddleware(async (auth, req) => {
  if (isProtected(req)) await auth.protect();
});
export const config = { matcher: ['/((?!_next|[^?]*\\\\.(?:html?|css|js)).*)', '/(api|trpc)(.*)'] };
"""

MW_SKIPS_API = """\
import { updateSession } from '@/utils/supabase/middleware';
export async function middleware(request) {
  return await updateSession(request);
}
export const config = { matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'] };
// updateSession redirects to /login when there is no user
function unused() { return redirect('/login'); }
"""

EXPRESS_OPENAI = """\
const express = require('express');
const OpenAI = require('openai');
const openai = new OpenAI();
const app = express();
app.use(express.json());

app.post('/api/generate', async (req, res) => {
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    messages: [{ role: 'user', content: req.body.prompt }],
  });
  res.json(completion.choices[0].message);
});
app.listen(3000);
"""

FASTAPI_CHAT = """\
from fastapi import FastAPI
from openai import OpenAI

app = FastAPI()
client = OpenAI()


@app.post("/chat")
async def chat(body: ChatIn):
    r = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": body.prompt}])
    return {"reply": r.choices[0].message.content}
"""

BYOK = """\
import OpenAI from 'openai';
export async function POST(req: Request) {
  const body = await req.json();
  const openai = new OpenAI({ apiKey: body.apiKey });
  const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: body.messages });
  return Response.json(r);
}
"""

CLIENT_SIDE_LLM = """\
import OpenAI from 'openai';
const openai = new OpenAI({ apiKey: import.meta.env.VITE_KEY, dangerouslyAllowBrowser: true });
export async function ask(q) {
  return openai.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: q }] });
}
"""

PKG_VITE = json.dumps({"dependencies": {"react": "18.3.0", "react-dom": "18.3.0", "openai": "4.0.0"},
                       "devDependencies": {"vite": "5.4.0"}}, indent=2)


@pytest.mark.parametrize("name,files,line", [
    ("next chat route", {"package.json": PKG_NEXT, "app/api/chat/route.ts": CHAT_ROUTE}, 6),
    ("middleware skips api", {"package.json": PKG_NEXT, "app/api/chat/route.ts": CHAT_ROUTE,
                              "middleware.ts": MW_SKIPS_API}, 6),
    ("express route", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_OPENAI}, 8),
    ("fastapi route", {"requirements.txt": "fastapi\nopenai\n", "main.py": FASTAPI_CHAT}, 10),
])
def test_llm_route_open_fires(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "abuse-llm-route-open")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("auth check", {"package.json": PKG_NEXT, "app/api/chat/route.ts": CHAT_ROUTE_AUTH}),
    ("rate limit", {"package.json": PKG_NEXT, "app/api/chat/route.ts": CHAT_ROUTE_LIMIT}),
    ("clerk middleware covers api", {"package.json": PKG_NEXT, "app/api/chat/route.ts": CHAT_ROUTE,
                                     "middleware.ts": CLERK_MW}),
    ("global express limiter", {"package.json": PKG_EXPRESS, "routes/ai.js": EXPRESS_OPENAI.replace(
        "app.use(express.json());", ""), "index.js": "const rateLimit = require('express-rate-limit');\n"
                                                     "app.use(rateLimit({ windowMs: 60000, max: 20 }));\n"}),
    ("fastapi depends on user", {"requirements.txt": "fastapi\nopenai\n", "main.py": FASTAPI_CHAT.replace(
        "async def chat(body: ChatIn):", "async def chat(body: ChatIn, user: User = Depends(get_current_user)):")}),
    ("user brings their own key", {"package.json": PKG_NEXT, "app/api/chat/route.ts": BYOK}),
    ("client-side call is another rule", {"package.json": PKG_VITE, "src/ai.ts": CLIENT_SIDE_LLM}),
    ("not a route", {"package.json": PKG_EXPRESS, "scripts/summarize.js": EXPRESS_OPENAI.replace(
        "app.post('/api/generate', async (req, res) => {", "async function main(req, res) {").replace(
        "});\napp.listen(3000);", "}")}),
])
def test_llm_route_open_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "abuse-llm-route-open") == [], name


# ---------------------------------------------------------------------------
# SMS and email sends
# ---------------------------------------------------------------------------

OTP_ROUTE = """\
import twilio from 'twilio';
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_TOKEN);

export async function POST(req: Request) {
  const { phone } = await req.json();
  await client.verify.v2.services(process.env.TWILIO_VERIFY_SID!).verifications.create({ to: phone, channel: 'sms' });
  return Response.json({ ok: true });
}
"""

SIGNUP_EMAIL = """\
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

router.post('/signup', async (req, res) => {
  const { email } = req.body;
  const code = makeCode();
  await resend.emails.send({ from: 'noreply@app.test', to: email, subject: 'Your code', text: code });
  res.json({ ok: true });
});
"""

CONTACT_FIXED = """\
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

router.post('/contact', async (req, res) => {
  await resend.emails.send({ from: 'site@app.test', to: 'owner@app.test', subject: 'Contact', text: req.body.message });
  res.json({ ok: true });
});
"""

RESET_DB_USER = """\
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);

router.post('/forgot', async (req, res) => {
  const user = await db.user.findUnique({ where: { email: req.body.email } });
  if (!user) return res.json({ ok: true });
  await resend.emails.send({ from: 'noreply@app.test', to: user.email, subject: 'Reset', text: link(user) });
  res.json({ ok: true });
});
"""

PHP_MAIL = """\
<?php
$email = $_POST['email'] ?? '';
$code = random_int(100000, 999999);
mail($email, 'Your login code', "Code: $code");
echo json_encode(['ok' => true]);
"""


@pytest.mark.parametrize("name,files,line,severity", [
    ("twilio verify otp", {"package.json": PKG_NEXT, "app/api/otp/route.ts": OTP_ROUTE}, 6, "high"),
    ("signup email", {"package.json": PKG_EXPRESS, "routes/auth.js": SIGNUP_EMAIL}, 7, "medium"),
    ("plain php mail", {"login-code.php": PHP_MAIL}, 4, "medium"),
])
def test_send_no_throttle_fires(tmp_path, write_tree, scan_rules, name, files, line, severity):
    found = hits(tmp_path, write_tree, scan_rules, files, "abuse-send-no-throttle")
    assert lines_of(found) == [line], name
    assert found[0].severity == severity


@pytest.mark.parametrize("name,files", [
    ("rate limited", {"package.json": PKG_NEXT, "app/api/otp/route.ts": OTP_ROUTE.replace(
        "  const { phone }", "  const { success } = await ratelimit.limit(ip);\n"
                             "  if (!success) return new Response('Too Many Requests', { status: 429 });\n"
                             "  const { phone }")}),
    ("turnstile", {"package.json": PKG_NEXT, "app/api/otp/route.ts": OTP_ROUTE.replace(
        "  const { phone }", "  await verifyTurnstile(token);\n  const { phone }")}),
    ("fixed admin address", {"package.json": PKG_EXPRESS, "routes/contact.js": CONTACT_FIXED}),
    ("reset email to a db user", {"package.json": PKG_EXPRESS, "routes/forgot.js": RESET_DB_USER}),
    ("behind login", {"package.json": PKG_EXPRESS, "routes/auth.js": SIGNUP_EMAIL.replace(
        "  const { email }", "  if (!req.user) return res.sendStatus(401);\n  const { email }")}),
])
def test_send_no_throttle_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "abuse-send-no-throttle") == [], name


def test_llm_rule_does_not_treat_twilio_as_llm(tmp_path, write_tree, scan_rules):
    assert hits(tmp_path, write_tree, scan_rules, {"package.json": PKG_NEXT, "app/api/otp/route.ts": OTP_ROUTE},
                "abuse-llm-route-open") == []


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def test_csurf_deprecated(tmp_path, write_tree, scan_rules):
    pkg = json.dumps({"dependencies": {"express": "4.19.2", "csurf": "1.11.0"}}, indent=2)
    found = hits(tmp_path, write_tree, scan_rules, {"package.json": pkg}, "csrf-csurf-deprecated")
    assert lines_of(found) == [4]
    other = tmp_path / "other"
    assert hits(other, write_tree, scan_rules, {"package.json": PKG_EXPRESS}, "csrf-csurf-deprecated") == []


DJANGO_EXEMPT = """\
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def update_email(request):
    if request.method == "POST":
        request.user.email = request.POST["email"]
        request.user.save()
    return JsonResponse({"ok": True})
"""

DJANGO_EXEMPT_WEBHOOK = DJANGO_EXEMPT.replace("def update_email(request):", "def stripe_webhook(request):")

DJANGO_EXEMPT_TOKEN = """\
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt
def api_update(request):
    token = request.headers.get("Authorization", "")
    account = account_for_token(token)
    account.update(name=request.POST["name"])
    return JsonResponse({"ok": True})
"""

DJANGO_MIDDLEWARE = """\
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
]
"""

LARAVEL_EXCEPT = """\
<?php

namespace App\\Http\\Middleware;

use Illuminate\\Foundation\\Http\\Middleware\\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    protected $except = [
        'stripe/*',
        '%s',
    ];
}
"""

LARAVEL11 = """\
<?php
return Application::configure(basePath: dirname(__DIR__))
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->validateCsrfTokens(except: [
            'stripe/*',
            '%s',
        ]);
    })->create();
"""

FLASK_CONFIG = """\
class Config:
    SECRET_KEY = os.environ["SECRET_KEY"]


class %s(Config):
    WTF_CSRF_ENABLED = False
"""


@pytest.mark.parametrize("name,files,expected", [
    ("django exempt session view", dict(DJANGO, **{"accounts/views.py": DJANGO_EXEMPT}), [5]),
    ("django middleware removed", dict(DJANGO, **{"proj/settings.py": DJANGO_MIDDLEWARE}), [1]),
    ("laravel except all", dict(LARAVEL, **{"app/Http/Middleware/VerifyCsrfToken.php": LARAVEL_EXCEPT % "*"}), [11]),
    ("laravel 11 except profile", dict(LARAVEL, **{"bootstrap/app.php": LARAVEL11 % "profile/*"}), [6]),
    ("flask-wtf off in prod config", dict(FLASK, **{"config.py": FLASK_CONFIG % "ProductionConfig"}), [6]),
    ("laravel 11 web group without csrf", dict(LARAVEL, **{"bootstrap/app.php": (
        "<?php\nreturn Application::configure(basePath: dirname(__DIR__))\n"
        "    ->withMiddleware(function (Middleware $middleware) {\n"
        "        $middleware->web(remove: [\\Illuminate\\Foundation\\Http\\Middleware\\ValidateCsrfToken::class]);\n"
        "    })->create();\n")}), [4]),
])
def test_csrf_disabled_fires(tmp_path, write_tree, scan_rules, name, files, expected):
    found = hits(tmp_path, write_tree, scan_rules, files, "csrf-protection-disabled")
    assert lines_of(found) == expected, name


@pytest.mark.parametrize("name,files", [
    ("django exempt webhook", dict(DJANGO, **{"billing/views.py": DJANGO_EXEMPT_WEBHOOK})),
    ("django exempt token api", dict(DJANGO, **{"api/views.py": DJANGO_EXEMPT_TOKEN})),
    ("django middleware present", dict(DJANGO, **{"proj/settings.py": DJANGO_MIDDLEWARE.replace("# ", "")})),
    ("laravel webhook only", dict(LARAVEL, **{"app/Http/Middleware/VerifyCsrfToken.php":
                                              LARAVEL_EXCEPT % "paddle/webhook"})),
    ("laravel 11 webhooks", dict(LARAVEL, **{"bootstrap/app.php": LARAVEL11 % "webhooks/*"})),
    ("flask-wtf off in testing config", dict(FLASK, **{"config.py": FLASK_CONFIG % "TestingConfig"})),
])
def test_csrf_disabled_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "csrf-protection-disabled") == [], name


EXPRESS_SESSION_APP = """\
const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false%s }));

app.post('/account/email', (req, res) => {
  if (!req.session.userId) return res.sendStatus(401);
  updateEmail(req.session.userId, req.body.email);
  res.redirect('/account');
});

app.post('/stripe/webhook', (req, res) => {
  handle(req.session.userId);
});
"""


def test_csrf_session_no_token(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules,
                 {"package.json": PKG_SESSION, "app.js": EXPRESS_SESSION_APP % ""}, "csrf-session-no-token")
    assert lines_of(found) == [6]


@pytest.mark.parametrize("name,files", [
    ("samesite lax", {"package.json": PKG_SESSION,
                      "app.js": EXPRESS_SESSION_APP % ", cookie: { sameSite: 'lax', httpOnly: true }"}),
    ("csrf library", {"package.json": json.dumps({"dependencies": {"express": "4", "express-session": "1",
                                                                   "csrf-csrf": "3"}}),
                      "app.js": EXPRESS_SESSION_APP % "",
                      "csrf.js": "const { doubleCsrf } = require('csrf-csrf');\n"
                                 "const { doubleCsrfProtection } = doubleCsrf({ getSecret: () => process.env.CSRF_SECRET });\n"
                                 "module.exports = (app) => app.use(doubleCsrfProtection);\n"}),
    ("no cookie session", {"package.json": PKG_EXPRESS, "app.js": EXPRESS_SESSION_APP % ""}),
])
def test_csrf_session_no_token_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "csrf-session-no-token") == [], name


def test_csrf_session_guard_middleware_on_route(tmp_path, write_tree, scan_rules):
    routes = ("module.exports = (app) => {\n"
              "  app.post('/login', sessionHandler.handleLoginRequest);\n"
              "  app.post('/profile', isLoggedIn, profileHandler.handleProfileUpdate);\n"
              "  app.post('/settings', ensureLoggedIn('/login'), settings.save);\n"
              "  app.post('/api/hook', isLoggedIn, hooks.receive);\n"
              "};\n")
    found = hits(tmp_path, write_tree, scan_rules,
                 {"package.json": PKG_SESSION, "app.js": "const session = require('express-session');\n"
                                                         "app.use(session({ secret: process.env.S }));\n",
                  "routes/index.js": routes}, "csrf-session-no-token")
    assert sorted((f.file, f.line) for f in found) == [("routes/index.js", 3), ("routes/index.js", 4)]


@pytest.mark.parametrize("name,extra", [
    ("listed but never called", ""),
    ("call left in a block comment", "/*\napp.use(csrf());\n"
                                     "app.use((req, res, next) => { res.locals.t = req.csrfToken(); next(); });\n*/\n"),
])
def test_csrf_package_counts_only_when_called(tmp_path, write_tree, scan_rules, name, extra):
    pkg = json.dumps({"dependencies": {"express": "4", "express-session": "1", "csurf": "1"}})
    found = hits(tmp_path, write_tree, scan_rules,
                 {"package.json": pkg, "app.js": EXPRESS_SESSION_APP % "" + extra}, "csrf-session-no-token")
    assert lines_of(found) == [6], name


# ---------------------------------------------------------------------------
# Open redirects
# ---------------------------------------------------------------------------

CALLBACK_NO_GUARD = """\
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const next = searchParams.get('next') ?? '/';
  await exchange(searchParams.get('code'));
  return NextResponse.redirect(`${origin}${next}`);
}
"""

CALLBACK_SUPABASE = """\
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  let next = searchParams.get('next') ?? '/';
  if (!next.startsWith('/')) {
    next = '/';
  }
  await exchange(searchParams.get('code'));
  return NextResponse.redirect(`${origin}${next}`);
}
"""

WEAK_NEW_URL = """\
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const next = new URL(request.url).searchParams.get('next') ?? '/dashboard';
  if (!next.startsWith('/')) return NextResponse.redirect(new URL('/dashboard', request.url));
  return NextResponse.redirect(new URL(next, request.url));
}
"""

SLASH2_NEW_URL = WEAK_NEW_URL.replace("if (!next.startsWith('/'))", "if (!next.startsWith('/') || next.startsWith('//'))")
STRONG_NEW_URL = WEAK_NEW_URL.replace(
    "if (!next.startsWith('/'))",
    "if (!/^\\/(?![\\/\\\\])/.test(next) || /[\\x00-\\x1f\\\\]/.test(next))")

EXPRESS_REDIRECT = """\
app.get('/login/done', (req, res) => {
  res.redirect(req.query.returnTo || '/');
});
app.get('/home', (req, res) => {
  res.redirect('/dashboard');
});
app.get('/login', (req, res) => {
  res.redirect(`/auth/start?next=${req.query.next}`);
});
"""

FLASK_REDIRECT = """\
from flask import Flask, redirect, request, url_for
app = Flask(__name__)


@app.route("/after-login")
def after_login():
    return redirect(request.args.get("next") or url_for("index"))
"""

FLASK_REDIRECT_SAFE = """\
from urllib.parse import urlsplit
from flask import Flask, redirect, request, url_for
app = Flask(__name__)


@app.route("/after-login")
def after_login():
    next_page = request.args.get("next")
    if not next_page or urlsplit(next_page).netloc != "" or "\\\\" in next_page:
        next_page = url_for("index")
    return redirect(next_page)
"""

FLASK_NETLOC_ONLY = FLASK_REDIRECT_SAFE.replace(' or "\\\\" in next_page', "")

DJANGO_REDIRECT_SAFE = """\
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme


def login_done(request):
    target = request.GET.get("next", "/")
    if not url_has_allowed_host_and_scheme(target, allowed_hosts={request.get_host()}):
        target = "/"
    return redirect(target)
"""

CLIENT_NAVIGATE = """\
import { useNavigate, useSearchParams } from 'react-router-dom';

export default function Login() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const returnTo = params.get('returnTo') || '/';
  async function onSubmit() {
    await signIn();
    navigate(returnTo);
  }
  return null;
}
"""

CLIENT_ALLOWLIST = CLIENT_NAVIGATE.replace(
    "    navigate(returnTo);", "    const ALLOWED = ['/dashboard', '/settings'];\n"
                              "    navigate(ALLOWED.includes(returnTo) ? returnTo : '/');")

CLIENT_HELPER = CLIENT_NAVIGATE.replace("navigate(returnTo);", "navigate(safeRedirect(returnTo));")

PHP_HEADER = """\
<?php
session_start();
if (login($_POST['user'] ?? '', $_POST['pass'] ?? '')) {
    header('Location: ' . $_GET['next']);
    exit;
}
"""

LARAVEL_INTENDED = """\
<?php
class LoginController extends Controller
{
    public function store(Request $request)
    {
        $next = $request->query('next');
        Auth::attempt($request->only('email', 'password'));
        return redirect()->intended('/dashboard');
    }
}
"""

PROVIDER_REDIRECT_URI = """\
app.get('/oauth/start', (req, res) => {
  res.redirect(`https://provider.test/authorize?client_id=abc&redirect_uri=${req.query.redirect_uri}`);
});
"""


@pytest.mark.parametrize("name,files,expected", [
    ("origin prefix without check", {"package.json": PKG_NEXT, "app/auth/callback/route.ts": CALLBACK_NO_GUARD}, [7]),
    ("startsWith slash alone with new URL", {"package.json": PKG_NEXT, "app/auth/route.ts": WEAK_NEW_URL}, [6]),
    ("express returnTo", {"server.js": EXPRESS_REDIRECT}, [2]),
    ("flask next", {"app.py": FLASK_REDIRECT}, [7]),
    ("client navigate", {"src/pages/Login.tsx": CLIENT_NAVIGATE}, [9]),
    ("php header", {"login.php": PHP_HEADER}, [4]),
])
def test_open_redirect_fires(tmp_path, write_tree, scan_rules, name, files, expected):
    found = hits(tmp_path, write_tree, scan_rules, files, "redirect-open")
    assert lines_of(found) == expected, name


def test_open_redirect_weak_guard_message(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules, {"app/auth/route.ts": WEAK_NEW_URL}, "redirect-open")
    assert "//other-host" in found[0].message


@pytest.mark.parametrize("name,files", [
    ("supabase sample guard", {"package.json": PKG_NEXT, "app/auth/callback/route.ts": CALLBACK_SUPABASE}),
    ("blocks double slash", {"package.json": PKG_NEXT, "app/auth/route.ts": STRONG_NEW_URL}),
    ("flask netloc check", {"app.py": FLASK_REDIRECT_SAFE}),
    ("django allowed host", {"accounts/views.py": DJANGO_REDIRECT_SAFE}),
    ("allowlist", {"src/pages/Login.tsx": CLIENT_ALLOWLIST}),
    ("helper", {"src/pages/Login.tsx": CLIENT_HELPER}),
    ("laravel intended", {"app/Http/Controllers/LoginController.php": LARAVEL_INTENDED}),
    ("param only as a query value", {"server.js": PROVIDER_REDIRECT_URI}),
    ("commented out", {"server.js": "app.get('/x', (req, res) => {\n  // res.redirect(req.query.next);\n"
                                    "  res.redirect('/');\n});\n"}),
])
def test_open_redirect_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "redirect-open") == [], name


# ---------------------------------------------------------------------------
# More traps from real code
# ---------------------------------------------------------------------------

REPLAY_SCRIPT = """\
import Stripe from 'stripe';
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const events = await stripe.events.list({ type: 'checkout.session.completed', limit: 100 });
for (const event of events.data) {
  if (event.type === 'checkout.session.completed') await backfill(event.data.object);
}
"""

EXPRESS_ISLOGGEDIN = EXPRESS_OPENAI.replace("app.post('/api/generate', async (req, res) => {",
                                            "app.post('/api/generate', isLoggedIn, async (req, res) => {")

DRF_EXEMPT = """\
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view


@csrf_exempt
@api_view(["POST"])
def rename(request):
    request.user.first_name = request.data["name"]
    request.user.save()
    return Response({"ok": True})
"""

AMOUNT_CHECKED = AMOUNT_DESTRUCT.replace(
    "  const paymentIntent", "  const product = await getProduct(req.body.productId);\n"
                             "  if (amount !== product.price) return res.status(400).end();\n  const paymentIntent")


@pytest.mark.parametrize("name,rule,files", [
    ("events fetched from the Stripe API", "pay-webhook-unverified", {"scripts/backfill.ts": REPLAY_SCRIPT}),
    ("isLoggedIn middleware", "abuse-llm-route-open", {"package.json": PKG_EXPRESS, "server.js": EXPRESS_ISLOGGEDIN}),
    ("drf view is already csrf checked", "csrf-protection-disabled", dict(DJANGO, **{"api/views.py": DRF_EXEMPT})),
    ("payment gateway callback", "csrf-protection-disabled",
     dict(LARAVEL, **{"app/Http/Middleware/VerifyCsrfToken.php": LARAVEL_EXCEPT % "paytr/callback"})),
    ("request value only picks the branch", "redirect-open",
     {"server.js": "app.get('/go', (req, res) => {\n  res.redirect(req.query.next ? '/a' : '/b');\n});\n"}),
    ("amount compared with the server price", "pay-client-amount", {"server.js": AMOUNT_CHECKED}),
    ("invoice id stored", "pay-webhook-no-idempotency", {"app/api/stripe/webhook/route.ts": WEBHOOK_CREDITS.replace(
        "    const userId", "    await db.payment.create({ data: { invoiceId: event.data.object.invoice } });\n    const userId")}),
])
def test_more_traps_stay_quiet(tmp_path, write_tree, scan_rules, name, rule, files):
    assert hits(tmp_path, write_tree, scan_rules, files, rule) == [], name


NESTED_AMOUNT = """\
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
router.post('/pay', async (req, res) => {
  const { amount, items } = req.body;
  try {
    for (const item of items) {
      if (item.ok) {
        await stripe.paymentIntents.create({ amount, currency: 'usd' });
      }
    }
  } catch (err) {
    res.status(500).end();
  }
});
"""

VERCEL_FN = """\
import OpenAI from 'openai';
const openai = new OpenAI();
export default async function handler(req, res) {
  const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages: req.body.messages });
  res.json(r);
}
"""


def test_nested_blocks_keep_the_handler_scope(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules, {"routes/pay.js": NESTED_AMOUNT}, "pay-client-amount")
    assert lines_of(found) == [7]


def test_vercel_function_is_a_route(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules, {"package.json": PKG_VITE, "api/chat.js": VERCEL_FN},
                 "abuse-llm-route-open")
    assert lines_of(found) == [4]


def test_redirect_ternary_branch_with_param_still_fires(tmp_path, write_tree, scan_rules):
    files = {"server.js": "app.get('/go', (req, res) => {\n  res.redirect(req.query.ok ? req.query.next : '/');\n});\n"}
    assert lines_of(hits(tmp_path, write_tree, scan_rules, files, "redirect-open")) == [2]


def test_evidence_and_ids(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules, {"server.js": AMOUNT_DESTRUCT}, "pay-client-amount")
    f = found[0]
    assert f.id == "pay-client-amount@server.js:4"
    assert "paymentIntents.create" in f.evidence
    assert f.fix_ref == "payments-and-abuse.md#server-side-prices" and f.needs_confirmation


# ---------------------------------------------------------------------------
# Auth helpers and LLM calls one or two imports away
# ---------------------------------------------------------------------------

AUTH_HELPER_LIB = """\
import { createClient } from '@/lib/supabase/server';

export async function loadProfile() {
  const supabase = createClient();
  const user = (await supabase.auth.getUser()).data.user;
  if (!user) {
    throw new Error('not signed in');
  }
  return user;
}
"""

ROUTE_WITH_AUTH_HELPER = """\
import OpenAI from 'openai';
import { loadProfile } from '@/lib/server/profile';

export async function POST(req: Request) {
  const { messages } = await req.json();
  const profile = await loadProfile();
  const openai = new OpenAI();
  const r = await openai.chat.completions.create({ model: 'gpt-4o-mini', messages });
  return Response.json(r);
}
"""

ROUTE_WITH_WRAPPER = """\
import { anthropic } from '@ai-sdk/anthropic';
import { streamText } from 'ai';
import { withWorkspace } from '@/lib/auth';

export const POST = withWorkspace(async ({ req }) => {
  const { prompt } = await req.json();
  return streamText({ model: anthropic('claude-haiku'), prompt }).toTextStreamResponse();
});
"""

ACTION_WITH_AUTH_CLIENT = """\
"use server";
import { anthropic } from '@ai-sdk/anthropic';
import { generateText } from 'ai';
import { authActionClient } from './safe-action';

export const summarize = authActionClient
  .schema(schema)
  .action(async ({ parsedInput }) => generateText({ model: anthropic('claude-haiku'), prompt: parsedInput.text }));
"""

ACTION_CLIENT_LIB = """\
import { createSafeActionClient } from 'next-safe-action';
import { auth } from '@/auth';

export const actionClient = createSafeActionClient().use(async ({ next }) => {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  return next({ ctx: { userId: session.user.id } });
});
"""

ACTION_WITH_PLAIN_CLIENT = ACTION_WITH_AUTH_CLIENT.replace("authActionClient", "actionClient")

ROUTE_USAGE_QUOTA = """\
import { openai } from '@ai-sdk/openai';
import { streamText } from 'ai';

export async function POST(req: Request) {
  const { prompt, workspaceId } = await req.json();
  const workspace = await loadWorkspace(workspaceId);
  throwIfAIUsageExceeded(workspace);
  return streamText({ model: openai('gpt-4o-mini'), prompt }).toTextStreamResponse();
}
"""

LOVABLE_EDGE = """\
Deno.serve(async (req) => {
  const { messages } = await req.json();
  const r = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ model: 'google/gemini-2.5-flash', messages }),
  });
  return new Response(await r.text());
});
"""

GEMINI_LOW = """\
const BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

export async function callModel(apiKey: string, parts: unknown[]) {
  const res = await fetch(`${BASE_URL}/gemini-2.5-flash:generateContent?key=${apiKey}`, {
    method: 'POST',
    body: JSON.stringify({ contents: [{ parts }] }),
  });
  return res.json();
}
"""

GEMINI_MID = """\
import { callModel } from './model.ts';

export async function extractFields(fileBase64: string) {
  const key = Deno.env.get('GEMINI_KEY') ?? '';
  return callModel(key, [{ inline_data: { data: fileBase64 } }]);
}
"""

EDGE_TWO_HOPS = """\
import { extractFields } from '../shared/parser.ts';

Deno.serve(async (req) => {
  const body = await req.json();
  if (!body.fileBase64) return new Response('bad request', { status: 400 });
  const fields = await extractFields(body.fileBase64);
  return Response.json(fields);
});
"""

SERVER_FN = """\
import { createServerFn } from '@tanstack/react-start';
import { generateIdeas } from './ideas.server';

export const getIdeas = createServerFn({ method: 'POST' })
  .inputValidator((d) => d)
  .handler(async ({ data }) => ({ ideas: await generateIdeas(data) }));
"""

SERVER_FN_LIB = """\
import { createOpenAI } from '@ai-sdk/openai';
import { generateText } from 'ai';

export async function generateIdeas(input: { topic: string }) {
  const provider = createOpenAI({ apiKey: process.env.AI_KEY });
  const r = await generateText({ model: provider('gpt-4o-mini'), prompt: input.topic });
  return r.text;
}
"""

SERVER_FN_AUTHED = SERVER_FN.replace(".inputValidator", ".middleware([authMiddleware])\n  .inputValidator")


@pytest.mark.parametrize("name,files,line", [
    ("lovable ai gateway", {"package.json": "{}", "supabase/functions/chat/index.ts": LOVABLE_EDGE}, 3),
    ("helper two imports away", {"package.json": "{}", "supabase/functions/extract/index.ts": EDGE_TWO_HOPS,
                                 "supabase/functions/shared/parser.ts": GEMINI_MID,
                                 "supabase/functions/shared/model.ts": GEMINI_LOW}, 6),
    ("tanstack server function", {"package.json": PKG_VITE, "src/lib/ideas.functions.ts": SERVER_FN,
                                  "src/lib/ideas.server.ts": SERVER_FN_LIB}, 6),
    ("server action on an unchecked client", {"package.json": PKG_NEXT, "lib/ai/summarize.ts": ACTION_WITH_PLAIN_CLIENT,
                                              "lib/ai/safe-action.ts": "export const actionClient = makeClient();\n"},
     8),
])
def test_llm_route_open_follows_imports(tmp_path, write_tree, scan_rules, name, files, line):
    found = hits(tmp_path, write_tree, scan_rules, files, "abuse-llm-route-open")
    assert lines_of(found) == [line], name


@pytest.mark.parametrize("name,files", [
    ("helper that checks the session and throws", {"package.json": PKG_NEXT, "app/api/chat/route.ts": ROUTE_WITH_AUTH_HELPER,
                                                   "lib/server/profile.ts": AUTH_HELPER_LIB}),
    ("auth wrapper", {"package.json": PKG_NEXT, "app/api/ai/route.ts": ROUTE_WITH_WRAPPER}),
    ("auth action client", {"package.json": PKG_NEXT, "lib/ai/summarize.ts": ACTION_WITH_AUTH_CLIENT}),
    ("action client built with an auth middleware", {"package.json": PKG_NEXT,
                                                     "lib/ai/summarize.ts": ACTION_WITH_PLAIN_CLIENT,
                                                     "lib/ai/safe-action.ts": ACTION_CLIENT_LIB}),
    ("usage quota guard", {"package.json": PKG_NEXT, "app/api/ai/route.ts": ROUTE_USAGE_QUOTA}),
    ("server function with auth middleware", {"package.json": PKG_VITE, "src/lib/ideas.functions.ts": SERVER_FN_AUTHED,
                                              "src/lib/ideas.server.ts": SERVER_FN_LIB}),
    ("helper that does not call a model", {"package.json": "{}", "supabase/functions/extract/index.ts": EDGE_TWO_HOPS,
                                           "supabase/functions/shared/parser.ts": GEMINI_MID.replace(
                                               "callModel(key,", "Promise.resolve(key,")}),
])
def test_llm_route_open_auth_shapes_stay_quiet(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "abuse-llm-route-open") == [], name


# ---------------------------------------------------------------------------
# Sends through provider REST APIs, and sends to a user picked by id
# ---------------------------------------------------------------------------

OTP_FETCH = """\
Deno.serve(async (req) => {
  const { phone } = await req.json();
  const sid = Deno.env.get('VERIFY_SID');
  const res = await fetch(`https://verify.twilio.com/v2/Services/${sid}/Verifications`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ To: `+1${phone}`, Channel: 'sms' }),
  });
  return new Response(await res.text());
});
"""

CONTACT_FETCH_FIXED = """\
export async function POST(request: Request) {
  const { email, message } = await request.json();
  await fetch('https://api.resend.com/emails', {
    method: 'POST',
    body: JSON.stringify({ from: 'site@app.test', to: 'team@app.test', subject: 'Contact', text: `${email}: ${message}` }),
  });
  return Response.json({ ok: true });
}
"""

NOTIFY_BY_ID = """\
import { Resend } from 'npm:resend';
const resend = new Resend(Deno.env.get('RESEND_KEY'));

Deno.serve(async (req) => {
  const { userId, note } = await req.json();
  const admin = createClient(Deno.env.get('SUPABASE_URL'), Deno.env.get('SERVICE_KEY'));
  const { data: found } = await admin.auth.admin.getUserById(userId);
  const address = found.user.email;
  await resend.emails.send({ from: 'shop@app.test', to: [address], subject: 'Update', html: `<p>${note}</p>` });
  return new Response('ok');
});
"""

NOTIFY_BY_ID_SECRET = NOTIFY_BY_ID.replace(
    "  const { userId, note }",
    "  if (req.headers.get('authorization') !== `Bearer ${Deno.env.get('HOOK_KEY')}`) "
    "return new Response('Unauthorized', { status: 401 });\n  const { userId, note }")


@pytest.mark.parametrize("name,files,line,severity", [
    ("twilio verify through fetch", {"package.json": "{}", "supabase/functions/send-otp/index.ts": OTP_FETCH}, 4, "high"),
    ("email to a user picked by id", {"package.json": "{}", "supabase/functions/notify/index.ts": NOTIFY_BY_ID}, 9,
     "medium"),
])
def test_send_no_throttle_more_shapes(tmp_path, write_tree, scan_rules, name, files, line, severity):
    found = hits(tmp_path, write_tree, scan_rules, files, "abuse-send-no-throttle")
    assert lines_of(found) == [line], name
    assert found[0].severity == severity


@pytest.mark.parametrize("name,files", [
    ("fixed inbox through fetch, address only in the text", {"package.json": PKG_NEXT,
                                                             "app/api/contact/route.ts": CONTACT_FETCH_FIXED}),
    ("id lookup behind a shared secret", {"package.json": "{}", "supabase/functions/notify/index.ts": NOTIFY_BY_ID_SECRET}),
    ("verification check is not a send", {"package.json": "{}", "supabase/functions/check-otp/index.ts":
                                          OTP_FETCH.replace("/Verifications`", "/VerificationCheck`")}),
])
def test_send_no_throttle_more_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "abuse-send-no-throttle") == [], name


OTP_CHECK_URL_CONST = """\
Deno.serve(async (req) => {
  const { phone, code } = await req.json();
  const sid = Deno.env.get('VERIFY_SID');
  const checkUrl = `https://verify.twilio.com/v2/Services/${sid}/VerificationCheck`;
  const res = await fetch(checkUrl, {
    method: 'POST',
    body: new URLSearchParams({ To: `+1${phone}`, Code: code }),
  });
  return new Response(await res.text());
});
"""

NOTIFY_BY_ID_TEMPLATE = NOTIFY_BY_ID.replace(
    "  const address = found.user.email;\n",
    "  const address = found.user.email;\n  const page = `\n    <h1>Hello</h1>\n    <p>${note}</p>\n  `;\n").replace(
    "html: `<p>${note}</p>`", "html: page")


def test_send_check_url_in_a_const_is_not_a_send(tmp_path, write_tree, scan_rules):
    files = {"package.json": "{}", "supabase/functions/verify-otp/index.ts": OTP_CHECK_URL_CONST}
    assert hits(tmp_path, write_tree, scan_rules, files, "abuse-send-no-throttle") == []
    other = tmp_path / "other"
    files = {"package.json": "{}", "supabase/functions/send-otp/index.ts":
             OTP_CHECK_URL_CONST.replace("/VerificationCheck`", "/Verifications`")}
    assert lines_of(hits(other, write_tree, scan_rules, files, "abuse-send-no-throttle")) == [5]


@pytest.mark.parametrize("name,code,relay", [
    ("request text inline in the html", NOTIFY_BY_ID, True),
    ("request text in a multi-line template const", NOTIFY_BY_ID_TEMPLATE, True),
    ("escaped request text", NOTIFY_BY_ID.replace("${note}", "${escapeHtml(note)}"), False),
])
def test_send_message_names_request_text_in_the_body(tmp_path, write_tree, scan_rules, name, code, relay):
    found = hits(tmp_path, write_tree, scan_rules, {"package.json": "{}", "supabase/functions/notify/index.ts": code},
                 "abuse-send-no-throttle")
    assert len(found) == 1, name
    assert ("phishing" in found[0].message) is relay, name


# ---------------------------------------------------------------------------
# Payment gateways other than Stripe
# ---------------------------------------------------------------------------

GATEWAY_FORM_INIT = """\
Deno.serve(async (req) => {
  const body = await req.json();
  const { orderId, amount } = body;
  const gatewayUrl = 'https://sandbox.sslcommerz.com/gwprocess/v4/api.php';
  const form = new URLSearchParams();
  form.append('store_id', Deno.env.get('STORE_ID') ?? '');
  form.append('total_amount', amount.toString());
  form.append('tran_id', orderId);
  const res = await fetch(gatewayUrl, { method: 'POST', body: form.toString() });
  return new Response(await res.text());
});
"""

RAZORPAY_ORDER = """\
Deno.serve(async (req) => {
  const { amount, receipt } = await req.json();
  const totalPaise = amount * 100;
  const res = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    headers: { Authorization: `Basic ${basic}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: totalPaise, currency: 'INR', receipt }),
  });
  return new Response(await res.text());
});
"""

RAZORPAY_ORDER_SAFE = """\
Deno.serve(async (req) => {
  const { orderId } = await req.json();
  const { data: order } = await admin.from('orders').select('total').eq('id', orderId).single();
  const res = await fetch('https://api.razorpay.com/v1/orders', {
    method: 'POST',
    body: JSON.stringify({ amount: order.total * 100, currency: 'INR', receipt: orderId }),
  });
  return new Response(await res.text());
});
"""

CHECKOUT_PAGE = """\
import { supabase } from '@/integrations/supabase/client';
import { useCart } from '@/hooks/useCart';

export default function Checkout() {
  const { items } = useCart();
  const total = items.reduce((s, i) => s + i.price * i.quantity, 0);
  async function placeOrder() {
    await supabase
      .from('orders')
      .insert({
        user_id: user.id,
        total_price: total,
        status: 'pending',
      });
  }
  return null;
}
"""

CHECKOUT_PAGE_RPC = CHECKOUT_PAGE.replace(
    "await supabase\n      .from('orders')\n      .insert({\n        user_id: user.id,\n        total_price: total,\n"
    "        status: 'pending',\n      });",
    "await supabase.rpc('place_order', { items: items.map((i) => ({ id: i.id, qty: i.quantity })) });")

INVOICE_FORM = """\
import { supabase } from '@/integrations/supabase/client';

export default function NewInvoice() {
  async function save(form) {
    await supabase.from('invoices').insert({ amount: form.amount, client: form.client });
  }
  return null;
}
"""

IPN_VALIDATE_ONLY = """\
Deno.serve(async (req) => {
  const data = await req.json();
  const tranId = data.tran_id;
  const valId = data.val_id;
  const check = await fetch(`https://sandbox.sslcommerz.com/validator/api/validationserverAPI.php?val_id=${valId}`);
  const result = await check.json();
  if (result.status === 'VALID') {
    await admin.from('orders').update({ payment_status: 'paid' }).eq('id', tranId);
  }
  return new Response('ok');
});
"""

IPN_COMPARED = IPN_VALIDATE_ONLY.replace(
    "  if (result.status === 'VALID') {",
    "  const { data: order } = await admin.from('orders').select('total').eq('id', tranId).single();\n"
    "  if (result.status === 'VALID' && Number(result.amount) === order.total && result.tran_id === tranId) {")

IPN_NO_CHECK = """\
Deno.serve(async (req) => {
  const data = await req.json();
  if (data.status === 'VALID') {
    await admin.from('orders').update({ payment_status: 'paid' }).eq('id', data.tran_id);
  }
  return new Response('ok');
});
"""

RAZORPAY_CONFIRM = """\
const keySecret = Deno.env.get('RAZORPAY_KEY_SECRET') || '';

Deno.serve(async (req) => {
  const { orderId, paymentId, signature } = await req.json();
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(keySecret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = await crypto.subtle.sign('HMAC', key, enc.encode(`${orderId}|${paymentId}`));
  if (toHex(mac) !== signature) return new Response('bad signature', { status: 400 });
  return new Response('ok');
});
"""

RAZORPAY_CONFIRM_FAIL_CLOSED = RAZORPAY_CONFIRM.replace(
    "  const { orderId, paymentId, signature }",
    "  if (!keySecret) return new Response('not configured', { status: 500 });\n  const { orderId, paymentId, signature }")


@pytest.mark.parametrize("name,rule,files,line,severity", [
    ("form field posted to the gateway", "pay-client-amount",
     {"supabase/functions/gateway-init/index.ts": GATEWAY_FORM_INIT}, 7, "high"),
    ("razorpay order amount from the body", "pay-client-amount",
     {"supabase/functions/create-order/index.ts": RAZORPAY_ORDER}, 7, "high"),
    ("browser inserts the order total", "pay-client-amount",
     {"package.json": PKG_VITE, "src/pages/Checkout.tsx": CHECKOUT_PAGE}, 12, "medium"),
    ("ipn validates but never compares", "pay-webhook-unverified",
     {"supabase/functions/gateway-ipn/index.ts": IPN_VALIDATE_ONLY}, 8, "medium"),
    ("ipn trusts the posted status", "pay-webhook-unverified",
     {"supabase/functions/sslcommerz-ipn/index.ts": IPN_NO_CHECK}, 4, "high"),
    ("hmac key falls back to empty", "pay-webhook-verify-optional",
     {"supabase/functions/confirm-razorpay-payment/index.ts": RAZORPAY_CONFIRM}, 1, "high"),
])
def test_other_gateways_fire(tmp_path, write_tree, scan_rules, name, rule, files, line, severity):
    found = hits(tmp_path, write_tree, scan_rules, files, rule)
    assert lines_of(found) == [line], name
    assert found[0].severity == severity, name


@pytest.mark.parametrize("name,rule,files", [
    ("gateway amount from the stored order", "pay-client-amount",
     {"supabase/functions/create-order/index.ts": RAZORPAY_ORDER_SAFE}),
    ("order placed through an rpc", "pay-client-amount",
     {"package.json": PKG_VITE, "src/pages/Checkout.tsx": CHECKOUT_PAGE_RPC}),
    ("user-entered invoice is not a cart", "pay-client-amount",
     {"package.json": PKG_VITE, "src/pages/NewInvoice.tsx": INVOICE_FORM}),
    ("ipn compares amount and id", "pay-webhook-unverified",
     {"supabase/functions/gateway-ipn/index.ts": IPN_COMPARED}),
    ("hmac key checked before use", "pay-webhook-verify-optional",
     {"supabase/functions/confirm-razorpay-payment/index.ts": RAZORPAY_CONFIRM_FAIL_CLOSED}),
])
def test_other_gateways_safe(tmp_path, write_tree, scan_rules, name, rule, files):
    assert hits(tmp_path, write_tree, scan_rules, files, rule) == [], name


IPN_POSTED_STATUS = """\
Deno.serve(async (req) => {
  const data = await req.json();
  const status = data.status;
  if (status === 'FAILED' || status === 'CANCELLED') {
    await admin.from('orders')
      .update({ payment_status: status.toLowerCase() })
      .eq('id', data.tran_id);
  }
  return new Response('ok', { status: 200 });
});
"""

IPN_POSTED_STATUS_SIGNED = IPN_POSTED_STATUS.replace(
    "  const data = await req.json();",
    "  const raw = await req.text();\n"
    "  if (!(await verifyGatewaySignature(raw, req.headers.get('x-signature')))) return new Response('no', { status: 401 });\n"
    "  const data = JSON.parse(raw);")

IPN_LOGS_POSTED_STATUS = """\
Deno.serve(async (req) => {
  const data = await req.json();
  await admin.from('ipn_logs').insert({ tran_id: data.tran_id, status: data.status });
  return new Response('ok', { status: 200 });
});
"""


def test_gateway_callback_status_from_post_fires(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules,
                 {"supabase/functions/sslcommerz-ipn/index.ts": IPN_POSTED_STATUS}, "pay-webhook-unverified")
    assert lines_of(found) == [6]
    assert found[0].severity == "medium" and "failed or cancelled" in found[0].message


@pytest.mark.parametrize("name,code", [
    ("signature checked first", IPN_POSTED_STATUS_SIGNED),
    ("posted status only logged", IPN_LOGS_POSTED_STATUS),
])
def test_gateway_callback_status_from_post_safe(tmp_path, write_tree, scan_rules, name, code):
    files = {"supabase/functions/sslcommerz-ipn/index.ts": code}
    assert hits(tmp_path, write_tree, scan_rules, files, "pay-webhook-unverified") == [], name


# ---------------------------------------------------------------------------
# Open redirect: more sinks, guards and messages
# ---------------------------------------------------------------------------

LOGIN_PUSH_CHAIN = """\
'use client';
import { useRouter, useSearchParams } from 'next/navigation';

export function SignIn() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const next = searchParams.get('next');
  async function done(response) {
    router.push(response?.url || next || '/home');
  }
  return null;
}
"""

PY_ALLOW_HELPER = """\
from django.shortcuts import redirect


def _allow_redirect(url):
    return url in SAFE_PATHS


def login_done(request):
    target = request.GET.get("next")
    if target and _allow_redirect(target):
        return redirect(target)
    return redirect("/")
"""

PHP_LOWER_HEADER = """\
<?php
if (isset($_GET['redirect'])) {
    header ("location: " . $_GET['redirect']);
    exit;
}
"""

EXPRESS_TO_PARAM = """\
app.get('/redirect', (req, res) => {
  const toUrl = req.query.to;
  res.redirect(toUrl);
});
"""

SUBSTRING_ALLOWLIST = """\
const allowlist = new Set(['https://github.com/acme', 'https://docs.acme.test']);

export const isRedirectAllowed = (url: string) => {
  let allowed = false;
  for (const allowedUrl of allowlist) {
    allowed = allowed || url.includes(allowedUrl);
  }
  return allowed;
};
"""

ORIGIN_ALLOWLIST = """\
const allowlist = new Set(['https://github.com', 'https://docs.acme.test']);

export const isRedirectAllowed = (url: string) => {
  try {
    return allowlist.has(new URL(url).origin);
  } catch {
    return false;
  }
};
"""


@pytest.mark.parametrize("name,files,expected", [
    ("php lowercase location header", {"redir.php": PHP_LOWER_HEADER}, [3]),
    ("to parameter", {"server.js": EXPRESS_TO_PARAM}, [3]),
    ("allowlist matched by substring", {"lib/security.ts": SUBSTRING_ALLOWLIST}, [6]),
    ("double slash check alone", {"package.json": PKG_NEXT, "app/auth/route.ts": SLASH2_NEW_URL}, [6]),
    ("flask netloc check alone", {"app.py": FLASK_NETLOC_ONLY}, [11]),
])
def test_open_redirect_more_shapes_fire(tmp_path, write_tree, scan_rules, name, files, expected):
    assert lines_of(hits(tmp_path, write_tree, scan_rules, files, "redirect-open")) == expected, name


@pytest.mark.parametrize("name,files", [
    ("python allow helper in a conjunct", {"accounts/views.py": PY_ALLOW_HELPER}),
    ("allowlist compared by origin", {"lib/security.ts": ORIGIN_ALLOWLIST}),
])
def test_open_redirect_more_shapes_safe(tmp_path, write_tree, scan_rules, name, files):
    assert hits(tmp_path, write_tree, scan_rules, files, "redirect-open") == [], name


def test_open_redirect_messages(tmp_path, write_tree, scan_rules):
    found = hits(tmp_path, write_tree, scan_rules, {"src/SignIn.tsx": LOGIN_PUSH_CHAIN}, "redirect-open")
    assert lines_of(found) == [9]
    assert "appended to the origin" not in found[0].message
    other = tmp_path / "other"
    found = hits(other, write_tree, scan_rules, {"package.json": PKG_NEXT, "app/auth/route.ts": SLASH2_NEW_URL},
                 "redirect-open")
    assert "backslash" in found[0].message


# ---------------------------------------------------------------------------
# Rule metadata and the reference files
# ---------------------------------------------------------------------------

PREFIXES = ("pay-", "abuse-", "csrf-", "redirect-")
REF_DIRS = [REPO_ROOT / "skills" / "preflight-audit" / "references",
            REPO_ROOT / "skills" / "secure-by-default" / "references"]
OWN_REFS = [REPO_ROOT / "skills" / "secure-by-default" / "references" / "payments-and-abuse.md",
            REPO_ROOT / "skills" / "preflight-audit" / "references" / "rotation.md"]


def _slug(heading):
    s = heading.strip().lower()
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", "-", s)


def _anchors(path):
    text = path.read_text(encoding="utf-8")
    return {_slug(h) for h in re.findall(r"^#{1,6}\s+(.+?)\s*$", text, re.M)}


def _ref_path(name):
    for d in REF_DIRS:
        if (d / name).is_file():
            return d / name
    return None


def test_rule_metadata():
    ids = [r.id for r in rl.RULES]
    assert len(ids) == len(set(ids))
    for r in rl.RULES:
        assert r.id.startswith(PREFIXES), r.id
        assert r.why and r.fp_trap and r.message and r.klass, r.id
        assert r.confidence in ("high", "medium", "low")
        if r.confidence != "high" or r.check is not None:
            assert r.needs_confirmation or r.id == "csrf-csurf-deprecated", r.id


def test_fix_refs_point_at_real_headings():
    for r in rl.RULES:
        name, _, anchor = r.fix_ref.partition("#")
        path = _ref_path(name)
        assert path is not None, r.fix_ref
        assert anchor in _anchors(path), r.fix_ref


def test_rotation_has_every_anchor_the_secret_scanner_uses():
    import _secret_patterns as sp
    anchors = _anchors(OWN_REFS[1])
    for ref in set(sp.ROTATION_REF.values()):
        name, _, anchor = ref.partition("#")
        assert name == "rotation.md" and anchor in anchors, ref


@pytest.mark.parametrize("path", OWN_REFS, ids=lambda p: p.name)
def test_reference_style(path):
    text = path.read_text(encoding="utf-8")
    assert chr(0x2014) not in text and chr(0x2013) not in text
    assert not any(0x2600 <= ord(c) <= 0x27BF or ord(c) >= 0x1F000 for c in text)
    assert text.rstrip().splitlines()[-1] == "LAST-VERIFIED: 2026-10-06"
    # payments-and-abuse.md also carries the Edge Function and other-gateway recipes.
    assert len(text.splitlines()) <= (240 if path.name == "payments-and-abuse.md" else 200)
    assert "\r" not in text
