import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";
import { priceFor } from "@/app/lib/catalog";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { plan } = await req.json();
  // price comes from the server catalog, never from the request body
  const amount = priceFor(plan);
  if (amount == null) {
    return NextResponse.json({ error: "unknown plan" }, { status: 400 });
  }
  const orderId = randomUUID();
  await db.from("orders").insert({
    id: orderId,
    user_id: user.id,
    product: plan,
    amount,
    status: "pending",
  });
  const base = process.env.STRIPE_API_BASE || "http://127.0.0.1:54722";
  const r = await fetch(`${base}/v1/checkout/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      amount,
      metadata: { user_id: user.id, order_id: orderId },
    }),
  });
  const session = await r.json();
  return NextResponse.json({
    url: session.url,
    session_id: session.id,
    amount_total: session.amount_total,
  });
}
