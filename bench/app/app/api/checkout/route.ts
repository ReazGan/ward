import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const user = await getUser();
  const { plan, amount } = await req.json();
  const orderId = randomUUID();
  const chargeAmount = Number(amount);
  await db.from("orders").insert({
    id: orderId,
    user_id: user?.id,
    product: plan,
    amount: chargeAmount,
    status: "pending",
  });
  const base = process.env.STRIPE_API_BASE || "http://127.0.0.1:54722";
  const r = await fetch(`${base}/v1/checkout/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      amount: chargeAmount,
      metadata: { user_id: user?.id, order_id: orderId },
    }),
  });
  const session = await r.json();
  return NextResponse.json({
    url: session.url,
    session_id: session.id,
    amount_total: session.amount_total,
  });
}
