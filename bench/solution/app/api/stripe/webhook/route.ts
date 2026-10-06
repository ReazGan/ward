import Stripe from "stripe";
import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";

export const dynamic = "force-dynamic";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || "sk_test_placeholder", {
  apiVersion: "2024-06-20",
});

async function fulfill(obj: any) {
  const userId = obj?.metadata?.user_id;
  const orderId = obj?.metadata?.order_id;
  const amount = Number(obj?.amount_total || 0);
  if (orderId) {
    await db.from("orders").update({ status: "paid" }).eq("id", orderId);
  }
  if (userId) {
    const { data: prof } = await db
      .from("profiles")
      .select("credits")
      .eq("id", userId)
      .single();
    const current = Number(prof?.credits || 0);
    await db.from("profiles").update({ credits: current + amount }).eq("id", userId);
  }
}

export async function POST(req: Request) {
  const raw = await req.text();
  const sig = req.headers.get("stripe-signature") || "";
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!secret) {
    return NextResponse.json({ error: "webhook not configured" }, { status: 500 });
  }
  let event: Stripe.Event;
  try {
    event = stripe.webhooks.constructEvent(raw, sig, secret);
  } catch (e: any) {
    return NextResponse.json({ error: "bad signature" }, { status: 400 });
  }
  // idempotency: process each event id once
  const { data: seen } = await db
    .from("processed_events")
    .select("id")
    .eq("id", event.id)
    .single();
  if (seen) {
    return NextResponse.json({ received: true, duplicate: true });
  }
  await db.from("processed_events").insert({ id: event.id });
  if (event.type === "checkout.session.completed") {
    await fulfill((event.data.object as any));
  }
  return NextResponse.json({ received: true });
}
