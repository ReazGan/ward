import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";

export const dynamic = "force-dynamic";

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
  const event = JSON.parse(raw);
  if (event.type === "checkout.session.completed") {
    await fulfill(event.data.object);
  }
  return NextResponse.json({ received: true });
}
