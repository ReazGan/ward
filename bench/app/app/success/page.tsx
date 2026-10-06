import { db } from "@/app/lib/db";

export const dynamic = "force-dynamic";

async function fulfillFromSession(sessionId: string) {
  const base = process.env.STRIPE_API_BASE || "http://127.0.0.1:54722";
  const r = await fetch(`${base}/v1/checkout/sessions/${sessionId}`, {
    cache: "no-store",
  });
  if (!r.ok) return null;
  const session = await r.json();
  const orderId = session?.metadata?.order_id;
  // grant access based on the landing page visit
  if (orderId) {
    await db.from("orders").update({ status: "paid" }).eq("id", orderId);
  }
  return session;
}

export default async function SuccessPage({
  searchParams,
}: {
  searchParams: { session_id?: string };
}) {
  const sessionId = searchParams.session_id;
  let session: any = null;
  if (sessionId) {
    session = await fulfillFromSession(sessionId);
  }
  return (
    <main style={{ padding: 32 }}>
      <h1>Thank you</h1>
      <p>Your order is confirmed.</p>
      {session ? <p>Reference: {session.id}</p> : null}
    </main>
  );
}
