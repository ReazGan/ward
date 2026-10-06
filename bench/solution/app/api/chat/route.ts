import { NextResponse } from "next/server";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

const hits = new Map<string, { n: number; ts: number }>();
function overLimit(id: string) {
  const now = Date.now();
  const w = hits.get(id);
  if (!w || now - w.ts > 60000) {
    hits.set(id, { n: 1, ts: now });
    return false;
  }
  w.n += 1;
  return w.n > 20;
}

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  if (overLimit(user.id)) {
    return NextResponse.json({ error: "rate limited" }, { status: 429 });
  }
  const body = await req.json().catch(() => ({}));
  const prompt = typeof body.prompt === "string" ? body.prompt : "";
  if (prompt.length > 4000) {
    return NextResponse.json({ error: "prompt too long" }, { status: 400 });
  }
  const messages = body.messages || [{ role: "user", content: prompt }];
  const base = process.env.OPENAI_API_BASE || "http://127.0.0.1:54723/v1";
  const key = process.env.OPENAI_API_KEY || "";
  const r = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages, max_tokens: 512 }),
  });
  const data = await r.json();
  const reply = data?.choices?.[0]?.message?.content ?? "";
  return NextResponse.json({ reply });
}
