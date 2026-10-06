import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const body = await req.json().catch(() => ({}));
  const messages = body.messages || [{ role: "user", content: body.prompt || "" }];
  const base = process.env.OPENAI_API_BASE || "http://127.0.0.1:54723/v1";
  const key = process.env.OPENAI_API_KEY || "";
  const r = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages }),
  });
  const data = await r.json();
  const reply = data?.choices?.[0]?.message?.content ?? "";
  return NextResponse.json({ reply });
}
