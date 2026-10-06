import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get("url");
  if (!target) return NextResponse.json({ error: "missing url" }, { status: 400 });
  const r = await fetch(target, { cache: "no-store" });
  const text = await r.text();
  return new NextResponse(text.slice(0, 2000), {
    headers: { "Content-Type": "text/plain" },
  });
}
