import { NextResponse } from "next/server";
import dns from "dns/promises";
import net from "net";

export const dynamic = "force-dynamic";

function isBlockedIp(ip: string): boolean {
  if (ip === "::1" || ip.startsWith("fc") || ip.startsWith("fd") || ip.startsWith("fe80")) {
    return true;
  }
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => isNaN(n))) return false;
  const [a, b] = parts;
  if (a === 127 || a === 10 || a === 0) return true;
  if (a === 169 && b === 254) return true; // link-local / cloud metadata
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  return false;
}

export async function GET(req: Request) {
  const target = new URL(req.url).searchParams.get("url");
  if (!target) return NextResponse.json({ error: "missing url" }, { status: 400 });
  let u: URL;
  try {
    u = new URL(target);
  } catch {
    return NextResponse.json({ error: "bad url" }, { status: 400 });
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    return NextResponse.json({ error: "scheme not allowed" }, { status: 400 });
  }
  const host = u.hostname;
  if (host === "localhost") {
    return NextResponse.json({ error: "blocked host" }, { status: 400 });
  }
  let ip = host;
  if (!net.isIP(host)) {
    try {
      const resolved = await dns.lookup(host);
      ip = resolved.address;
    } catch {
      return NextResponse.json({ error: "cannot resolve" }, { status: 400 });
    }
  }
  if (isBlockedIp(ip)) {
    return NextResponse.json({ error: "blocked host" }, { status: 400 });
  }
  const r = await fetch(u.toString(), { cache: "no-store" });
  const text = await r.text();
  return new NextResponse(text.slice(0, 2000), {
    headers: { "Content-Type": "text/plain" },
  });
}
