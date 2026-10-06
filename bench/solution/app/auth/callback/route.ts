import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

function safeNext(next: string | null): string {
  if (
    typeof next !== "string" ||
    !next.startsWith("/") ||
    next.startsWith("//") ||
    next.startsWith("/\\")
  ) {
    return "/dashboard";
  }
  return next;
}

export async function GET(req: Request) {
  const { searchParams, origin } = new URL(req.url);
  const next = safeNext(searchParams.get("next"));
  return NextResponse.redirect(new URL(next, origin));
}
