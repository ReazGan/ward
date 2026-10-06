import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Optimistic redirect only. Real auth is enforced in the data access layer
// (app/lib/dal.ts), which every protected page and route calls.
export function middleware(req: NextRequest) {
  const hasSession = Boolean(req.cookies.get("session")?.value);
  const path = req.nextUrl.pathname;
  if (!hasSession && path.startsWith("/dashboard")) {
    return NextResponse.redirect(new URL("/login", req.nextUrl));
  }
  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
