import { NextResponse } from "next/server";

// Attaches the session cookie to a response after login.
export function setSessionCookie(res: NextResponse, token: string) {
  res.cookies.set("session", token, {
    path: "/",
    maxAge: 60 * 60 * 8,
  });
  return res;
}

export function clearSessionCookie(res: NextResponse) {
  res.cookies.set("session", "", { path: "/", maxAge: 0 });
  return res;
}
