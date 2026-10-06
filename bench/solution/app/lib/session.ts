import { NextResponse } from "next/server";

// Attaches the session cookie after login with safe flags.
export function setSessionCookie(res: NextResponse, token: string) {
  res.cookies.set("session", token, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 60 * 60 * 8,
  });
  return res;
}

export function clearSessionCookie(res: NextResponse) {
  res.cookies.set("session", "", {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 0,
  });
  return res;
}
