import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const { searchParams, origin } = new URL(req.url);
  const next = searchParams.get("next") || "/dashboard";
  // send the user where they were headed
  return NextResponse.redirect(new URL(next, origin));
}
