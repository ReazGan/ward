import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ errors: [{ message: "unauthorized" }] }, { status: 401 });
  const { query } = await req.json();

  const orderMatch = String(query || "").match(/order\s*\(\s*id:\s*"([^"]+)"\s*\)/);
  if (orderMatch) {
    const { data } = await db
      .from("orders")
      .select("*")
      .eq("id", orderMatch[1])
      .single();
    // only return the order if it belongs to the caller
    if (!data || data.user_id !== user.id) {
      return NextResponse.json({ data: { order: null } });
    }
    return NextResponse.json({ data: { order: data } });
  }

  if (/\bme\b/.test(String(query || ""))) {
    const { data } = await db
      .from("profiles")
      .select("id,email,full_name")
      .eq("id", user.id)
      .single();
    return NextResponse.json({ data: { me: data || null } });
  }

  return NextResponse.json({ data: null });
}
