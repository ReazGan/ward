import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await db.from("orders").select("*").eq("user_id", user.id);
  return NextResponse.json(data || []);
}
