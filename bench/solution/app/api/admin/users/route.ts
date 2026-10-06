import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getProfile } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const profile = await getProfile();
  if (!profile || profile.role !== "admin") {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  const { data } = await db.from("profiles").select("id,email,role,credits");
  return NextResponse.json(data || []);
}
