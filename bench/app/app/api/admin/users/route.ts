import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";

export const dynamic = "force-dynamic";

export async function GET() {
  const { data } = await db.from("profiles").select("id,email,role,credits");
  return NextResponse.json(data || []);
}
