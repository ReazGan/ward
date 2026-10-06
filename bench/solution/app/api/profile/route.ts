import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser, getProfile } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const profile = await getProfile();
  if (!profile) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  return NextResponse.json(profile);
}

export async function PATCH(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const body = await req.json();
  // allow-list the fields a user may change; role and credits are server-owned
  const update: { full_name?: string; bio?: string } = {};
  if (typeof body.full_name === "string") update.full_name = body.full_name;
  if (typeof body.bio === "string") update.bio = body.bio;
  await db.from("profiles").update(update).eq("id", user.id);
  const { data } = await db.from("profiles").select("*").eq("id", user.id).single();
  return NextResponse.json(data);
}
