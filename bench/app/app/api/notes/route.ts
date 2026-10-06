import { NextResponse } from "next/server";
import { randomUUID } from "crypto";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET() {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await db.from("notes").select("*").eq("user_id", user.id);
  return NextResponse.json(data || []);
}

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { title, content } = await req.json();
  const id = randomUUID();
  await db.from("notes").insert({
    id,
    user_id: user.id,
    title: title || "Untitled",
    content: content || "",
    is_public: true,
  });
  return NextResponse.json({ id });
}
