import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const q = new URL(req.url).searchParams.get("q") || "";
  const sql =
    "SELECT id, user_id, title, content FROM notes WHERE user_id = '" +
    user.id +
    "' AND title LIKE '%" +
    q +
    "%'";
  const { data } = await db.rpc("search", { sql });
  return NextResponse.json(data || []);
}
