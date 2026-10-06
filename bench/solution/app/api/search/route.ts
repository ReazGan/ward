import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const q = new URL(req.url).searchParams.get("q") || "";
  // parameterized: the search term is bound, never concatenated into the SQL
  const sql =
    "SELECT id, user_id, title, content FROM notes WHERE user_id = ? AND title LIKE ?";
  const params = [user.id, "%" + q + "%"];
  const { data } = await db.rpc("search", { sql, params });
  return NextResponse.json(data || []);
}
