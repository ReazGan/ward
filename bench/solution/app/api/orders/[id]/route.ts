import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

export async function GET(
  _req: Request,
  { params }: { params: { id: string } }
) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { data } = await db
    .from("orders")
    .select("*")
    .eq("id", params.id)
    .single();
  if (!data) return NextResponse.json({ error: "not found" }, { status: 404 });
  // this order must belong to the caller
  if (data.user_id !== user.id) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }
  return NextResponse.json(data);
}
