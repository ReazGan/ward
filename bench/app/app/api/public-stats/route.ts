import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";

export const dynamic = "force-dynamic";

// Public, read-only aggregate numbers for the marketing page.
export async function GET() {
  const { data: notes } = await db.from("notes").select("id");
  const { data: posts } = await db.from("posts").select("id");
  const payload = {
    notes: (notes || []).length,
    posts: (posts || []).length,
  };
  // public data, no credentials, any origin may read it
  return NextResponse.json(payload, {
    headers: { "Access-Control-Allow-Origin": "*" },
  });
}
