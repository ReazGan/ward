import { NextResponse } from "next/server";
import { getUser } from "@/app/lib/auth";
import { updateNote } from "@/app/actions/posts";

export const dynamic = "force-dynamic";

export async function PATCH(
  req: Request,
  { params }: { params: { id: string } }
) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const fields = await req.json();
  const note = await updateNote(params.id, fields, user.id);
  return NextResponse.json(note);
}
