"use server";
import { db } from "@/app/lib/db";

// Edit a note. The note must belong to the caller.
export async function updateNote(
  id: string,
  fields: { title?: string; content?: string },
  userId: string
) {
  const { data: existing } = await db
    .from("notes")
    .select("user_id")
    .eq("id", id)
    .single();
  if (!existing || existing.user_id !== userId) {
    return null;
  }
  const allowed: { title?: string; content?: string } = {};
  if (typeof fields.title === "string") allowed.title = fields.title;
  if (typeof fields.content === "string") allowed.content = fields.content;
  await db.from("notes").update(allowed).eq("id", id);
  const { data } = await db.from("notes").select("*").eq("id", id).single();
  return data;
}
