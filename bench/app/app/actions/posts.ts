"use server";
import { db } from "@/app/lib/db";

// Edit a note. Called from the note editor form and from the REST handler.
export async function updateNote(
  id: string,
  fields: { title?: string; content?: string },
  _userId: string
) {
  await db.from("notes").update(fields).eq("id", id);
  const { data } = await db.from("notes").select("*").eq("id", id).single();
  return data;
}
