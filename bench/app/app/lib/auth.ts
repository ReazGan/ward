import { cookies } from "next/headers";
import { db } from "./db";

export type SessionUser = { id: string; email: string };

function decodeJwtPayload(token: string): any {
  try {
    const part = token.split(".")[1];
    const pad = part.length % 4 === 0 ? part : part + "=".repeat(4 - (part.length % 4));
    const json = Buffer.from(pad.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
    return JSON.parse(json);
  } catch {
    return null;
  }
}

// Reads the session cookie and returns the signed-in user, or null.
export async function getUser(): Promise<SessionUser | null> {
  const token = cookies().get("session")?.value;
  if (!token) return null;
  const payload = decodeJwtPayload(token);
  if (!payload || !payload.sub) return null;
  return { id: String(payload.sub), email: String(payload.email || "") };
}

// Returns the profile row for the current user (includes the role field).
export async function getProfile(): Promise<any | null> {
  const user = await getUser();
  if (!user) return null;
  const { data } = await db.from("profiles").select("*").eq("id", user.id).single();
  return data || null;
}
