import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getUser } from "./auth";

// Data access layer. This is the real enforcement point: every protected
// page and route calls requireUser(), so proxy.ts only needs to be optimistic.
export async function requireUser() {
  const token = cookies().get("session")?.value;
  if (!token) redirect("/login");
  const user = await getUser();
  if (!user) redirect("/login");
  return user;
}
