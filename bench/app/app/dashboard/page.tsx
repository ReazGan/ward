import { requireUser } from "@/app/lib/dal";
import { db } from "@/app/lib/db";
import Chat from "@/app/components/Chat";

export const dynamic = "force-dynamic";

export default async function Dashboard() {
  // real enforcement happens here, not in middleware
  const user = await requireUser();
  const { data: notes } = await db
    .from("notes")
    .select("*")
    .eq("user_id", user.id);

  return (
    <main style={{ padding: 32, maxWidth: 720 }}>
      <h1>Your notes</h1>
      <ul>
        {(notes || []).map((n: any) => (
          <li key={n.id}>{n.title}</li>
        ))}
      </ul>
      <h2>Assistant</h2>
      <Chat />
    </main>
  );
}
