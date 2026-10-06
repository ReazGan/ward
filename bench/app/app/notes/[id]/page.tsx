import { db } from "@/app/lib/db";
import Message from "@/app/components/Message";

export const dynamic = "force-dynamic";

// Public, shareable note view.
export default async function NotePage({ params }: { params: { id: string } }) {
  const { data: note } = await db
    .from("notes")
    .select("*")
    .eq("id", params.id)
    .single();

  if (!note) {
    return <main style={{ padding: 32 }}><p>Note not found.</p></main>;
  }

  return (
    <main style={{ padding: 32, maxWidth: 720 }}>
      <h1>{note.title}</h1>
      <Message content={note.content || ""} />
    </main>
  );
}
