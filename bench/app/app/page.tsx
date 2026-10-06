import Link from "next/link";
import Markdown from "./components/Markdown";

export default function Home() {
  return (
    <main style={{ padding: 32, maxWidth: 720 }}>
      <h1>Notesly</h1>
      <Markdown text={"Keep your **notes**, place **orders**, and ask the built-in assistant."} />
      <p>
        <Link href="/login">Log in</Link> &middot; <Link href="/dashboard">Dashboard</Link>
      </p>
    </main>
  );
}
