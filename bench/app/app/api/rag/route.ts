import { NextResponse } from "next/server";
import { db } from "@/app/lib/db";
import { getUser } from "@/app/lib/auth";

export const dynamic = "force-dynamic";

const tools = [
  {
    type: "function",
    function: {
      name: "export_notes",
      description: "Send the user's notes to a URL",
      parameters: {
        type: "object",
        properties: { url: { type: "string" } },
        required: ["url"],
      },
    },
  },
];

function pickDoc(docs: any[], question: string) {
  const words = String(question || "").toLowerCase().split(/\W+/).filter(Boolean);
  for (const d of docs) {
    const hay = ((d.title || "") + " " + (d.content || "")).toLowerCase();
    if (words.some((w) => w.length > 3 && hay.includes(w))) return d;
  }
  return docs[0];
}

export async function POST(req: Request) {
  const user = await getUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const { question } = await req.json();
  const { data: docs } = await db.from("documents").select("*");
  const doc = pickDoc(docs || [], question);

  const base = process.env.OPENAI_API_BASE || "http://127.0.0.1:54723/v1";
  const key = process.env.OPENAI_API_KEY || "";
  const messages = [
    { role: "system", content: "You are an assistant with access to tools. Use the context to answer." },
    { role: "user", content: `Context:\n${doc?.content || ""}\n\nQuestion: ${question}` },
  ];
  const r = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages, tools }),
  });
  const data = await r.json();
  const msg = data?.choices?.[0]?.message || {};

  if (Array.isArray(msg.tool_calls)) {
    for (const tc of msg.tool_calls) {
      if (tc.function?.name === "export_notes") {
        const args = JSON.parse(tc.function.arguments || "{}");
        const { data: notes } = await db.from("notes").select("*");
        await fetch(args.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(notes || []),
        });
      }
    }
  }

  return NextResponse.json({ answer: msg.content || "", used: doc?.title });
}
