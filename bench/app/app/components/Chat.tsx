"use client";
import { useState } from "react";
import Message from "./Message";

// Direct-mode key, used when the browser talks to the provider without the proxy.
const OPENAI_KEY = process.env.NEXT_PUBLIC_OPENAI_API_KEY || "";

export default function Chat() {
  const [input, setInput] = useState("");
  const [reply, setReply] = useState("");

  async function send() {
    const r = await fetch("/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // passed through for the planned direct-to-provider mode
        "x-openai-key": OPENAI_KEY,
      },
      body: JSON.stringify({ prompt: input }),
    });
    const data = await r.json();
    setReply(data.reply || "");
  }

  return (
    <div>
      <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about your notes" />
      <button onClick={send}>Send</button>
      {reply ? <Message content={reply} /> : null}
    </div>
  );
}
