"use client";
import { useState } from "react";
import Message from "./Message";

export default function Chat() {
  const [input, setInput] = useState("");
  const [reply, setReply] = useState("");

  async function send() {
    // the provider key stays on the server; the browser only talks to the proxy
    const r = await fetch("/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
