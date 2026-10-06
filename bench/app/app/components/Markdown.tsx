"use client";
import ReactMarkdown from "react-markdown";

// react-markdown is safe by default: no raw HTML passthrough (no rehype-raw).
export default function Markdown({ text }: { text: string }) {
  return <ReactMarkdown>{text}</ReactMarkdown>;
}
