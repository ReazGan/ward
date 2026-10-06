"use client";
import DOMPurify from "dompurify";

// Renders HTML after sanitizing it with DOMPurify.
export default function SafeHtml({ html }: { html: string }) {
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
