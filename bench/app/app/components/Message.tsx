// Renders a chat or note body as rich text.
export default function Message({ content }: { content: string }) {
  return (
    <div className="message" dangerouslySetInnerHTML={{ __html: content }} />
  );
}
