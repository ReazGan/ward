// Renders a chat or note body as plain text. React escapes it, so user and
// model content cannot inject markup.
export default function Message({ content }: { content: string }) {
  return <div className="message">{content}</div>;
}
