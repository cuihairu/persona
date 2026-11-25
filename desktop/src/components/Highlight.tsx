/**
 * Search-term highlighting: split the text into plain and hit fragments by
 * case-insensitive whole-string match, rendering hits as <mark>. Plain text
 * splitting only (no innerHTML), so there is no injection surface; the behavior
 * matches the backend search (SQLite LIKE is case-insensitive for ASCII).
 */
const Highlight = ({ text, query }: { text: string; query: string }) => {
  const needle = query.trim();
  if (!needle) {
    return <>{text}</>;
  }
  const lower = text.toLowerCase();
  const target = needle.toLowerCase();
  const parts: { text: string; hit: boolean }[] = [];
  let from = 0;
  let at = lower.indexOf(target);
  while (at !== -1) {
    if (at > from) {
      parts.push({ text: text.slice(from, at), hit: false });
    }
    parts.push({ text: text.slice(at, at + target.length), hit: true });
    from = at + target.length;
    at = lower.indexOf(target, from);
  }
  if (from < text.length) {
    parts.push({ text: text.slice(from), hit: false });
  }
  return (
    <>
      {parts.map((part, index) =>
        part.hit ? (
          <mark
            key={index}
            data-testid="highlight-hit"
            className="bg-yellow-200/80 dark:bg-yellow-500/30 text-inherit rounded-sm px-0.5"
          >
            {part.text}
          </mark>
        ) : (
          <span key={index}>{part.text}</span>
        ),
      )}
    </>
  );
};

export default Highlight;
