/**
 * 搜索词高亮：把文本按不区分大小写的整串匹配拆成普通与命中片段，
 * 命中渲染 <mark>。纯文本拆分渲染（不走 innerHTML），无注入面；
 * 行为对齐后端搜索（SQLite LIKE 对 ASCII 大小写不敏感）。
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
