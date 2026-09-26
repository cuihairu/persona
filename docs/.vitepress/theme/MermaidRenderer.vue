<script setup lang="ts">
import { nextTick, onMounted, watch } from "vue";
import { useData, useRoute } from "vitepress";

// VitePress 默认把 ```mermaid 围栏当普通代码块做 shiki 高亮，不渲染图形。
// 这里在客户端把 .language-mermaid 块替换成 mermaid 生成的 SVG。
// mermaid 体积大，按需动态 import：页面里没有图就不拉这个包。
const route = useRoute();
const { isDark } = useData();

/** 原始 mermaid 源码按元素留底——深浅色切换时 SVG 里的主题色是烧死的，需要整块重渲 */
const sources = new WeakMap<HTMLElement, string>();
let mermaid: (typeof import("mermaid"))["default"] | null = null;
let seq = 0;

const renderBlock = async (block: HTMLElement, code: string) => {
  if (!mermaid) return;
  try {
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: isDark.value ? "dark" : "default",
    });
    const { svg } = await mermaid.render(`persona-mermaid-${++seq}`, code);
    block.classList.add("mermaid-rendered");
    block.querySelector("button.copy")?.remove();
    block.innerHTML = svg;
    sources.set(block, code);
  } catch (error) {
    // 渲染失败保留原代码块，不把整页炸掉
    console.warn("[mermaid] render failed:", error);
  }
};

const scan = async () => {
  const blocks = [
    ...document.querySelectorAll<HTMLElement>(
      ".vp-doc div.language-mermaid:not([data-mermaid-state])",
    ),
  ];
  if (!blocks.length) return;
  mermaid ??= (await import("mermaid")).default;
  for (const block of blocks) {
    block.dataset.mermaidState = "pending";
    const code = block.querySelector("code")?.textContent ?? "";
    if (code.trim()) await renderBlock(block, code);
    block.dataset.mermaidState = "done";
  }
};

onMounted(() => {
  void scan();
});

watch(
  () => route.path,
  () => nextTick(() => void scan()),
);

watch(isDark, () => {
  document
    .querySelectorAll<HTMLElement>(".vp-doc div.language-mermaid.mermaid-rendered")
    .forEach((block) => {
      const code = sources.get(block);
      if (code) void renderBlock(block, code);
    });
});
</script>

<template>
  <div hidden aria-hidden="true"></div>
</template>

<style>
.vp-doc .language-mermaid.mermaid-rendered {
  display: flex;
  justify-content: center;
  padding: 12px 0;
}
.vp-doc .language-mermaid.mermaid-rendered svg {
  max-width: 100%;
  height: auto;
}
</style>
