import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import MermaidRenderer from "./MermaidRenderer.vue";
import "./custom.css";

export default {
  extends: DefaultTheme,
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      // layout-bottom：客户端组件，把正文里的 ```mermaid 块替换成渲染后的 SVG
      "layout-bottom": () => h(MermaidRenderer),
    }),
} satisfies Theme;
