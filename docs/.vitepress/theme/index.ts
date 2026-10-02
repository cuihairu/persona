import { h } from "vue";
import DefaultTheme from "vitepress/theme";
import type { Theme } from "vitepress";
import MermaidRenderer from "./MermaidRenderer.vue";
import UiCarousel from "./UiCarousel.vue";
import "./custom.css";

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    // 首页 index.md 里以 <UiCarousel /> 挂载的走马灯
    app.component("UiCarousel", UiCarousel);
  },
  Layout: () =>
    h(DefaultTheme.Layout, null, {
      // layout-bottom：客户端组件，把正文里的 ```mermaid 块替换成渲染后的 SVG
      "layout-bottom": () => h(MermaidRenderer),
    }),
} satisfies Theme;
