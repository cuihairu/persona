<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { withBase } from "vitepress";

interface Slide {
  src: string;
  alt: string;
  title: string;
  desc: string;
  link?: { href: string; text: string };
}

// 桌面素材源在 docs/branding/ui/（README 同款），站点副本 docs/src/public/ui/。
// 手机原型图到位后在此追加，走马灯与 previews 页共用同一批源文件。
const slides: Slide[] = [
  {
    src: "/ui/light-full.png",
    alt: "亮色主题全窗",
    title: "亮色主题 · 全窗",
    desc: "三栏布局：左侧身份切换与分组导航，中间凭据列表，右侧常驻详情面板。",
  },
  {
    src: "/ui/dark-full.png",
    alt: "暗色主题全窗",
    title: "暗色主题 · 全窗",
    desc: "同一布局的深色形态，语义色 token 随主题整体翻转，不做简单反色。",
  },
  {
    src: "/ui/light-sidebar.png",
    alt: "亮色侧栏特写",
    title: "侧栏特写 · 亮色",
    desc: "1Password 风格分组导航：类别、保险库、标签与工具区一栏收纳。",
  },
  {
    src: "/ui/dark-sidebar.png",
    alt: "暗色侧栏特写",
    title: "侧栏特写 · 暗色",
    desc: "同结构的深色形态。",
  },
  {
    src: "/ui/sidebar-before-redesign.png",
    alt: "侧栏重设计前",
    title: "重设计前",
    desc: "平铺面板菜单、英文枚举类别——与上方特写构成前后对照。",
  },
  {
    src: "/ui/mobile-android-home.png",
    alt: "Android 移动端主界面",
    title: "移动端 · Android",
    desc: "原生 Kotlin + JNI 桥真实构建运行的主界面（保险库 / 底部导航），iOS 与鸿蒙原型仍暂缺。",
  },
];

const index = ref(0);
const paused = ref(false);
let timer: number | undefined;

const prefersReducedMotion = () =>
  typeof window !== "undefined" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const slide = computed(() => slides[index.value]);

function goTo(i: number) {
  index.value = (i + slides.length) % slides.length;
  restart();
}

function next() {
  if (paused.value) return;
  index.value = (index.value + 1) % slides.length;
}

function restart() {
  stop();
  if (prefersReducedMotion()) return;
  timer = window.setInterval(next, 5000);
}

function stop() {
  if (timer !== undefined) {
    window.clearInterval(timer);
    timer = undefined;
  }
}

function pause() {
  paused.value = true;
  stop();
}

function resume() {
  paused.value = false;
  restart();
}

onMounted(restart);
onBeforeUnmount(stop);
</script>

<template>
  <div
    class="ui-carousel"
    role="region"
    aria-roledescription="carousel"
    aria-label="界面预览走马灯"
    @mouseenter="pause"
    @mouseleave="resume"
    @focusin="pause"
    @focusout="resume"
  >
    <div class="stage">
      <Transition name="fade" mode="out-in">
        <figure
          :key="slide.src"
          role="group"
          aria-roledescription="slide"
          :aria-label="`${index + 1} / ${slides.length}`"
        >
          <img
            :src="withBase(slide.src)"
            :alt="slide.alt"
            :loading="index === 0 ? 'eager' : 'lazy'"
            decoding="async"
          />
        </figure>
      </Transition>

      <button
        class="arrow prev"
        type="button"
        aria-label="上一张"
        @click="goTo(index - 1)"
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M15 5l-7 7 7 7"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
      <button
        class="arrow next"
        type="button"
        aria-label="下一张"
        @click="goTo(index + 1)"
      >
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M9 5l7 7-7 7"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
    </div>

    <figcaption class="caption">
      <div class="caption-text">
        <strong>{{ slide.title }}</strong>
        <span>{{ slide.desc }}</span>
      </div>
      <div class="dots" role="tablist" aria-label="选择幻灯片">
        <button
          v-for="(s, i) in slides"
          :key="s.src"
          type="button"
          role="tab"
          class="dot"
          :class="{ active: i === index }"
          :aria-selected="i === index"
          :aria-label="`第 ${i + 1} 张：${s.title}`"
          @click="goTo(i)"
        />
      </div>
    </figcaption>
  </div>
</template>

<style scoped>
.ui-carousel {
  margin: 32px auto 8px;
  max-width: 1040px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 16px;
  background: var(--vp-c-bg-soft);
  overflow: hidden;
}

.stage {
  position: relative;
  height: clamp(260px, 42vw, 540px);
  background: var(--vp-c-bg-alt);
}

.stage figure {
  position: absolute;
  inset: 0;
  margin: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}

.stage img {
  max-width: 100%;
  max-height: 100%;
  object-fit: contain;
  border-radius: 8px;
  box-shadow: 0 8px 32px rgba(0, 0, 0, 0.18);
}

.fade-enter-active,
.fade-leave-active {
  transition: opacity 0.35s ease;
}

.fade-enter-from,
.fade-leave-to {
  opacity: 0;
}

.arrow {
  position: absolute;
  top: 50%;
  transform: translateY(-50%);
  width: 40px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--vp-c-divider);
  border-radius: 50%;
  background: var(--vp-c-bg-soft);
  color: var(--vp-c-text-2);
  cursor: pointer;
  opacity: 0;
  transition: opacity 0.2s ease, color 0.2s ease, border-color 0.2s ease;
}

.ui-carousel:hover .arrow,
.ui-carousel:focus-within .arrow {
  opacity: 1;
}

.arrow:hover {
  color: var(--vp-c-brand-1);
  border-color: var(--vp-c-brand-1);
}

.arrow svg {
  width: 20px;
  height: 20px;
}

.arrow.prev {
  left: 14px;
}

.arrow.next {
  right: 14px;
}

.caption {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 14px 20px;
}

.caption-text {
  display: flex;
  flex-direction: column;
  gap: 2px;
  text-align: left;
  min-width: 0;
}

.caption-text strong {
  font-size: 14px;
  color: var(--vp-c-text-1);
}

.caption-text span {
  font-size: 13px;
  line-height: 1.5;
  color: var(--vp-c-text-2);
}

.dots {
  display: flex;
  gap: 8px;
  flex-shrink: 0;
}

.dot {
  width: 8px;
  height: 8px;
  padding: 0;
  border: none;
  border-radius: 50%;
  background: var(--vp-c-default-3);
  cursor: pointer;
  transition: background 0.2s ease, transform 0.2s ease;
}

.dot.active {
  background: var(--vp-c-brand-1);
  transform: scale(1.25);
}

@media (max-width: 640px) {
  .caption {
    flex-direction: column;
    align-items: flex-start;
    gap: 10px;
  }

  .arrow {
    opacity: 0.85;
  }
}

@media (prefers-reduced-motion: reduce) {
  .fade-enter-active,
  .fade-leave-active {
    transition: none;
  }
}
</style>
