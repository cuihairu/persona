import '@testing-library/jest-dom';
// i18n 基准语言 zh-CN：模块加载即同步初始化，组件测试断言用中文文案
import '@/i18n';

// headlessui v2 的 Listbox 关闭路径依赖 ResizeObserver（jsdom 未实现）
if (typeof window !== 'undefined' && !window.ResizeObserver) {
  window.ResizeObserver = class ResizeObserver {
    observe() {}
    unobserve() {}
    disconnect() {}
  } as unknown as typeof ResizeObserver;
}
