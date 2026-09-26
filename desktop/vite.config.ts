import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // 更新检测的渠道元信息（src/utils/updateCheck.ts 读 __PERSONA_BUILD__）。
  // desktop-build.yml（每日构建）注入 nightly + commit + 构建时间；未来的
  // 发版流水线注入 release；本地不注入 → dev（不参与版本比对）。
  define: {
    __PERSONA_BUILD__: JSON.stringify({
      channel: process.env.VITE_UPDATE_CHANNEL ?? "dev",
      sha: process.env.VITE_BUILD_SHA ?? "",
      builtAt: process.env.VITE_BUILD_TIME ?? "",
    }),
  },

  // Path resolution
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
  },
  // 3. to make use of `TAURI_DEBUG` and other env variables
  // https://tauri.studio/v1/api/config#buildconfig.beforedevcommand
  envPrefix: ["VITE_", "TAURI_"],
}));