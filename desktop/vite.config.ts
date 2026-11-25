import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// https://vitejs.dev/config/
export default defineConfig(async () => ({
  plugins: [react()],

  // Update-check channel metadata (src/utils/updateCheck.ts reads __PERSONA_BUILD__).
  // desktop-build.yml (the daily build) injects nightly + commit + build time; a future
  // release pipeline injects release; local builds inject nothing → dev (excluded from
  // version comparison).
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