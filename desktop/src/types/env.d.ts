/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly MODE: string
  readonly NODE_ENV: string
  readonly PROD: boolean
  readonly DEV: boolean
  readonly VITE_APP_NAME?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare namespace NodeJS {
  interface ProcessEnv {
    NODE_ENV: 'development' | 'production' | 'test'
  }
}

declare const process: {
  env: NodeJS.ProcessEnv
}

// 构建期经 vite define 注入（见 vite.config.ts）；jest 里不定义，
// updateCheck.ts 以 typeof 守卫回退 dev
declare const __PERSONA_BUILD__: {
  channel: 'nightly' | 'release' | 'dev'
  sha: string
  builtAt: string
}