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

// Injected at build time via vite define (see vite.config.ts); undefined under
// jest, where updateCheck.ts falls back to dev behind a typeof guard.
declare const __PERSONA_BUILD__: {
  channel: 'nightly' | 'release' | 'dev'
  sha: string
  builtAt: string
}