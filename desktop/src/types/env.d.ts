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