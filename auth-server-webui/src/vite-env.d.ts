/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_ADMIN_CLIENT_ID: string
  readonly VITE_ADMIN_CLIENT_SECRET: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
