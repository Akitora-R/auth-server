import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

const port = 8080

export default defineConfig({
  plugins: [tailwindcss(), react()],
  server: {
    host: true,
    port: Number(process.env.VITE_PORT) || undefined,
    allowedHosts: ['aki.internal', 'localhost'],
    proxy: {
      '/oauth2': `http://localhost:${port}`,
      '/login': `http://localhost:${port}`,
      '/auth': `http://localhost:${port}`,
      '/api': `http://localhost:${port}`,
      '/registration': `http://localhost:${port}`,
      '/userinfo': `http://localhost:${port}`,
      '/introspect': `http://localhost:${port}`,
      '/.well-known': `http://localhost:${port}`,
    },
  },
})
