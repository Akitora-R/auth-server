import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [tailwindcss(), react()],
  define: {
    __ADMIN_CLIENT_SECRET__: JSON.stringify(process.env.VITE_ADMIN_CLIENT_SECRET || ''),
  },
})
