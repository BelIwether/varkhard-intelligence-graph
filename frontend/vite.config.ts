import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const { VARKHARD_API_URL } = loadEnv(mode, '.', 'VARKHARD_')
  const proxy = { '/api': VARKHARD_API_URL || 'http://127.0.0.1:8010' }

  return {
    plugins: [react()],
    server: { proxy },
    preview: { proxy },
  }
})
