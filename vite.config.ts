import { defineConfig } from 'vite'
import wasm from 'vite-plugin-wasm'

export default defineConfig({
  plugins: [
    wasm()
  ],
  build: {
    target: 'esnext'
  },
  worker: {
    plugins: () => [
      wasm()
    ],
    format: 'es'
  }
})
