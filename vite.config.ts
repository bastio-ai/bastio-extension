import { defineConfig } from 'vite';
import { crx } from '@crxjs/vite-plugin';
import manifest from './manifest.json' with { type: 'json' };

// Sourcemaps are gated on dev mode. Production CRX/Web-Store bundles
// should not ship .map files — they reveal the full source-tree layout
// to anyone who unzips the archive. `npm run dev` (mode=development)
// emits maps for local debugging; `npm run build` (mode=production)
// does not.
export default defineConfig(({ mode }) => ({
  plugins: [crx({ manifest })],
  resolve: {
    alias: {
      '@': new URL('./src', import.meta.url).pathname,
    },
  },
  build: {
    target: 'chrome120',
    sourcemap: mode === 'development',
    rollupOptions: {
      input: {
        popup: 'src/popup/popup.html',
        options: 'src/options/options.html',
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    hmr: {
      port: 5174,
    },
  },
}));
