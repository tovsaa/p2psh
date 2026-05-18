import { defineConfig } from "vite";

// Browser entry lives under `web/`. Build output is `dist/` so it's easy to
// drop into a `gh-pages` branch or a Pages workflow. `base` is set via env
// for GitHub Pages project sites (e.g. /P2PSH/).
export default defineConfig({
  root: "web",
  base: process.env.P2PSH_BASE ?? "/",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
  },
  server: {
    port: 5173,
    host: "127.0.0.1",
    strictPort: true,
  },
});
