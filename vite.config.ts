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
    // The Nym browser SDK bundle is ~6.7 MB (2.8 MB gzip) because it inlines
    // a WASM mixnet client. That's intrinsic to the dependency — code-splitting
    // can't shrink it further than the existing dynamic import in main.ts.
    // Raise the warning threshold to match reality so CI logs aren't dominated
    // by a known false positive.
    chunkSizeWarningLimit: 7000,
  },
  server: {
    port: 5173,
    host: "127.0.0.1",
    strictPort: true,
  },
});
