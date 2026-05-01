import path from "node:path";
import { fileURLToPath } from "node:url";

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));

// Default backend address. Operators running `ivre httpd` on a
// non-default port can override via VITE_BACKEND_URL.
const BACKEND_URL = process.env.VITE_BACKEND_URL ?? "http://localhost:9000";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(here, "./src"),
    },
  },
  server: {
    proxy: {
      // Proxy the IVRE Web API (mounted at /cgi/ by the legacy nginx
      // setup) so `pnpm dev` works against a running `ivre httpd`.
      "/cgi": {
        target: BACKEND_URL,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
