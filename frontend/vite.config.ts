import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/targets": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/dashboard": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/decisions": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/tools": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/approvals": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000",
      "/automation": process.env.VITE_M2A_PROXY_TARGET ?? "http://127.0.0.1:8000"
    }
  }
});
