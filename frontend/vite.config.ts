import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/targets": "http://127.0.0.1:8000",
      "/dashboard": "http://127.0.0.1:8000",
      "/decisions": "http://127.0.0.1:8000",
      "/tools": "http://127.0.0.1:8000",
      "/approvals": "http://127.0.0.1:8000"
    }
  }
});
