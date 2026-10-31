import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves project sites under /<repository>/. The workflow sets
// VITE_BASE_PATH so the same build works for a root domain as well.
const base = process.env.VITE_BASE_PATH || "./";

export default defineConfig({
    base,
    plugins: [react()],
    server: { host: "127.0.0.1" },
    preview: { host: "127.0.0.1" },
    test: {
        environment: "node",
        include: ["src/**/*.test.{js,jsx}"],
    },
});
