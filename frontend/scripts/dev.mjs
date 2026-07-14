/**
 * Start Next.js dev server in the most stable mode for this install.
 * - Next 16+: prefer --webpack (avoids Turbopack CSS panics)
 * - Next 15: plain `next dev` (webpack is already default)
 */
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { rmSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");

const nextPkg = require("next/package.json");
const major = Number.parseInt(String(nextPkg.version).split(".")[0], 10) || 15;

const args = ["dev"];
if (major >= 16) {
  args.push("--webpack");
  console.log(`[vaultscan] Next ${nextPkg.version} → using webpack (stable local dev)`);
} else {
  console.log(`[vaultscan] Next ${nextPkg.version} → default dev server`);
}

// Optional: npm run dev -- --clean
if (process.argv.includes("--clean")) {
  const nextDir = path.join(root, ".next");
  if (existsSync(nextDir)) {
    console.log("[vaultscan] clearing .next cache…");
    rmSync(nextDir, { recursive: true, force: true });
  }
}

const child = spawn("npx", ["next", ...args, ...process.argv.slice(2).filter((a) => a !== "--clean")], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
  env: process.env,
});

child.on("exit", (code) => process.exit(code ?? 0));
