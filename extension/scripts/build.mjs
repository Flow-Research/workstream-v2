import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src");
const dist = join(root, "dist");

const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const template = JSON.parse(await readFile(join(src, "manifest.json"), "utf8"));

await rm(dist, { recursive: true, force: true });

const npx = process.platform === "win32" ? "npx.cmd" : "npx";
execFileSync(npx, ["--no-install", "vite", "build"], {
  cwd: root,
  stdio: "inherit",
  shell: process.platform === "win32",
});

for (const dir of ["background", "content"]) {
  await cp(join(src, dir), join(dist, dir), { recursive: true });
}

await writeFile(
  join(dist, "manifest.json"),
  `${JSON.stringify({ ...template, version: packageJson.version }, null, 2)}\n`,
);

console.log(`Built extension v${packageJson.version} into ${dist}`);
