import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src");
const dist = join(root, "dist");

const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
const template = JSON.parse(await readFile(join(src, "manifest.json"), "utf8"));

await rm(dist, { recursive: true, force: true });
await mkdir(dist, { recursive: true });
await cp(src, dist, { recursive: true });

await writeFile(
  join(dist, "manifest.json"),
  `${JSON.stringify({ ...template, version: packageJson.version }, null, 2)}\n`,
);

console.log(`Built extension v${packageJson.version} into ${dist}`);
