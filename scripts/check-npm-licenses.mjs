import fs from "node:fs";

const allowed = new Set([
  "Apache-2.0",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "MIT",
  "MPL-2.0",
]);

const lock = JSON.parse(fs.readFileSync("package-lock.json", "utf8"));
const dependencies = Object.entries(lock.packages ?? {})
  .filter(([path]) => path !== "")
  .map(([path, metadata]) => ({
    name: path.replace(/^node_modules\//, ""),
    version: metadata.version ?? "unknown",
    license: metadata.license ?? "UNLICENSED",
  }))
  .sort((left, right) => left.name.localeCompare(right.name));

const rejected = dependencies.filter(({ license }) => !allowed.has(license));

for (const dependency of dependencies) {
  process.stdout.write(
    `${dependency.name},${dependency.version},${dependency.license}\n`,
  );
}

if (rejected.length > 0) {
  const summary = rejected
    .map(({ name, version, license }) => `${name}@${version} (${license})`)
    .join(", ");
  throw new Error(`Disallowed or unknown npm licenses: ${summary}`);
}
