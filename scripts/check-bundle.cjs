const fs = require("node:fs");
const path = require("node:path");

const distDir = path.resolve(__dirname, "..", "dist");
const javascriptFiles = fs
  .readdirSync(distDir)
  .filter((file) => file.endsWith(".js"))
  .map((file) => path.join(distDir, file));

for (const file of javascriptFiles) {
  const bundle = fs.readFileSync(file, "utf8");
  if (/crc64_require\s*=.*crc64_require\(/.test(bundle)) {
    throw new Error(`broken bundled CRC64 loader detected in ${path.basename(file)}`);
  }
}
