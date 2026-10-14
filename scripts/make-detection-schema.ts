/**
 * Regenerate schemas/*.schema.json from lib/schema-files.ts — the
 * committed, readable copy of the detection schema. The TypeScript
 * object is the source; test/detection-schema.test.ts fails when the
 * committed files lag it. Run: npx vite-node scripts/make-detection-schema.ts
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderSchemaFiles } from "../main/lib/schema-files.js";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "schemas");
for (const [name, body] of Object.entries(renderSchemaFiles())) {
  writeFileSync(join(dir, name), body);
  console.log(`wrote schemas/${name}`);
}
