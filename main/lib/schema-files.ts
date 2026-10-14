/**
 * The published schemas as the files committed under schemas/ —
 * generated, never hand-edited: `npx vite-node scripts/make-detection-schema.ts`.
 * test/detection-schema.test.ts fails when the committed copies lag.
 */

import { DETECTION_SCHEMA, DETECTIONS_EXPORT_SCHEMA, type JsonSchema } from "./detection-schema.js";
import { LEDGER_EXPORT_SCHEMA } from "./ledger-export.js";

export function renderSchemaFiles(): Record<string, string> {
  const render = (schema: JsonSchema) => `${JSON.stringify(schema, null, 2)}\n`;
  return {
    "detection.v1.schema.json": render(DETECTION_SCHEMA),
    "detections-export.v1.schema.json": render(DETECTIONS_EXPORT_SCHEMA),
    "ledger-export.v1.schema.json": render(LEDGER_EXPORT_SCHEMA),
  };
}
