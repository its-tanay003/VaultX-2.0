import Ajv2020Pkg from 'ajv/dist/2020.js';
import addFormatsPkg from 'ajv-formats';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Interop with CommonJS/ESM exports for ajv and ajv-formats under NodeNext
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const Ajv2020: any = (Ajv2020Pkg as any).default ?? Ajv2020Pkg;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const addFormats: any = (addFormatsPkg as any).default ?? addFormatsPkg;

function getSchemasDir(): string {
  const candidate1 = path.resolve(__dirname, '../../schemas/v1');
  if (fs.existsSync(candidate1)) {
    return candidate1;
  }
  const candidate2 = path.resolve(__dirname, '../../../packages/schemas/v1');
  if (fs.existsSync(candidate2)) {
    return candidate2;
  }
  throw new Error('Cannot locate schemas/v1 directory');
}

export function createProtocolValidator() {
  const ajv = new Ajv2020({
    allErrors: true,
    strict: false,
  });
  addFormats(ajv);

  const schemasDir = getSchemasDir();
  const schemaFiles = fs.readdirSync(schemasDir).filter((f) => f.endsWith('.json'));

  for (const file of schemaFiles) {
    const filePath = path.join(schemasDir, file);
    const content = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    ajv.addSchema(content, file);
  }

  return ajv;
}

export interface ValidationOutcome {
  valid: boolean;
  errors: string[];
}

export function validateSchema(schemaName: string, data: unknown): ValidationOutcome {
  const ajv = createProtocolValidator();
  const validate = ajv.getSchema(schemaName);
  if (!validate) {
    throw new Error(`Schema ${schemaName} not found in validator`);
  }

  const valid = Boolean(validate(data));
  const errors = (validate.errors ?? []).map(
    (e: { instancePath?: string; message?: string; keyword?: string }) =>
      `${e.instancePath || '/'}: ${e.message ?? 'validation error'} (keyword: ${e.keyword ?? 'unknown'})`
  );

  return { valid, errors };
}
