import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface BreakingDiff {
  file: string;
  kind: 'REMOVED_PROPERTY' | 'ADDED_REQUIRED_PROPERTY' | 'REMOVED_ENUM_VARIANT' | 'TYPE_CHANGED';
  message: string;
}

export function compareSchemas(
  baseline: Record<string, unknown>,
  current: Record<string, unknown>,
  fileName: string
): BreakingDiff[] {
  const diffs: BreakingDiff[] = [];

  // Check type change
  if (baseline.type && current.type && baseline.type !== current.type) {
    diffs.push({
      file: fileName,
      kind: 'TYPE_CHANGED',
      message: `Type changed from ${String(baseline.type)} to ${String(current.type)}`,
    });
  }

  // Check enum removal
  if (Array.isArray(baseline.enum) && Array.isArray(current.enum)) {
    const currentSet = new Set(current.enum);
    for (const val of baseline.enum) {
      if (!currentSet.has(val)) {
        diffs.push({
          file: fileName,
          kind: 'REMOVED_ENUM_VARIANT',
          message: `Enum variant '${String(val)}' was removed`,
        });
      }
    }
  }

  // Check properties
  const baseProps = (baseline.properties ?? {}) as Record<string, Record<string, unknown>>;
  const currProps = (current.properties ?? {}) as Record<string, Record<string, unknown>>;

  for (const prop of Object.keys(baseProps)) {
    if (!(prop in currProps)) {
      diffs.push({
        file: fileName,
        kind: 'REMOVED_PROPERTY',
        message: `Property '${prop}' was removed`,
      });
    }
  }

  // Check newly added required properties (breaking for existing producers)
  const baseReq = new Set<string>((baseline.required as string[]) ?? []);
  const currReq = (current.required as string[]) ?? [];

  for (const prop of currReq) {
    if (!baseReq.has(prop)) {
      diffs.push({
        file: fileName,
        kind: 'ADDED_REQUIRED_PROPERTY',
        message: `New required property '${prop}' added without major version bump`,
      });
    }
  }

  return diffs;
}

export function checkAllSchemas(baselineDir: string, currentDir: string): BreakingDiff[] {
  const allDiffs: BreakingDiff[] = [];
  const files = fs.readdirSync(baselineDir).filter((f) => f.endsWith('.json'));

  for (const file of files) {
    const basePath = path.join(baselineDir, file);
    const currPath = path.join(currentDir, file);

    if (!fs.existsSync(currPath)) {
      allDiffs.push({
        file,
        kind: 'REMOVED_PROPERTY',
        message: `Schema file ${file} was deleted`,
      });
      continue;
    }

    const baseJson = JSON.parse(fs.readFileSync(basePath, 'utf-8'));
    const currJson = JSON.parse(fs.readFileSync(currPath, 'utf-8'));

    const fileDiffs = compareSchemas(baseJson, currJson, file);
    allDiffs.push(...fileDiffs);
  }

  return allDiffs;
}

// CLI entry point
if (process.argv[1] && process.argv[1].endsWith('check-breaking.ts')) {
  const baselineDir = path.resolve(__dirname, '../v1/.baseline');
  const currentDir = path.resolve(__dirname, '../v1');

  if (!fs.existsSync(baselineDir)) {
    console.log('No .baseline directory found. Initializing baseline snapshot...');
    fs.mkdirSync(baselineDir, { recursive: true });
    const schemaFiles = fs.readdirSync(currentDir).filter((f) => f.endsWith('.json'));
    for (const f of schemaFiles) {
      fs.copyFileSync(path.join(currentDir, f), path.join(baselineDir, f));
    }
    console.log(`✓ Initialized baseline with ${schemaFiles.length} schemas.`);
    process.exit(0);
  }

  const diffs = checkAllSchemas(baselineDir, currentDir);
  if (diffs.length > 0) {
    console.error('❌ BREAKING SCHEMA CHANGES DETECTED WITHOUT MAJOR VERSION BUMP:');
    for (const d of diffs) {
      console.error(`  - [${d.file}] ${d.kind}: ${d.message}`);
    }
    process.exit(1);
  }

  console.log('✓ No breaking schema changes detected against baseline.');
}
