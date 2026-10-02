import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const THREAT_MODEL_PATH = path.resolve(__dirname, '../security/threat-models/threat-model.yaml');

interface TestEntry {
  id: string;
  name: string;
  expected?: string;
  status: 'planned' | 'implemented';
}

interface StandardsMapping {
  owasp_asi?: string;
  owasp_llm?: string;
  mcp_risk?: string;
}

interface Threat {
  id: string;
  name: string;
  stride_category: string;
  standards_mapping: StandardsMapping;
  control_status: 'planned' | 'implemented';
  tests?: TestEntry[];
}

interface ThreatModel {
  version: string;
  system: string;
  owner: string;
  threats: Threat[];
}

const VALID_STRIDE = new Set([
  'Spoofing',
  'Tampering',
  'Repudiation',
  'Information Disclosure',
  'Denial of Service',
  'Elevation of Privilege',
]);

function main() {
  if (!fs.existsSync(THREAT_MODEL_PATH)) {
    console.error(`Error: Threat model file not found at ${THREAT_MODEL_PATH}`);
    process.exit(1);
  }

  const raw = fs.readFileSync(THREAT_MODEL_PATH, 'utf-8');
  const model = YAML.parse(raw) as ThreatModel;

  if (!model || !Array.isArray(model.threats)) {
    console.error('Error: Invalid threat model structure. Missing threats array.');
    process.exit(1);
  }

  console.log(`\n================================================================================`);
  console.log(` VaultX 2.0 Threat Model Coverage Matrix (v${model.version})`);
  console.log(` Owner: ${model.owner} | System: ${model.system}`);
  console.log(`================================================================================\n`);

  let failures = 0;
  const rows: Array<{
    id: string;
    stride: string;
    asi: string;
    controls: string;
    tests: string;
    status: string;
  }> = [];

  for (const threat of model.threats) {
    let error: string | null = null;

    if (!threat.id) {
      error = 'Missing threat ID';
    } else if (!VALID_STRIDE.has(threat.stride_category)) {
      error = `Invalid STRIDE category '${threat.stride_category}'`;
    } else if (!threat.standards_mapping || (!threat.standards_mapping.owasp_asi && !threat.standards_mapping.owasp_llm)) {
      error = 'Missing standards mapping (OWASP ASI/LLM)';
    } else if (!threat.tests || threat.tests.length === 0) {
      error = 'NO TEST ID ASSOCIATED';
    } else if (threat.control_status === 'implemented') {
      const hasImplemented = threat.tests.some((t) => t.status === 'implemented');
      if (!hasImplemented) {
        error = 'Implemented control lacks implemented test';
      }
    }

    const testSummary = (threat.tests ?? [])
      .map((t) => `${t.id} (${t.status})`)
      .join(', ') || 'NONE';

    rows.push({
      id: threat.id,
      stride: threat.stride_category,
      asi: threat.standards_mapping?.owasp_asi?.split(':')[0] ?? 'N/A',
      controls: threat.control_status ?? 'unknown',
      tests: testSummary,
      status: error ? `❌ ${error}` : '✓ OK',
    });

    if (error) {
      failures++;
    }
  }

  // Print table
  console.log(
    'ID'.padEnd(18) +
    'STRIDE'.padEnd(26) +
    'OWASP ASI'.padEnd(14) +
    'CONTROLS'.padEnd(14) +
    'STATUS'.padEnd(20) +
    'TESTS'
  );
  console.log('-'.repeat(120));

  for (const r of rows) {
    console.log(
      r.id.padEnd(18) +
      r.stride.padEnd(26) +
      r.asi.padEnd(14) +
      r.controls.padEnd(14) +
      r.status.padEnd(20) +
      r.tests
    );
  }

  console.log('\n' + '='.repeat(120));
  if (failures > 0) {
    console.error(`\n❌ CI FAILURE: ${failures} threat(s) failed coverage or test validation.`);
    process.exit(1);
  }

  console.log(`\n✓ All ${model.threats.length} threats have valid standards mappings and test coverage.`);
  process.exit(0);
}

main();
