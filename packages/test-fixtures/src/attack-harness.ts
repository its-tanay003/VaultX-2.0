import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export type FixtureKind =
  | 'postinstall'
  | 'makefile'
  | 'git_hook'
  | 'prompt_injection_docs'
  | 'symlink_escape'
  | 'fake_mcp'
  | 'ci_workflow'
  | 'prompt_injection_corpus';

export interface CanaryPaths {
  canaryFile: string;
  canarySshKey: string;
}

export interface LoopbackRequest {
  method: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface LoopbackListener {
  port: number;
  url: string;
  receivedRequests: LoopbackRequest[];
  close: () => Promise<void>;
}

export interface FixtureContext {
  kind: FixtureKind;
  repoPath: string;
  canaryPaths: CanaryPaths;
  listener: LoopbackListener;
  cleanUp: () => Promise<void>;
}

export interface CanaryEvaluation {
  canaryTouched: boolean;
  canaryContent: string;
  sshKeyTouched: boolean;
  listenerReceivedCount: number;
  requests: LoopbackRequest[];
}

export const INITIAL_CANARY_CONTENT = 'INITIAL_CANARY_STATE_UNTOUCHED';
export const INITIAL_SSH_KEY_CONTENT = 'INERT_CANARY_SSH_KEY_TOKEN_DO_NOT_LEAK';

function getCatalogDir(): string {
  const candidate1 = path.resolve(__dirname, '../../../security/attack-fixtures/catalog');
  if (fs.existsSync(candidate1)) {
    return candidate1;
  }
  const candidate2 = path.resolve(__dirname, '../../../../security/attack-fixtures/catalog');
  if (fs.existsSync(candidate2)) {
    return candidate2;
  }
  throw new Error(`Cannot locate security/attack-fixtures/catalog from ${__dirname}`);
}

/**
 * Starts a local-only HTTP listener strictly bound to 127.0.0.1 on an ephemeral port.
 */
export async function startLoopbackListener(): Promise<LoopbackListener> {
  const receivedRequests: LoopbackRequest[] = [];

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk.toString();
    });
    req.on('end', () => {
      receivedRequests.push({
        method: req.method ?? 'GET',
        path: req.url ?? '/',
        headers: req.headers,
        body,
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'received_by_inert_loopback' }));
    });
  });

  await new Promise<void>((resolve, reject) => {
    // Strictly bind to 127.0.0.1 (never 0.0.0.0 or external network)
    server.listen(0, '127.0.0.1', () => resolve());
    server.on('error', reject);
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('Failed to obtain loopback listener address');
  }

  const port = address.port;
  const url = `http://127.0.0.1:${port}`;

  return {
    port,
    url,
    receivedRequests,
    close: async () => {
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
      });
    },
  };
}

/**
 * Creates an isolated, inert fixture in a fresh temporary directory.
 * Sets up canary files and an active loopback HTTP listener.
 */
export async function createFixture(kind: FixtureKind): Promise<FixtureContext> {
  const baseTmp = path.join(os.tmpdir(), `valutx-attack-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`);
  fs.mkdirSync(baseTmp, { recursive: true });

  const canaryDir = path.join(baseTmp, 'canary_files');
  fs.mkdirSync(canaryDir, { recursive: true });

  const canaryFile = path.join(canaryDir, 'canary.txt');
  const canarySshKey = path.join(canaryDir, 'id_ed25519_canary');

  fs.writeFileSync(canaryFile, INITIAL_CANARY_CONTENT, 'utf-8');
  fs.writeFileSync(canarySshKey, INITIAL_SSH_KEY_CONTENT, 'utf-8');

  const listener = await startLoopbackListener();

  const repoPath = path.join(baseTmp, 'repo');
  fs.mkdirSync(repoPath, { recursive: true });

  const catalogDir = getCatalogDir();

  // Helper to replace placeholders
  const templateContent = (raw: string): string => {
    return raw
      .replace(/{{CANARY_PATH}}/g, canaryFile.replace(/\\/g, '/'))
      .replace(/{{CANARY_SSH_KEY}}/g, canarySshKey.replace(/\\/g, '/'))
      .replace(/{{LOOPBACK_URL}}/g, listener.url);
  };

  const copyAndTemplate = (src: string, dest: string) => {
    const stat = fs.statSync(src);
    if (stat.isDirectory()) {
      fs.mkdirSync(dest, { recursive: true });
      for (const entry of fs.readdirSync(src)) {
        copyAndTemplate(path.join(src, entry), path.join(dest, entry));
      }
    } else {
      const raw = fs.readFileSync(src, 'utf-8');
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, templateContent(raw), 'utf-8');
    }
  };

  switch (kind) {
    case 'postinstall': {
      copyAndTemplate(path.join(catalogDir, 'postinstall'), repoPath);
      break;
    }
    case 'makefile': {
      copyAndTemplate(path.join(catalogDir, 'makefile'), repoPath);
      break;
    }
    case 'git_hook': {
      const gitDir = path.join(repoPath, '.git', 'hooks');
      fs.mkdirSync(gitDir, { recursive: true });
      const hookSrc = path.join(catalogDir, 'git-hook', 'pre-commit');
      const hookDest = path.join(gitDir, 'pre-commit');
      copyAndTemplate(hookSrc, hookDest);
      break;
    }
    case 'prompt_injection_docs': {
      copyAndTemplate(path.join(catalogDir, 'prompt-injection-docs'), repoPath);
      break;
    }
    case 'symlink_escape': {
      copyAndTemplate(path.join(catalogDir, 'symlink-escape'), repoPath);
      const linkPath = path.join(repoPath, 'canary_symlink');
      try {
        fs.symlinkSync(canaryFile, linkPath, 'file');
      } catch {
        // Fallback for Windows environments without developer mode symlink privileges
        fs.writeFileSync(linkPath, `MOCK_SYMLINK_TO:${canaryFile}`, 'utf-8');
      }
      break;
    }
    case 'fake_mcp': {
      copyAndTemplate(path.join(catalogDir, 'fake-mcp'), repoPath);
      break;
    }
    case 'ci_workflow': {
      const workflowsDir = path.join(repoPath, '.github', 'workflows');
      fs.mkdirSync(workflowsDir, { recursive: true });
      copyAndTemplate(
        path.join(catalogDir, 'ci-workflow', 'ci.yml'),
        path.join(workflowsDir, 'ci.yml')
      );
      break;
    }
    case 'prompt_injection_corpus': {
      copyAndTemplate(path.join(catalogDir, 'prompt-injections'), repoPath);
      break;
    }
    default:
      throw new Error(`Unknown fixture kind: ${String(kind)}`);
  }

  const cleanUp = async () => {
    try {
      await listener.close();
    } catch {
      // Ignore listener close error during teardown
    }
    try {
      if (fs.existsSync(baseTmp)) {
        fs.rmSync(baseTmp, { recursive: true, force: true });
      }
    } catch {
      // Ignore temp directory deletion errors on Windows locked files
    }
  };

  return {
    kind,
    repoPath,
    canaryPaths: {
      canaryFile,
      canarySshKey,
    },
    listener,
    cleanUp,
  };
}

export const create_fixture = createFixture;

/**
 * Asserts on observable facts in the environment:
 * Whether canary files were modified or the loopback listener received requests.
 */
export function evaluateCanary(context: FixtureContext): CanaryEvaluation {
  let canaryContent = '';
  let canaryTouched = false;
  if (fs.existsSync(context.canaryPaths.canaryFile)) {
    canaryContent = fs.readFileSync(context.canaryPaths.canaryFile, 'utf-8');
    canaryTouched = canaryContent !== INITIAL_CANARY_CONTENT;
  }

  let sshKeyContent = '';
  let sshKeyTouched = false;
  if (fs.existsSync(context.canaryPaths.canarySshKey)) {
    sshKeyContent = fs.readFileSync(context.canaryPaths.canarySshKey, 'utf-8');
    sshKeyTouched = sshKeyContent !== INITIAL_SSH_KEY_CONTENT;
  }

  return {
    canaryTouched,
    canaryContent,
    sshKeyTouched,
    listenerReceivedCount: context.listener.receivedRequests.length,
    requests: context.listener.receivedRequests,
  };
}
