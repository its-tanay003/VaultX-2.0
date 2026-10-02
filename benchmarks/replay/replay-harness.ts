import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export type ReplayMode = 'record' | 'replay' | 'passthrough';

export interface ModelMessage {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string;
  name?: string;
}

export interface ModelRequest {
  model: string;
  messages: ModelMessage[];
  temperature?: number;
  max_tokens?: number;
  tools?: unknown[];
}

export interface ModelResponse {
  id: string;
  model: string;
  content: string;
  tool_calls?: unknown[];
  finish_reason: string;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  };
}

export interface CassetteEntry {
  request_hash: string;
  canonical_request: string;
  response: ModelResponse;
  recorded_at: string;
}

export interface Cassette {
  cassette_version: string;
  entries: Record<string, CassetteEntry>;
}

/**
 * Produces a stable, deterministic canonical JSON string by sorting keys recursively.
 */
export function canonicalizeJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map((item) => canonicalizeJson(item)).join(',') + ']';
  }
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const entries = keys.map((key) => {
    const val = (obj as Record<string, unknown>)[key];
    return `${JSON.stringify(key)}:${canonicalizeJson(val)}`;
  });
  return '{' + entries.join(',') + '}';
}

/**
 * Computes a SHA-256 hash of the canonicalized request.
 */
export function computeRequestHash(request: ModelRequest): string {
  const canonical = canonicalizeJson(request);
  return crypto.createHash('sha256').update(canonical, 'utf-8').digest('hex');
}

export class ModelReplayHarness {
  private mode: ReplayMode;
  private cassettePath: string;
  private cassette: Cassette;
  private dirty: boolean = false;

  constructor(cassettePath: string, mode: ReplayMode = 'replay') {
    this.cassettePath = cassettePath;
    this.mode = mode;
    this.cassette = this.loadCassette();
  }

  private loadCassette(): Cassette {
    if (fs.existsSync(this.cassettePath)) {
      try {
        const raw = fs.readFileSync(this.cassettePath, 'utf-8');
        return JSON.parse(raw) as Cassette;
      } catch (err) {
        throw new Error(`Failed to read cassette from ${this.cassettePath}: ${(err as Error).message}`);
      }
    }
    return {
      cassette_version: '1.0.0',
      entries: {},
    };
  }

  public save(): void {
    if (!this.dirty) {
      return;
    }
    fs.mkdirSync(path.dirname(this.cassettePath), { recursive: true });
    fs.writeFileSync(this.cassettePath, JSON.stringify(this.cassette, null, 2) + '\n', 'utf-8');
    this.dirty = false;
  }

  /**
   * Executes a model query through the replay harness.
   * If replay mode: returns recorded response or throws MODEL_REPLAY_MISS.
   * If record mode: invokes live provider, records response, and returns it.
   */
  public async execute(
    request: ModelRequest,
    liveProvider?: (req: ModelRequest) => Promise<ModelResponse>
  ): Promise<ModelResponse> {
    const hash = computeRequestHash(request);

    if (this.mode === 'replay') {
      const entry = this.cassette.entries[hash];
      if (!entry) {
        throw new Error(
          `MODEL_REPLAY_MISS: No recorded response found in cassette for request hash [${hash}]. ` +
          `Run with --record to capture new model responses.`
        );
      }
      return entry.response;
    }

    if (this.mode === 'record') {
      if (!liveProvider) {
        throw new Error('Live provider callback is required when running in record mode');
      }
      const response = await liveProvider(request);
      this.cassette.entries[hash] = {
        request_hash: hash,
        canonical_request: canonicalizeJson(request),
        response,
        recorded_at: new Date().toISOString(),
      };
      this.dirty = true;
      this.save();
      return response;
    }

    // passthrough
    if (!liveProvider) {
      throw new Error('Live provider callback is required for passthrough mode');
    }
    return liveProvider(request);
  }

  public getEntryCount(): number {
    return Object.keys(this.cassette.entries).length;
  }
}
