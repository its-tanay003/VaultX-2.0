/**
 * @valutx/context-engine
 * Builds AST, semantic search indices, and workspace context. Must NEVER treat retrieved repo data as instructions.
 */

export class ContextEngine {
  readonly version = "0.1.0";

  isReady(): boolean {
    return true;
  }
}
