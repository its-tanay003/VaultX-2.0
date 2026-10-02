/**
 * @valutx/model-router
 * Dispatches prompts to local/cloud models. Must NEVER silently fall back to cloud when in local-only mode.
 */

export class ModelRouter {
  readonly version = "0.1.0";

  isReady(): boolean {
    return true;
  }
}
