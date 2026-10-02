/**
 * @valutx/tool-registry
 * Manages Tool Passports and capability declarations. Must NEVER register unsigned or unverified tools.
 */

export class ToolRegistry {
  readonly version = "0.1.0";

  isReady(): boolean {
    return true;
  }
}
