/**
 * The rendering context where sanitized HTML will be displayed.
 *
 * Each context has a different trust level and therefore a different allowlist:
 *   article      — full rich-text editor output (widest allowlist)
 *   chat         — inline messaging (moderate allowlist)
 *   notification — push/in-app notification body (plain text only)
 *   email        — email digest renderer (tables + basic formatting)
 */
export type SanitizeContext = 'article' | 'chat' | 'notification' | 'email';

/**
 * Low-level allowlist configuration resolved per context.
 * Consumers should not build this directly — use SanitizeContext instead.
 */
export interface SanitizeConfig {
  /** HTML tags that are kept (everything else is stripped). */
  allowedTags: string[];
  /**
   * Per-tag attribute allowlists.
   * Use '*' as the key to allow an attribute on any tag.
   */
  allowedAttributes: Record<string, string[]>;
  /** URI schemes allowed in href/src/action attributes. */
  allowedProtocols: string[];
  /** Whether to strip HTML comments. Always true in production. */
  stripComments: boolean;
  /** Hard truncate input before sanitizing (prevents parser DoS on huge payloads). */
  maxInputLength?: number;
}

/**
 * Return value of sanitize(). The caller can inspect wasModified to decide
 * whether to log a security event (e.g., an employee pasted malicious HTML).
 */
export interface SanitizeResult {
  /** The sanitized, safe HTML string. */
  output: string;
  /** True if the sanitizer removed or altered anything. */
  wasModified: boolean;
  /** The context that was used to produce this result. */
  context: SanitizeContext;
}
