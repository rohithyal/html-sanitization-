export type SanitizeContext = 'article' | 'chat' | 'notification' | 'email';

export interface SanitizeConfig {
  allowedTags: string[];
  allowedAttributes: Record<string, string[]>;
  /** URI schemes allowed in href/src/action attributes (include trailing colon, e.g. "https:"). */
  allowedProtocols: string[];
  maxInputLength?: number;
}

export interface SanitizeResult {
  output: string;
  /** True if the sanitizer removed or changed anything — useful for security logging. */
  wasModified: boolean;
  context: SanitizeContext;
}
