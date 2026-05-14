/** HTML attributes that carry URLs and must have their protocol validated. */
export const URL_ATTRIBUTES = ['href', 'src', 'action', 'formaction', 'xlink:href', 'cite'];

/**
 * Returns true if the URL is safe to render.
 *
 * Uses the platform URL parser (never regex) so that case variants like
 * "JAVASCRIPT:", encoded forms, and leading-whitespace tricks are all caught.
 * Relative URLs (no colon present) pass through — they resolve against the
 * page origin and carry no scheme risk.
 */
export function isSafeUrl(url: string, allowedProtocols: string[]): boolean {
  const trimmed = url.trim();

  if (!trimmed.includes(':')) {
    return true; // relative URL — safe
  }

  try {
    const { protocol } = new URL(trimmed, 'https://placeholder.invalid');
    return allowedProtocols.includes(protocol);
  } catch {
    return false; // malformed — reject
  }
}
