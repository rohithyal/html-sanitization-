/**
 * Checks whether a URL string is safe to render.
 *
 * Uses the platform URL parser — not regex — so that encoded or malformed
 * inputs like `javas\tcript:`, `JAVASCRIPT:`, and `javascript%3A` are all
 * correctly classified as unsafe.
 *
 * Relative URLs (no scheme) are allowed through so that in-app links like
 * `/articles/123` continue to work.
 */
export function isSafeUrl(url: string, allowedProtocols: string[]): boolean {
  const trimmed = url.trim();

  // Relative URLs have no protocol — they are safe (browser resolves against origin).
  if (!trimmed.includes(':')) {
    return true;
  }

  try {
    // Passing a dummy base so relative URLs without `://` don't throw.
    const parsed = new URL(trimmed, 'https://placeholder.invalid');
    // parsed.protocol always has a trailing colon, e.g. "javascript:"
    return allowedProtocols.includes(parsed.protocol);
  } catch {
    // URL constructor threw — malformed; reject to be safe.
    return false;
  }
}
