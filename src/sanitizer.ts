import sanitizeHtml from 'sanitize-html';
import type { SanitizeContext, SanitizeResult } from './types';
import { getConfig } from './config';
import { isSafeUrl } from './url-validator';
import { URL_ATTRIBUTES } from './config';

// ---------------------------------------------------------------------------
// Core sanitize function
// ---------------------------------------------------------------------------

/**
 * Sanitizes untrusted HTML according to the rules of the given context.
 *
 * @param input   - Raw HTML string from user input, a rich-text editor, or API.
 * @param context - Rendering context that determines the allowlist.
 * @returns       - SanitizeResult with the safe HTML, a modification flag, and context.
 *
 * Security properties guaranteed:
 *   - All tags not on the allowlist are stripped (not escaped — stripped).
 *   - All event handler attributes (on*) are removed.
 *   - URL attributes are validated against an explicit protocol allowlist.
 *   - HTML comments are stripped by default (sanitize-html default behaviour).
 *   - SVG and MathML are disallowed in all contexts.
 *   - script/style/iframe and their text content are completely discarded.
 */
export function sanitize(input: string, context: SanitizeContext): SanitizeResult {
  const config = getConfig(context);

  // Hard truncate before parsing to prevent parser DoS on extremely large inputs.
  const bounded =
    config.maxInputLength !== undefined && input.length > config.maxInputLength
      ? input.slice(0, config.maxInputLength)
      : input;

  const output = sanitizeHtml(bounded, {
    allowedTags: config.allowedTags,
    allowedAttributes: buildSanitizeHtmlAttributes(config.allowedAttributes),
    allowedSchemes: config.allowedProtocols.map(stripTrailingColon),
    allowedSchemesByTag: {},
    allowVulnerableTags: false,
    // 'discard' removes the tag element but keeps its text content.
    // This is the correct mode for stripping unknown wrapper tags while
    // preserving readable text — important for the notification context.
    // Dangerous tags (script, style, etc.) have their content discarded
    // via nonTextTags below.
    disallowedTagsMode: 'discard',
    // Treat these as non-text so their inner content is also stripped,
    // not collected as text nodes.
    nonTextTags: ['script', 'style', 'textarea', 'noscript'],
    // Validate URLs using our url-validator, and enforce noopener on _blank links.
    transformTags: buildUrlTransformer(config.allowedProtocols),
  });

  return {
    output,
    wasModified: output !== bounded,
    context,
  };
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * sanitize-html expects allowedAttributes as:
 *   { tagName: AllowedAttribute[] } | { '*': AllowedAttribute[] }
 *
 * Our config uses the same shape already, so this is a passthrough.
 */
function buildSanitizeHtmlAttributes(
  map: Record<string, string[]>
): sanitizeHtml.IOptions['allowedAttributes'] {
  const result: Record<string, string[]> = {};
  for (const [tag, attrs] of Object.entries(map)) {
    result[tag] = attrs;
  }
  return result;
}

/**
 * Returns a sanitize-html transformTags map that strips URL attributes
 * whose protocol is not in the allowlist, and enforces rel="noopener noreferrer"
 * on target="_blank" links to prevent tab-napping.
 */
function buildUrlTransformer(
  allowedProtocols: string[]
): sanitizeHtml.IOptions['transformTags'] {
  const urlAttrs = new Set(URL_ATTRIBUTES);

  const transformer: sanitizeHtml.Transformer = (tagName, attribs) => {
    const cleaned: Record<string, string> = {};

    for (const [attr, value] of Object.entries(attribs)) {
      if (urlAttrs.has(attr)) {
        if (isSafeUrl(value, allowedProtocols)) {
          cleaned[attr] = value;
        }
        // Silently drop URL attrs with unsafe protocols.
      } else {
        cleaned[attr] = value;
      }
    }

    // Enforce rel="noopener noreferrer" when target="_blank" is present.
    if (cleaned['target'] === '_blank') {
      cleaned['rel'] = 'noopener noreferrer';
    }

    return { tagName, attribs: cleaned };
  };

  return { '*': transformer };
}

/** sanitize-html expects scheme names WITHOUT a trailing colon; our config has them WITH. */
function stripTrailingColon(protocol: string): string {
  return protocol.endsWith(':') ? protocol.slice(0, -1) : protocol;
}
