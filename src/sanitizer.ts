import sanitizeHtml from 'sanitize-html';
import type { SanitizeContext, SanitizeResult } from './types';
import { getConfig } from './config';
import { isSafeUrl, URL_ATTRIBUTES } from './url-validator';

const URL_ATTR_SET = new Set(URL_ATTRIBUTES);

/**
 * Sanitizes untrusted HTML for the given rendering context.
 *
 * Guarantees:
 *   - Only explicitly allowed tags and attributes survive.
 *   - All on* event handlers are stripped.
 *   - URL attributes (href, src, etc.) are validated against a protocol allowlist.
 *   - script/style/noscript tag contents are fully discarded, not just unwrapped.
 *   - SVG and MathML are blocked in every context.
 *   - target="_blank" links get rel="noopener noreferrer" to prevent tab-napping.
 */
export function sanitize(input: string, context: SanitizeContext): SanitizeResult {
  const config = getConfig(context);

  // Truncate before parsing to guard against parser DoS on huge payloads.
  const bounded = config.maxInputLength && input.length > config.maxInputLength
    ? input.slice(0, config.maxInputLength)
    : input;

  const output = sanitizeHtml(bounded, {
    allowedTags: config.allowedTags,
    allowedAttributes: config.allowedAttributes,
    allowedSchemes: config.allowedProtocols.map(p => p.slice(0, -1)), // strip trailing ":"
    allowedSchemesByTag: {},
    allowVulnerableTags: false,
    // 'discard' strips the tag but keeps its text — correct for notification context
    // where we want plain text, not a blank string.
    // script/style text is killed separately via nonTextTags.
    disallowedTagsMode: 'discard',
    nonTextTags: ['script', 'style', 'noscript', 'textarea'],
    transformTags: { '*': urlTransformer(config.allowedProtocols) },
  });

  return { output, wasModified: output !== bounded, context };
}

function urlTransformer(allowedProtocols: string[]): sanitizeHtml.Transformer {
  return (tagName, attribs) => {
    const cleaned: Record<string, string> = {};

    for (const [attr, value] of Object.entries(attribs)) {
      if (!URL_ATTR_SET.has(attr) || isSafeUrl(value, allowedProtocols)) {
        cleaned[attr] = value;
      }
      // URL attrs with disallowed protocols are silently dropped.
    }

    // Prevent tab-napping: a page opened via target="_blank" can redirect its opener.
    if (cleaned['target'] === '_blank') {
      cleaned['rel'] = 'noopener noreferrer';
    }

    return { tagName, attribs: cleaned };
  };
}
