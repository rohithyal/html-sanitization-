import type { SanitizeConfig, SanitizeContext } from './types';

// ---------------------------------------------------------------------------
// Shared building blocks
// ---------------------------------------------------------------------------

const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:'];

/** Attributes that are safe on any tag. */
const GLOBAL_SAFE_ATTRS = ['class', 'id', 'dir', 'lang', 'title'];

/** URL-carrying attributes that require protocol validation. */
export const URL_ATTRIBUTES = ['href', 'src', 'action', 'formaction', 'xlink:href', 'cite'];

// ---------------------------------------------------------------------------
// article — widest allowlist
// Represents a full CMS rich-text article authored by an employee or admin.
// Allows headings, tables, images, and links because all are product features.
// ---------------------------------------------------------------------------
const ARTICLE_CONFIG: SanitizeConfig = {
  allowedTags: [
    // Structure
    'div', 'section', 'article', 'aside', 'main', 'header', 'footer',
    // Text blocks
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre',
    // Inline formatting
    'span', 'a', 'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'sup', 'sub',
    'code', 'kbd', 'mark', 'small',
    // Lists
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    // Tables (needed for structured content)
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
    // Media
    'img', 'figure', 'figcaption',
    // Other
    'br', 'hr',
  ],
  allowedAttributes: {
    // Global
    '*': GLOBAL_SAFE_ATTRS,
    // Links — href is validated separately by url-validator hook
    'a': ['href', 'target', 'rel'],
    // Images — src is validated separately
    'img': ['src', 'alt', 'width', 'height', 'loading'],
    // Tables
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan', 'scope'],
    'col': ['span', 'width'],
  },
  allowedProtocols: SAFE_PROTOCOLS,
  stripComments: true,
  maxInputLength: 500_000,
};

// ---------------------------------------------------------------------------
// chat — moderate allowlist
// Inline messaging. No block layout, no images, no tables.
// Employees send messages; attackers may probe this surface more aggressively.
// ---------------------------------------------------------------------------
const CHAT_CONFIG: SanitizeConfig = {
  allowedTags: [
    'p', 'span', 'br',
    'b', 'strong', 'i', 'em', 'u', 's', 'strike',
    'code', 'pre',
    'a',
    'ul', 'ol', 'li',
  ],
  allowedAttributes: {
    '*': ['class'],
    'a': ['href', 'target', 'rel'],
  },
  allowedProtocols: SAFE_PROTOCOLS,
  stripComments: true,
  maxInputLength: 10_000,
};

// ---------------------------------------------------------------------------
// notification — tightest allowlist (plain text only)
// Push notifications and in-app banners are rendered as plain text in mobile
// OS notification trays. Any markup is stripped entirely.
// ---------------------------------------------------------------------------
const NOTIFICATION_CONFIG: SanitizeConfig = {
  allowedTags: [],
  allowedAttributes: {},
  allowedProtocols: [],
  stripComments: true,
  maxInputLength: 500,
};

// ---------------------------------------------------------------------------
// email — email digest renderer
// Tables are required for email layout; images are common. No scripts/iframes.
// The wider allowlist is acceptable because emails render in isolated webviews.
// ---------------------------------------------------------------------------
const EMAIL_CONFIG: SanitizeConfig = {
  allowedTags: [
    'div', 'p', 'span', 'br', 'hr',
    'h1', 'h2', 'h3', 'h4',
    'b', 'strong', 'i', 'em', 'u', 's',
    'a',
    'img',
    'ul', 'ol', 'li',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
  ],
  allowedAttributes: {
    '*': [...GLOBAL_SAFE_ATTRS, 'style', 'align', 'valign', 'bgcolor', 'width', 'height'],
    'a': ['href', 'target', 'rel'],
    'img': ['src', 'alt', 'width', 'height', 'border'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
    'table': ['cellpadding', 'cellspacing', 'border'],
  },
  allowedProtocols: SAFE_PROTOCOLS,
  stripComments: true,
  maxInputLength: 200_000,
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

const CONFIGS: Record<SanitizeContext, SanitizeConfig> = {
  article: ARTICLE_CONFIG,
  chat: CHAT_CONFIG,
  notification: NOTIFICATION_CONFIG,
  email: EMAIL_CONFIG,
};

export function getConfig(context: SanitizeContext): Readonly<SanitizeConfig> {
  return CONFIGS[context];
}
