import type { SanitizeConfig, SanitizeContext } from './types';

const SAFE_PROTOCOLS = ['http:', 'https:', 'mailto:'];
const GLOBAL_ATTRS = ['class', 'id', 'dir', 'lang', 'title'];

// article — full CMS rich-text. Widest allowlist: headings, tables, images, links.
const ARTICLE_CONFIG: SanitizeConfig = {
  allowedTags: [
    'div', 'section', 'article', 'aside', 'main', 'header', 'footer',
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote', 'pre',
    'span', 'a', 'b', 'strong', 'i', 'em', 'u', 's', 'strike', 'sup', 'sub',
    'code', 'kbd', 'mark', 'small',
    'ul', 'ol', 'li', 'dl', 'dt', 'dd',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'caption', 'colgroup', 'col',
    'img', 'figure', 'figcaption',
    'br', 'hr',
  ],
  allowedAttributes: {
    '*': GLOBAL_ATTRS,
    'a': ['href', 'target', 'rel'],
    'img': ['src', 'alt', 'width', 'height', 'loading'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan', 'scope'],
    'col': ['span', 'width'],
  },
  allowedProtocols: SAFE_PROTOCOLS,
  maxInputLength: 500_000,
};

// chat — inline messaging. No images, no tables, no block layout.
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
  maxInputLength: 10_000,
};

// notification — push / in-app banners rendered as plain text in mobile OS trays.
const NOTIFICATION_CONFIG: SanitizeConfig = {
  allowedTags: [],
  allowedAttributes: {},
  allowedProtocols: [],
  maxInputLength: 500,
};

// email — HTML email digest. Tables and inline styles required for mail-client layout.
const EMAIL_CONFIG: SanitizeConfig = {
  allowedTags: [
    'div', 'p', 'span', 'br', 'hr',
    'h1', 'h2', 'h3', 'h4',
    'b', 'strong', 'i', 'em', 'u', 's',
    'a', 'img',
    'ul', 'ol', 'li',
    'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
  ],
  allowedAttributes: {
    '*': [...GLOBAL_ATTRS, 'style', 'align', 'valign', 'bgcolor', 'width', 'height'],
    'a': ['href', 'target', 'rel'],
    'img': ['src', 'alt', 'width', 'height', 'border'],
    'td': ['colspan', 'rowspan'],
    'th': ['colspan', 'rowspan'],
    'table': ['cellpadding', 'cellspacing', 'border'],
  },
  allowedProtocols: SAFE_PROTOCOLS,
  maxInputLength: 200_000,
};

const CONFIGS: Record<SanitizeContext, SanitizeConfig> = {
  article: ARTICLE_CONFIG,
  chat: CHAT_CONFIG,
  notification: NOTIFICATION_CONFIG,
  email: EMAIL_CONFIG,
};

export function getConfig(context: SanitizeContext): Readonly<SanitizeConfig> {
  return CONFIGS[context];
}
