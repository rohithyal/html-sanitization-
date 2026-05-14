import { isSafeUrl } from '../url-validator';

const ALLOWED = ['http:', 'https:', 'mailto:'];

describe('isSafeUrl', () => {
  describe('safe URLs', () => {
    it('allows https', () => {
      expect(isSafeUrl('https://staffbase.com/article/123', ALLOWED)).toBe(true);
    });

    it('allows http', () => {
      expect(isSafeUrl('http://staffbase.com', ALLOWED)).toBe(true);
    });

    it('allows mailto', () => {
      expect(isSafeUrl('mailto:hr@company.com', ALLOWED)).toBe(true);
    });

    it('allows relative paths (no scheme)', () => {
      expect(isSafeUrl('/articles/123', ALLOWED)).toBe(true);
    });

    it('allows relative paths with query string', () => {
      expect(isSafeUrl('/search?q=hello', ALLOWED)).toBe(true);
    });

    it('allows fragment-only URLs', () => {
      expect(isSafeUrl('#section-1', ALLOWED)).toBe(true);
    });
  });

  describe('dangerous URLs', () => {
    it('blocks javascript: scheme', () => {
      expect(isSafeUrl('javascript:alert(1)', ALLOWED)).toBe(false);
    });

    it('blocks uppercase JAVASCRIPT:', () => {
      expect(isSafeUrl('JAVASCRIPT:alert(1)', ALLOWED)).toBe(false);
    });

    it('blocks mixed case JavaScript:', () => {
      expect(isSafeUrl('JavaScript:alert(1)', ALLOWED)).toBe(false);
    });

    it('blocks javascript: with leading whitespace', () => {
      expect(isSafeUrl('  javascript:alert(1)', ALLOWED)).toBe(false);
    });

    it('blocks vbscript:', () => {
      expect(isSafeUrl('vbscript:MsgBox(1)', ALLOWED)).toBe(false);
    });

    it('blocks data: URI for HTML', () => {
      expect(isSafeUrl('data:text/html,<script>alert(1)</script>', ALLOWED)).toBe(false);
    });

    it('blocks data: URI for images (exfiltration via CSS)', () => {
      expect(isSafeUrl('data:image/png;base64,abc123', ALLOWED)).toBe(false);
    });

    it('blocks file: scheme', () => {
      expect(isSafeUrl('file:///etc/passwd', ALLOWED)).toBe(false);
    });

    it('blocks ftp: scheme', () => {
      expect(isSafeUrl('ftp://evil.com/payload', ALLOWED)).toBe(false);
    });
  });
});
