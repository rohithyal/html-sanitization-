import { getConfig } from '../config';

describe('getConfig', () => {
  it('article allows headings and tables', () => {
    const cfg = getConfig('article');
    expect(cfg.allowedTags).toContain('h1');
    expect(cfg.allowedTags).toContain('table');
    expect(cfg.allowedTags).toContain('img');
  });

  it('chat does NOT allow tables or images', () => {
    const cfg = getConfig('chat');
    expect(cfg.allowedTags).not.toContain('table');
    expect(cfg.allowedTags).not.toContain('img');
  });

  it('notification allows NO tags (plain text only)', () => {
    const cfg = getConfig('notification');
    expect(cfg.allowedTags).toHaveLength(0);
    expect(cfg.allowedAttributes).toEqual({});
  });

  it('notification has a very short maxInputLength', () => {
    const cfg = getConfig('notification');
    expect(cfg.maxInputLength).toBeLessThanOrEqual(500);
  });

  it('email allows style attributes (needed for HTML email layout)', () => {
    const cfg = getConfig('email');
    const globalAttrs = cfg.allowedAttributes['*'] ?? [];
    expect(globalAttrs).toContain('style');
  });

  it('all contexts allow only safe protocols', () => {
    for (const context of ['article', 'chat', 'email'] as const) {
      const { allowedProtocols } = getConfig(context);
      expect(allowedProtocols).not.toContain('javascript:');
      expect(allowedProtocols).not.toContain('data:');
      expect(allowedProtocols).not.toContain('vbscript:');
    }
  });

  it('all contexts strip HTML comments', () => {
    for (const context of ['article', 'chat', 'notification', 'email'] as const) {
      expect(getConfig(context).stripComments).toBe(true);
    }
  });
});
