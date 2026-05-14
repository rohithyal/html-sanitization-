import { getConfig } from '../config';

describe('getConfig', () => {
  it('article allows headings, tables, and images', () => {
    const cfg = getConfig('article');
    expect(cfg.allowedTags).toContain('h1');
    expect(cfg.allowedTags).toContain('table');
    expect(cfg.allowedTags).toContain('img');
  });

  it('chat does not allow tables or images', () => {
    const cfg = getConfig('chat');
    expect(cfg.allowedTags).not.toContain('table');
    expect(cfg.allowedTags).not.toContain('img');
  });

  it('notification allows no tags and no attributes', () => {
    const cfg = getConfig('notification');
    expect(cfg.allowedTags).toHaveLength(0);
    expect(cfg.allowedAttributes).toEqual({});
  });

  it('notification has a short maxInputLength', () => {
    expect(getConfig('notification').maxInputLength).toBeLessThanOrEqual(500);
  });

  it('email allows style attributes for mail-client layout', () => {
    const globalAttrs = getConfig('email').allowedAttributes['*'] ?? [];
    expect(globalAttrs).toContain('style');
  });

  it('no context allows dangerous protocols', () => {
    for (const context of ['article', 'chat', 'email'] as const) {
      const { allowedProtocols } = getConfig(context);
      expect(allowedProtocols).not.toContain('javascript:');
      expect(allowedProtocols).not.toContain('data:');
      expect(allowedProtocols).not.toContain('vbscript:');
    }
  });

  it('article allows a wider tag set than chat', () => {
    const articleTags = new Set(getConfig('article').allowedTags);
    const chatTags = getConfig('chat').allowedTags;
    expect(articleTags.size).toBeGreaterThan(chatTags.length);
  });
});
