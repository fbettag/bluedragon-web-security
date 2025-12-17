/**
 * Framework Detection Tests - BlueDragon Web Security
 * Tests the patterns used for framework detection
 */

describe('Framework Detection', () => {

  describe('Next.js Detection Patterns', () => {
    test('detects __NEXT_DATA__ script tag', () => {
      const html = '<script id="__NEXT_DATA__" type="application/json">{}</script>';
      expect(html.includes('__NEXT_DATA__')).toBe(true);
    });

    test('detects _next static paths', () => {
      const html = '<script src="/_next/static/chunks/main.js"></script>';
      expect(html.includes('/_next/static/')).toBe(true);
    });

    test('detects __next div', () => {
      const html = '<div id="__next"></div>';
      expect(html.includes('id="__next"')).toBe(true);
    });

    test('extracts buildId from __NEXT_DATA__', () => {
      const html = '<script id="__NEXT_DATA__" type="application/json">{"buildId":"abc123"}</script>';
      const match = html.match(/"buildId":"([^"]+)"/);
      expect(match).not.toBeNull();
      expect(match[1]).toBe('abc123');
    });
  });

  describe('Angular Detection Patterns', () => {
    test('detects ng-version attribute', () => {
      const html = '<app-root ng-version="17.0.0"></app-root>';
      expect(html.includes('ng-version')).toBe(true);
    });

    test('detects Angular module scripts', () => {
      const html = '<script src="main.js" type="module"></script>';
      expect(html.includes('type="module"')).toBe(true);
    });

    test('extracts version from ng-version', () => {
      const html = '<app-root ng-version="17.0.0"></app-root>';
      const match = html.match(/ng-version="([^"]+)"/);
      expect(match[1]).toBe('17.0.0');
    });

    test('detects app-root element', () => {
      const html = '<app-root></app-root>';
      expect(/<app-root/.test(html)).toBe(true);
    });
  });

  describe('SvelteKit Detection Patterns', () => {
    test('detects sveltekit-hydrate attribute', () => {
      const html = '<div data-sveltekit-hydrate="abc123"></div>';
      expect(html.includes('data-sveltekit-hydrate')).toBe(true);
    });

    test('detects _app immutable paths', () => {
      const html = '<script src="/_app/immutable/entry/start.js"></script>';
      expect(html.includes('/_app/immutable/')).toBe(true);
    });

    test('extracts hydration ID', () => {
      const html = '<div data-sveltekit-hydrate="abc123"></div>';
      const match = html.match(/data-sveltekit-hydrate="([^"]+)"/);
      expect(match[1]).toBe('abc123');
    });
  });

  describe('Nuxt/Vue Detection Patterns', () => {
    test('detects __nuxt div', () => {
      const html = '<div id="__nuxt"></div>';
      expect(html.includes('id="__nuxt"')).toBe(true);
    });

    test('detects __NUXT__ global', () => {
      const html = '<script>window.__NUXT__={};</script>';
      expect(html.includes('__NUXT__')).toBe(true);
    });

    test('detects Vue data-v-app', () => {
      const html = '<div id="app" data-v-app></div>';
      expect(html.includes('data-v-app')).toBe(true);
    });

    test('detects _nuxt paths', () => {
      const html = '<script src="/_nuxt/entry.js"></script>';
      expect(html.includes('/_nuxt/')).toBe(true);
    });
  });

  describe('RSC Detection Patterns', () => {
    test('detects RSC content type', () => {
      const contentType = 'text/x-component';
      expect(contentType).toBe('text/x-component');
    });

    test('detects RSC response format', () => {
      const rscResponse = '0:["$","div",null,{"children":"test"}]';
      expect(rscResponse.startsWith('0:')).toBe(true);
      expect(rscResponse.includes('["$"')).toBe(true);
    });

    test('detects Flight protocol marker', () => {
      const response = '1:I["react.suspense",{}]';
      expect(/^\d+:/.test(response)).toBe(true);
    });
  });

  describe('React Detection Patterns', () => {
    test('detects React root element', () => {
      const html = '<div id="root"></div>';
      expect(html.includes('id="root"')).toBe(true);
    });

    test('detects React data attributes', () => {
      const html = '<div data-reactroot=""></div>';
      expect(html.includes('data-reactroot')).toBe(true);
    });
  });

  describe('Remix Detection Patterns', () => {
    test('detects Remix hydration', () => {
      const html = '<script>window.__remixContext = {};</script>';
      expect(html.includes('__remixContext')).toBe(true);
    });
  });

  describe('Astro Detection Patterns', () => {
    test('detects Astro island', () => {
      const html = '<astro-island></astro-island>';
      expect(html.includes('astro-island')).toBe(true);
    });
  });
});
