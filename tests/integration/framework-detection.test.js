/**
 * Integration Tests - BlueDragon Web Security
 */

const { startServer } = require('../server');

describe('Framework Detection Integration', () => {
  let server;
  const PORT = 3334;
  const BASE_URL = `http://localhost:${PORT}`;

  beforeAll(async () => {
    server = await startServer(PORT);
  });

  afterAll((done) => {
    server.close(done);
  });

  describe('Mock Server', () => {
    test('serves Next.js page', async () => {
      const response = await fetch(`${BASE_URL}/nextjs`);
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('__NEXT_DATA__');
      expect(html).toContain('/_next/static/');
    });

    test('serves Angular page', async () => {
      const response = await fetch(`${BASE_URL}/angular`);
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('ng-version');
      expect(html).toContain('app-root');
    });

    test('serves SvelteKit page', async () => {
      const response = await fetch(`${BASE_URL}/sveltekit`);
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('data-sveltekit-hydrate');
      expect(html).toContain('/_app/immutable/');
    });

    test('serves Nuxt page', async () => {
      const response = await fetch(`${BASE_URL}/nuxt`);
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).toContain('__nuxt');
      expect(html).toContain('__NUXT__');
    });

    test('serves clean page without framework markers', async () => {
      const response = await fetch(`${BASE_URL}/clean`);
      expect(response.status).toBe(200);
      const html = await response.text();
      expect(html).not.toContain('__NEXT_DATA__');
      expect(html).not.toContain('ng-version');
      expect(html).not.toContain('__nuxt');
    });
  });

  describe('Next.js Detection', () => {
    test('extracts Next.js markers', async () => {
      const response = await fetch(`${BASE_URL}/nextjs`);
      const html = await response.text();

      // Check for __NEXT_DATA__
      expect(html).toMatch(/__NEXT_DATA__/);

      // Check for buildId in JSON
      const dataMatch = html.match(/<script id="__NEXT_DATA__"[^>]*>([^<]+)<\/script>/);
      expect(dataMatch).not.toBeNull();

      const data = JSON.parse(dataMatch[1]);
      expect(data.buildId).toBeDefined();
    });

    test('detects RSC-enabled Next.js', async () => {
      const response = await fetch(`${BASE_URL}/nextjs-rsc`);
      const html = await response.text();

      expect(html).toContain('appDir');
    });
  });

  describe('Angular Detection', () => {
    test('extracts Angular version', async () => {
      const response = await fetch(`${BASE_URL}/angular`);
      const html = await response.text();

      const versionMatch = html.match(/ng-version="([^"]+)"/);
      expect(versionMatch).not.toBeNull();
      expect(versionMatch[1]).toBe('17.0.0');
    });
  });

  describe('SvelteKit Detection', () => {
    test('extracts SvelteKit hydration marker', async () => {
      const response = await fetch(`${BASE_URL}/sveltekit`);
      const html = await response.text();

      const hydrateMatch = html.match(/data-sveltekit-hydrate="([^"]+)"/);
      expect(hydrateMatch).not.toBeNull();
    });
  });

  describe('Nuxt/Vue Detection', () => {
    test('detects Nuxt global object', async () => {
      const response = await fetch(`${BASE_URL}/nuxt`);
      const html = await response.text();

      expect(html).toMatch(/window\.__NUXT__/);
    });

    test('detects Vue data-v-app', async () => {
      const response = await fetch(`${BASE_URL}/nuxt`);
      const html = await response.text();

      expect(html).toContain('data-v-app');
    });
  });

  describe('RSC Endpoint', () => {
    test('returns RSC content type', async () => {
      const response = await fetch(`${BASE_URL}/_next/rsc`);
      expect(response.headers.get('content-type')).toContain('text/x-component');
    });

    test('returns RSC format response', async () => {
      const response = await fetch(`${BASE_URL}/_next/rsc`);
      const text = await response.text();

      expect(text).toMatch(/^\d+:/);
      expect(text).toContain('["$"');
    });
  });
});
