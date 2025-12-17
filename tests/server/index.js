/**
 * Mock Test Server - BlueDragon Web Security
 * Serves test pages simulating various frameworks
 */

const express = require('express');
const path = require('path');

function createTestServer() {
  const app = express();

  // Serve static fixtures
  app.use('/static', express.static(path.join(__dirname, '../fixtures')));

  // Next.js App
  app.get('/nextjs', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Next.js App</title>
        <script src="/_next/static/chunks/main.js"></script>
      </head>
      <body>
        <div id="__next">
          <h1>Next.js Application</h1>
        </div>
        <script id="__NEXT_DATA__" type="application/json">
          {"buildId":"abc123","nextExport":false,"props":{}}
        </script>
      </body>
      </html>
    `);
  });

  // Next.js with RSC
  app.get('/nextjs-rsc', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Next.js RSC App</title>
        <script src="/_next/static/chunks/app/page.js"></script>
      </head>
      <body>
        <div id="__next"></div>
        <script id="__NEXT_DATA__" type="application/json">
          {"buildId":"rsc123","appDir":true}
        </script>
      </body>
      </html>
    `);
  });

  // Angular App
  app.get('/angular', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Angular App</title>
        <script src="runtime.js" type="module"></script>
        <script src="main.js" type="module"></script>
      </head>
      <body>
        <app-root ng-version="17.0.0">
          <h1>Angular Application</h1>
        </app-root>
      </body>
      </html>
    `);
  });

  // SvelteKit App
  app.get('/sveltekit', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>SvelteKit App</title>
        <script type="module" src="/_app/immutable/entry/start.js"></script>
      </head>
      <body>
        <div data-sveltekit-hydrate="abc123">
          <h1>SvelteKit Application</h1>
        </div>
      </body>
      </html>
    `);
  });

  // Nuxt/Vue App
  app.get('/nuxt', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Nuxt App</title>
        <script src="/_nuxt/entry.js" type="module"></script>
      </head>
      <body>
        <div id="__nuxt">
          <div id="app" data-v-app>
            <h1>Nuxt Application</h1>
          </div>
        </div>
        <script>window.__NUXT__={config:{}};</script>
      </body>
      </html>
    `);
  });

  // Vulnerable Next.js (middleware bypass)
  app.get('/vulnerable-nextjs', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Vulnerable Next.js</title>
        <script src="/_next/static/chunks/main.js"></script>
      </head>
      <body>
        <div id="__next"></div>
        <script id="__NEXT_DATA__" type="application/json">
          {"buildId":"vuln123","runtimeConfig":{"middleware":true}}
        </script>
      </body>
      </html>
    `);
  });

  // RSC endpoint simulation
  app.get('/_next/rsc', (req, res) => {
    res.setHeader('Content-Type', 'text/x-component');
    res.send('0:["$","div",null,{"children":"RSC Response"}]');
  });

  // Clean page (no framework)
  app.get('/clean', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>Static Page</title></head>
      <body>
        <h1>Plain HTML Page</h1>
        <p>No framework detected here.</p>
      </body>
      </html>
    `);
  });

  return app;
}

function startServer(port = 3334) {
  return new Promise((resolve) => {
    const app = createTestServer();
    const server = app.listen(port, () => {
      resolve(server);
    });
  });
}

module.exports = { createTestServer, startServer };
