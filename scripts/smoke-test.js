'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { createServer } = require('../src/server');

function formBody(values) {
  return new URLSearchParams(values).toString();
}

function cookieFrom(response) {
  const value = response.headers.get('set-cookie');
  assert.ok(value, 'response should set a cookie');
  return value.split(';')[0];
}

async function main() {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'text-gist-service-'));
  const server = createServer({ dataDir, host: '127.0.0.1', port: 0 });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    const health = await fetch(`${baseUrl}/healthz`);
    assert.equal(health.status, 200);
    assert.equal(await health.text(), 'ok\n');

    const register = await fetch(`${baseUrl}/register`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formBody({ username: 'alice', password: 'correct horse battery staple' }),
    });
    assert.equal(register.status, 303);
    const cookie = cookieFrom(register);

    const dashboard = await fetch(`${baseUrl}/`, { headers: { Cookie: cookie } });
    assert.equal(dashboard.status, 200);
    const dashboardHtml = await dashboard.text();
    const csrf = dashboardHtml.match(/name="csrf" value="([^"]+)"/)?.[1];
    assert.ok(csrf, 'dashboard should include csrf token');

    const create = await fetch(`${baseUrl}/gists`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formBody({ csrf, title: 'Example', content: 'hello raw text\nline two' }),
    });
    assert.equal(create.status, 303);
    const gistPath = new URL(create.headers.get('location'), baseUrl).pathname;
    const id = gistPath.split('/').pop();
    assert.match(id, /^[A-Za-z0-9_-]{10,64}$/);

    const raw = await fetch(`${baseUrl}/raw/${id}`);
    assert.equal(raw.status, 200);
    assert.equal(raw.headers.get('content-type'), 'text/plain; charset=utf-8');
    assert.equal(await raw.text(), 'hello raw text\nline two');

    const update = await fetch(`${baseUrl}/gists/${id}`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        Cookie: cookie,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: formBody({ csrf, title: 'Example edited', content: 'updated text' }),
    });
    assert.equal(update.status, 303);

    const rawAfterUpdate = await fetch(`${baseUrl}/raw/${id}`);
    assert.equal(await rawAfterUpdate.text(), 'updated text');

    const publicView = await fetch(`${baseUrl}/gists/${id}`);
    assert.equal(publicView.status, 200);

    console.log(`smoke test passed: ${baseUrl}/raw/${id}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await fs.rm(dataDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});