'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 30;
const DEFAULT_MAX_TEXT_BYTES = 1024 * 1024;
const PASSWORD_MIN_LENGTH = 8;
const ID_PATTERN = /^[A-Za-z0-9_-]{10,64}$/;
const USERNAME_PATTERN = /^[A-Za-z0-9_-]{3,32}$/;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function makeConfig(options = {}) {
  const dataDir = path.resolve(
    options.dataDir || process.env.DATA_DIR || path.join(__dirname, '..', 'data'),
  );
  const maxTextBytes = Number(options.maxTextBytes || process.env.MAX_TEXT_BYTES || DEFAULT_MAX_TEXT_BYTES);

  return {
    dataDir,
    textDir: path.join(dataDir, 'gists'),
    usersFile: path.join(dataDir, 'users.json'),
    gistsFile: path.join(dataDir, 'gists.json'),
    sessionsFile: path.join(dataDir, 'sessions.json'),
    settingsFile: path.join(dataDir, 'settings.json'),
    adminCredentialsFile: path.join(dataDir, 'admin-credentials.txt'),
    host: options.host || process.env.HOST || '127.0.0.1',
    port: Number(options.port || process.env.PORT || 3456),
    maxTextBytes,
    maxBodyBytes: maxTextBytes + 32 * 1024,
    publicBaseUrl: options.publicBaseUrl || process.env.PUBLIC_BASE_URL || '',
    secureCookies: options.secureCookies ?? process.env.COOKIE_SECURE === 'true',
    adminUsername: options.adminUsername || process.env.ADMIN_USERNAME || 'admin',
  };
}

async function ensureStore(config) {
  await fs.mkdir(config.textDir, { recursive: true });
  await ensureJson(config.usersFile, { users: [] });
  await ensureJson(config.gistsFile, { gists: [] });
  await ensureJson(config.sessionsFile, { sessions: [] });
  await ensureJson(config.settingsFile, { allowRegistration: true });
  await ensureSettings(config);
  const createdAdmin = await ensureAdminUser(config);
  if (createdAdmin) {
    console.log(`Created admin account: ${createdAdmin.username}`);
    console.log(`Admin password: ${createdAdmin.password}`);
    console.log(`Admin credentials saved to: ${config.adminCredentialsFile}`);
  }
}

async function ensureJson(file, fallback) {
  try {
    await fs.access(file);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await writeJson(file, fallback);
  }
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch (error) {
    if (error.code === 'ENOENT') return fallback;
    throw error;
  }
}

async function writeJson(file, value) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tempFile = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  await fs.writeFile(tempFile, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
  await fs.rename(tempFile, file);
}

async function writeTextFile(file, text) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tempFile = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  await fs.writeFile(tempFile, text, 'utf8');
  await fs.rename(tempFile, file);
}

async function ensureSettings(config) {
  const settings = await readJson(config.settingsFile, { allowRegistration: true });
  if (typeof settings.allowRegistration !== 'boolean') {
    settings.allowRegistration = true;
    await writeJson(config.settingsFile, settings);
  }
}

function normalizeUsersData(data) {
  let changed = false;
  for (const user of data.users) {
    if (!user.usernameKey) {
      user.usernameKey = String(user.username || '').toLowerCase();
      changed = true;
    }
    if (!user.role) {
      user.role = 'user';
      changed = true;
    }
    if (!user.status) {
      user.status = 'active';
      changed = true;
    }
  }
  return changed;
}

async function ensureAdminUser(config) {
  const data = await readJson(config.usersFile, { users: [] });
  let changed = normalizeUsersData(data);
  const adminUsername = String(config.adminUsername).trim() || 'admin';
  const adminUsernameKey = adminUsername.toLowerCase();
  const existingAdmin = data.users.find((user) => user.role === 'admin');

  if (existingAdmin) {
    if (changed) await writeJson(config.usersFile, data);
    return null;
  }

  const existingAdminUsername = data.users.find((user) => user.usernameKey === adminUsernameKey);
  if (existingAdminUsername) {
    existingAdminUsername.role = 'admin';
    existingAdminUsername.status = 'active';
    await writeJson(config.usersFile, data);
    return null;
  }

  const password = createPassword();
  const passwordRecord = await hashPassword(password);
  const timestamp = nowIso();
  data.users.push({
    id: crypto.randomUUID(),
    username: adminUsername,
    usernameKey: adminUsernameKey,
    role: 'admin',
    status: 'active',
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    createdAt: timestamp,
    passwordChangedAt: null,
  });
  await writeJson(config.usersFile, data);
  await fs.writeFile(
    config.adminCredentialsFile,
    `username=${adminUsername}\npassword=${password}\ncreated_at=${timestamp}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );
  return { username: adminUsername, password };
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('base64url');
  const hash = await scrypt(password, salt, 64);
  return { salt, hash: hash.toString('base64url') };
}

async function verifyPassword(password, user) {
  const stored = Buffer.from(user.passwordHash, 'base64url');
  const candidate = await scrypt(password, user.passwordSalt, stored.length);
  return stored.length === candidate.length && crypto.timingSafeEqual(stored, candidate);
}

function createId() {
  return crypto.randomBytes(12).toString('base64url');
}

function createPassword() {
  return crypto.randomBytes(18).toString('base64url');
}

function nowIso() {
  return new Date().toISOString();
}

function htmlEscape(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatDate(value) {
  return new Intl.DateTimeFormat('en', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}

function textFileFor(config, id) {
  if (!ID_PATTERN.test(id)) throw new HttpError(404, 'Gist not found');
  return path.join(config.textDir, `${id}.txt`);
}

function parseCookies(header = '') {
  const cookies = new Map();
  for (const part of header.split(';')) {
    const [rawName, ...rest] = part.trim().split('=');
    if (!rawName || rest.length === 0) continue;
    cookies.set(rawName, decodeURIComponent(rest.join('=')));
  }
  return cookies;
}

function cookieHeader(name, value, options = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax'];
  if (options.maxAge !== undefined) parts.push(`Max-Age=${options.maxAge}`);
  if (options.secure) parts.push('Secure');
  return parts.join('; ');
}

async function readForm(req, config) {
  const contentType = req.headers['content-type'] || '';
  if (!contentType.startsWith('application/x-www-form-urlencoded')) {
    throw new HttpError(415, 'Only application/x-www-form-urlencoded forms are accepted');
  }

  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > config.maxBodyBytes) throw new HttpError(413, 'Submitted text is too large');
    chunks.push(chunk);
  }

  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
}

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(body);
}

function sendText(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Cache-Control': 'no-cache',
  });
  res.end(body);
}

function redirect(res, location, headers = {}) {
  res.writeHead(303, { Location: location, ...headers });
  res.end();
}

function absoluteUrl(req, config, pathname) {
  if (config.publicBaseUrl) return new URL(pathname, config.publicBaseUrl).toString();
  const host = req.headers.host || `${config.host}:${config.port}`;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return `${proto}://${host}${pathname}`;
}

function layout({ title, user, body, flash = '' }) {
  const nav = user
    ? `
      <span class="muted">Signed in as ${htmlEscape(user.username)}</span>
      <a class="button ghost" href="/account">Account</a>
      ${user.role === 'admin' ? '<a class="button ghost" href="/admin">Admin</a>' : ''}
      <form method="post" action="/logout" class="inline-form">
        <input type="hidden" name="csrf" value="${htmlEscape(user.csrf)}">
        <button type="submit" class="ghost">Sign out</button>
      </form>`
    : '<span class="muted">Editable text hosting</span>';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${htmlEscape(title)} - Text Gists</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f7f4;
      --surface: #ffffff;
      --text: #202124;
      --muted: #676b72;
      --line: #d9d9d2;
      --accent: #136f63;
      --accent-strong: #0c4f47;
      --danger: #a33a2d;
      --code-bg: #f0f1ed;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      line-height: 1.5;
    }
    a { color: var(--accent-strong); }
    header {
      border-bottom: 1px solid var(--line);
      background: var(--surface);
    }
    .bar, main {
      width: min(1100px, calc(100% - 32px));
      margin: 0 auto;
    }
    .bar {
      min-height: 64px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .brand {
      color: inherit;
      text-decoration: none;
      font-weight: 700;
      letter-spacing: 0;
    }
    .nav {
      display: flex;
      align-items: center;
      gap: 12px;
      flex-wrap: wrap;
      justify-content: flex-end;
    }
    main { padding: 28px 0 56px; }
    h1 {
      margin: 0 0 18px;
      font-size: clamp(1.7rem, 1.4rem + 0.9vw, 2.35rem);
      line-height: 1.15;
      letter-spacing: 0;
    }
    h2 {
      margin: 0 0 14px;
      font-size: 1.05rem;
      letter-spacing: 0;
    }
    .muted { color: var(--muted); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 18px;
      align-items: start;
    }
    .panel, .gist-row {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
    }
    .panel { padding: 18px; }
    .stack { display: grid; gap: 14px; }
    .field { display: grid; gap: 6px; }
    label { font-weight: 650; }
    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 10px 11px;
      font: inherit;
    }
    input[type="checkbox"] {
      width: auto;
      margin-right: 6px;
    }
    textarea {
      min-height: 390px;
      resize: vertical;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      line-height: 1.45;
      white-space: pre;
    }
    button, .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 38px;
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      padding: 8px 13px;
      font: inherit;
      font-weight: 650;
      text-decoration: none;
      cursor: pointer;
    }
    button:hover, .button:hover { background: var(--accent-strong); }
    button:disabled {
      cursor: not-allowed;
      opacity: 0.55;
    }
    .ghost {
      background: transparent;
      color: var(--accent-strong);
    }
    .ghost:hover { background: #e8efed; }
    .danger {
      border-color: var(--danger);
      background: var(--danger);
    }
    .danger:hover { background: #7d2b22; }
    .inline-form { display: inline; margin: 0; }
    .actions {
      display: flex;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }
    .flash {
      margin-bottom: 18px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fffbea;
    }
    .gist-list { display: grid; gap: 10px; }
    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
    }
    th, td {
      border-bottom: 1px solid var(--line);
      padding: 10px 12px;
      text-align: left;
      vertical-align: top;
      white-space: nowrap;
    }
    th { background: #f0f1ed; }
    tr:last-child td { border-bottom: 0; }
    .small-form {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
      margin: 0 8px 8px 0;
    }
    .small-input {
      min-height: 38px;
      width: min(220px, 100%);
    }
    .pill {
      display: inline-block;
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 2px 8px;
      background: #f0f1ed;
      color: var(--muted);
      font-size: 0.86rem;
      font-weight: 650;
    }
    .gist-row {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 12px 14px;
    }
    .gist-title {
      font-weight: 700;
      overflow-wrap: anywhere;
    }
    .gist-meta {
      color: var(--muted);
      font-size: 0.92rem;
    }
    .raw-link, code {
      background: var(--code-bg);
      border-radius: 5px;
      padding: 2px 5px;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
      overflow-wrap: anywhere;
    }
    pre {
      margin: 0;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Consolas, "Liberation Mono", monospace;
    }
    @media (max-width: 620px) {
      .bar { align-items: flex-start; flex-direction: column; padding: 14px 0; }
      .nav { justify-content: flex-start; }
      .gist-row { align-items: flex-start; flex-direction: column; }
      textarea { min-height: 320px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="bar">
      <a class="brand" href="/">Text Gists</a>
      <nav class="nav">${nav}</nav>
    </div>
  </header>
  <main>
    ${flash}
    ${body}
  </main>
</body>
</html>`;
}

function flashFrom(url) {
  const error = url.searchParams.get('error');
  const ok = url.searchParams.get('ok');
  const text = error || ok;
  if (!text) return '';
  return `<div class="flash">${htmlEscape(text.replaceAll('_', ' '))}</div>`;
}

function flashMessage(text) {
  return text ? `<div class="flash">${htmlEscape(text)}</div>` : '';
}

async function getRequestContext(req, config) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies.get('sid');
  if (!token) return { user: null, session: null };

  const [{ sessions }, { users }] = await Promise.all([
    readJson(config.sessionsFile, { sessions: [] }),
    readJson(config.usersFile, { users: [] }),
  ]);
  const session = sessions.find((item) => item.token === token && item.expiresAt > Date.now());
  if (!session) return { user: null, session: null };

  const user = users.find((item) => item.id === session.userId);
  if (!user) return { user: null, session: null };
  if (user.status === 'disabled') return { user: null, session: null };

  return {
    session,
    user: {
      id: user.id,
      username: user.username,
      role: user.role || 'user',
      status: user.status || 'active',
      csrf: session.csrf,
    },
  };
}

function requireUser(context) {
  if (!context.user) throw new HttpError(401, 'Please sign in first');
  return context.user;
}

function requireAdmin(context) {
  const user = requireUser(context);
  if (user.role !== 'admin') throw new HttpError(403, 'Admin access required');
  return user;
}

function requireCsrf(form, context) {
  requireUser(context);
  if (!form.csrf || form.csrf !== context.session.csrf) {
    throw new HttpError(403, 'Your form expired. Please reload and try again');
  }
}

async function createSession(config, userId) {
  const data = await readJson(config.sessionsFile, { sessions: [] });
  const session = {
    token: crypto.randomBytes(32).toString('base64url'),
    csrf: crypto.randomBytes(24).toString('base64url'),
    userId,
    expiresAt: Date.now() + SESSION_TTL_MS,
    createdAt: nowIso(),
  };
  data.sessions = data.sessions.filter((item) => item.expiresAt > Date.now());
  data.sessions.push(session);
  await writeJson(config.sessionsFile, data);
  return session;
}

async function deleteSession(config, token) {
  const data = await readJson(config.sessionsFile, { sessions: [] });
  const next = data.sessions.filter((item) => item.token !== token);
  if (next.length !== data.sessions.length) {
    await writeJson(config.sessionsFile, { sessions: next });
  }
}

async function findGist(config, id) {
  const data = await readJson(config.gistsFile, { gists: [] });
  return data.gists.find((gist) => gist.id === id) || null;
}

async function renderHome(req, res, config, context, url) {
  if (!context.user) {
    const settings = await readJson(config.settingsFile, { allowRegistration: true });
    const registrationPanel = settings.allowRegistration
      ? `
        <section class="panel">
          <h2>Create account</h2>
          <form method="post" action="/register" class="stack">
            <div class="field">
              <label for="register-username">Username</label>
              <input id="register-username" name="username" autocomplete="username" pattern="[A-Za-z0-9_-]{3,32}" required>
            </div>
            <div class="field">
              <label for="register-password">Password</label>
              <input id="register-password" name="password" type="password" autocomplete="new-password" minlength="${PASSWORD_MIN_LENGTH}" required>
            </div>
            <button type="submit">Register</button>
          </form>
        </section>`
      : `
        <section class="panel">
          <h2>Registration closed</h2>
          <p class="muted">New accounts can only be created by an administrator right now.</p>
        </section>`;
    const body = `
      <h1>Host editable text with stable raw links.</h1>
      <div class="grid">
        <section class="panel">
          <h2>Sign in</h2>
          <form method="post" action="/login" class="stack">
            <div class="field">
              <label for="login-username">Username</label>
              <input id="login-username" name="username" autocomplete="username" required>
            </div>
            <div class="field">
              <label for="login-password">Password</label>
              <input id="login-password" name="password" type="password" autocomplete="current-password" required>
            </div>
            <button type="submit">Sign in</button>
          </form>
        </section>
        ${registrationPanel}
      </div>`;
    send(res, 200, layout({ title: 'Sign in', user: null, body, flash: flashFrom(url) }));
    return;
  }

  const { gists } = await readJson(config.gistsFile, { gists: [] });
  const ownGists = gists
    .filter((gist) => gist.ownerId === context.user.id)
    .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const list = ownGists.length
    ? ownGists
        .map((gist) => `
          <article class="gist-row">
            <div>
              <a class="gist-title" href="/gists/${htmlEscape(gist.id)}">${htmlEscape(gist.title)}</a>
              <div class="gist-meta">${htmlEscape(gist.id)} · updated ${htmlEscape(formatDate(gist.updatedAt))}</div>
            </div>
            <a class="raw-link" href="/raw/${htmlEscape(gist.id)}">/raw/${htmlEscape(gist.id)}</a>
          </article>`)
        .join('')
    : '<p class="muted">No gists yet.</p>';

  const body = `
    <h1>Your text gists</h1>
    <div class="grid">
      <section class="panel">
        <h2>New gist</h2>
        <form method="post" action="/gists" class="stack">
          <input type="hidden" name="csrf" value="${htmlEscape(context.user.csrf)}">
          <div class="field">
            <label for="title">Title</label>
            <input id="title" name="title" maxlength="120" placeholder="Untitled">
          </div>
          <div class="field">
            <label for="content">Text</label>
            <textarea id="content" name="content" spellcheck="false"></textarea>
          </div>
          <button type="submit">Create gist</button>
        </form>
      </section>
      <section class="stack">
        <h2>Owned by you</h2>
        <div class="gist-list">${list}</div>
      </section>
    </div>`;
  send(res, 200, layout({ title: 'Dashboard', user: context.user, body, flash: flashFrom(url) }));
}

async function handleRegister(req, res, config) {
  const settings = await readJson(config.settingsFile, { allowRegistration: true });
  if (!settings.allowRegistration) {
    redirect(res, '/?error=registration_is_closed');
    return;
  }

  const form = await readForm(req, config);
  const username = String(form.username || '').trim();
  const password = String(form.password || '');

  if (!USERNAME_PATTERN.test(username)) {
    redirect(res, '/?error=username_must_be_3_to_32_letters_numbers_dashes_or_underscores');
    return;
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    redirect(res, `/?error=password_must_be_at_least_${PASSWORD_MIN_LENGTH}_characters`);
    return;
  }

  const data = await readJson(config.usersFile, { users: [] });
  const usernameKey = username.toLowerCase();
  if (data.users.some((user) => user.usernameKey === usernameKey)) {
    redirect(res, '/?error=username_already_exists');
    return;
  }

  const passwordRecord = await hashPassword(password);
  const user = {
    id: crypto.randomUUID(),
    username,
    usernameKey,
    role: 'user',
    status: 'active',
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    createdAt: nowIso(),
    passwordChangedAt: null,
  };
  data.users.push(user);
  await writeJson(config.usersFile, data);

  const session = await createSession(config, user.id);
  redirect(res, '/?ok=account_created', {
    'Set-Cookie': cookieHeader('sid', session.token, {
      maxAge: Math.floor(SESSION_TTL_MS / 1000),
      secure: config.secureCookies,
    }),
  });
}

async function handleLogin(req, res, config) {
  const form = await readForm(req, config);
  const usernameKey = String(form.username || '').trim().toLowerCase();
  const password = String(form.password || '');
  const { users } = await readJson(config.usersFile, { users: [] });
  const user = users.find((item) => item.usernameKey === usernameKey);

  if (!user || !(await verifyPassword(password, user))) {
    redirect(res, '/?error=invalid_username_or_password');
    return;
  }
  if (user.status === 'disabled') {
    redirect(res, '/?error=account_disabled');
    return;
  }

  const session = await createSession(config, user.id);
  redirect(res, '/?ok=signed_in', {
    'Set-Cookie': cookieHeader('sid', session.token, {
      maxAge: Math.floor(SESSION_TTL_MS / 1000),
      secure: config.secureCookies,
    }),
  });
}

async function handleLogout(req, res, config, context) {
  const form = await readForm(req, config);
  requireCsrf(form, context);
  const token = parseCookies(req.headers.cookie || '').get('sid');
  if (token) await deleteSession(config, token);
  redirect(res, '/', {
    'Set-Cookie': cookieHeader('sid', '', { maxAge: 0, secure: config.secureCookies }),
  });
}

async function renderAccount(res, context, url) {
  requireUser(context);
  const body = `
    <h1>User center</h1>
    <section class="panel stack">
      <div>
        <div class="muted">Username</div>
        <strong>${htmlEscape(context.user.username)}</strong>
        <span class="pill">${htmlEscape(context.user.role)}</span>
      </div>
      <form method="post" action="/account/password" class="stack">
        <input type="hidden" name="csrf" value="${htmlEscape(context.user.csrf)}">
        <div class="field">
          <label for="current-password">Current password</label>
          <input id="current-password" name="currentPassword" type="password" autocomplete="current-password" required>
        </div>
        <div class="field">
          <label for="new-password">New password</label>
          <input id="new-password" name="newPassword" type="password" autocomplete="new-password" minlength="${PASSWORD_MIN_LENGTH}" required>
        </div>
        <div class="field">
          <label for="confirm-password">Confirm new password</label>
          <input id="confirm-password" name="confirmPassword" type="password" autocomplete="new-password" minlength="${PASSWORD_MIN_LENGTH}" required>
        </div>
        <button type="submit">Change password</button>
      </form>
    </section>`;
  send(res, 200, layout({ title: 'Account', user: context.user, body, flash: flashFrom(url) }));
}

async function handleChangePassword(req, res, config, context) {
  const user = requireUser(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const currentPassword = String(form.currentPassword || '');
  const newPassword = String(form.newPassword || '');
  const confirmPassword = String(form.confirmPassword || '');
  if (newPassword.length < PASSWORD_MIN_LENGTH) {
    redirect(res, `/account?error=password_must_be_at_least_${PASSWORD_MIN_LENGTH}_characters`);
    return;
  }
  if (newPassword !== confirmPassword) {
    redirect(res, '/account?error=password_confirmation_does_not_match');
    return;
  }

  const data = await readJson(config.usersFile, { users: [] });
  const storedUser = data.users.find((item) => item.id === user.id);
  if (!storedUser || !(await verifyPassword(currentPassword, storedUser))) {
    redirect(res, '/account?error=current_password_is_incorrect');
    return;
  }

  const passwordRecord = await hashPassword(newPassword);
  storedUser.passwordSalt = passwordRecord.salt;
  storedUser.passwordHash = passwordRecord.hash;
  storedUser.passwordChangedAt = nowIso();
  await writeJson(config.usersFile, data);
  redirect(res, '/account?ok=password_changed');
}

function renderUserActions(currentUser, targetUser) {
  const forms = [];
  const disabled = targetUser.status === 'disabled';
  const isSelf = currentUser.id === targetUser.id;
  forms.push(`
    <form method="post" action="/admin/users/${htmlEscape(targetUser.id)}/action" class="small-form">
      <input type="hidden" name="csrf" value="${htmlEscape(currentUser.csrf)}">
      <input type="hidden" name="action" value="${disabled ? 'enable' : 'disable'}">
      <button type="submit" class="${disabled ? 'ghost' : 'danger'}" ${isSelf ? 'disabled' : ''}>${disabled ? 'Enable' : 'Disable'}</button>
    </form>`);
  forms.push(`
    <form method="post" action="/admin/users/${htmlEscape(targetUser.id)}/action" class="small-form">
      <input type="hidden" name="csrf" value="${htmlEscape(currentUser.csrf)}">
      <input type="hidden" name="action" value="${targetUser.role === 'admin' ? 'demote' : 'promote'}">
      <button type="submit" class="ghost" ${isSelf ? 'disabled' : ''}>${targetUser.role === 'admin' ? 'Make user' : 'Make admin'}</button>
    </form>`);
  forms.push(`
    <form method="post" action="/admin/users/${htmlEscape(targetUser.id)}/action" class="small-form">
      <input type="hidden" name="csrf" value="${htmlEscape(currentUser.csrf)}">
      <input type="hidden" name="action" value="reset-password">
      <button type="submit" class="ghost">Reset password</button>
    </form>`);
  return forms.join('');
}

async function renderAdmin(res, config, context, url, message = '') {
  const admin = requireAdmin(context);
  const [{ users }, settings] = await Promise.all([
    readJson(config.usersFile, { users: [] }),
    readJson(config.settingsFile, { allowRegistration: true }),
  ]);
  const rows = users
    .slice()
    .sort((a, b) => a.username.localeCompare(b.username))
    .map((user) => `
      <tr>
        <td><strong>${htmlEscape(user.username)}</strong></td>
        <td><span class="pill">${htmlEscape(user.role || 'user')}</span></td>
        <td><span class="pill">${htmlEscape(user.status || 'active')}</span></td>
        <td>${htmlEscape(formatDate(user.createdAt || nowIso()))}</td>
        <td>${renderUserActions(admin, user)}</td>
      </tr>`)
    .join('');

  const body = `
    <h1>Admin center</h1>
    <div class="grid">
      <section class="panel stack">
        <h2>Registration</h2>
        <p class="muted">Free registration is currently ${settings.allowRegistration ? 'open' : 'closed'}.</p>
        <form method="post" action="/admin/settings" class="actions">
          <input type="hidden" name="csrf" value="${htmlEscape(admin.csrf)}">
          <button type="submit" name="allowRegistration" value="true" class="${settings.allowRegistration ? 'ghost' : ''}">Open registration</button>
          <button type="submit" name="allowRegistration" value="false" class="${settings.allowRegistration ? 'danger' : 'ghost'}">Close registration</button>
        </form>
      </section>
      <section class="panel">
        <h2>Create user</h2>
        <form method="post" action="/admin/users" class="stack">
          <input type="hidden" name="csrf" value="${htmlEscape(admin.csrf)}">
          <div class="field">
            <label for="admin-create-username">Username</label>
            <input id="admin-create-username" name="username" pattern="[A-Za-z0-9_-]{3,32}" required>
          </div>
          <div class="field">
            <label for="admin-create-password">Password</label>
            <input id="admin-create-password" name="password" type="text" minlength="${PASSWORD_MIN_LENGTH}" placeholder="Leave blank to generate">
          </div>
          <label>
            <input type="checkbox" name="isAdmin" value="true">
            Administrator
          </label>
          <button type="submit">Create user</button>
        </form>
      </section>
    </div>
    <section class="stack" style="margin-top:18px">
      <h2>Users</h2>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>${rows}</tbody>
        </table>
      </div>
    </section>`;
  send(res, 200, layout({ title: 'Admin', user: admin, body, flash: message ? flashMessage(message) : flashFrom(url) }));
}

async function handleAdminSettings(req, res, config, context) {
  requireAdmin(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);
  await writeJson(config.settingsFile, { allowRegistration: form.allowRegistration === 'true' });
  redirect(res, '/admin?ok=settings_saved');
}

async function handleAdminCreateUser(req, res, config, context, url) {
  const admin = requireAdmin(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const username = String(form.username || '').trim();
  if (!USERNAME_PATTERN.test(username)) {
    redirect(res, '/admin?error=username_must_be_3_to_32_letters_numbers_dashes_or_underscores');
    return;
  }

  const generatedPassword = !form.password;
  const password = generatedPassword ? createPassword() : String(form.password || '');
  if (password.length < PASSWORD_MIN_LENGTH) {
    redirect(res, `/admin?error=password_must_be_at_least_${PASSWORD_MIN_LENGTH}_characters`);
    return;
  }

  const data = await readJson(config.usersFile, { users: [] });
  const usernameKey = username.toLowerCase();
  if (data.users.some((user) => user.usernameKey === usernameKey)) {
    redirect(res, '/admin?error=username_already_exists');
    return;
  }

  const passwordRecord = await hashPassword(password);
  data.users.push({
    id: crypto.randomUUID(),
    username,
    usernameKey,
    role: form.isAdmin === 'true' ? 'admin' : 'user',
    status: 'active',
    passwordSalt: passwordRecord.salt,
    passwordHash: passwordRecord.hash,
    createdAt: nowIso(),
    passwordChangedAt: null,
  });
  await writeJson(config.usersFile, data);
  await renderAdmin(res, config, { ...context, user: admin }, url, `Created ${username}. Password: ${password}`);
}

async function removeSessionsForUser(config, userId) {
  const data = await readJson(config.sessionsFile, { sessions: [] });
  const next = data.sessions.filter((session) => session.userId !== userId);
  if (next.length !== data.sessions.length) {
    await writeJson(config.sessionsFile, { sessions: next });
  }
}

async function handleAdminUserAction(req, res, config, context, id, url) {
  const admin = requireAdmin(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const data = await readJson(config.usersFile, { users: [] });
  const target = data.users.find((user) => user.id === id);
  if (!target) throw new HttpError(404, 'User not found');

  const action = String(form.action || '');
  const adminCount = data.users.filter((user) => user.role === 'admin' && user.status !== 'disabled').length;
  if (target.id === admin.id && ['disable', 'demote'].includes(action)) {
    redirect(res, '/admin?error=cannot_change_your_own_admin_access');
    return;
  }
  if (target.role === 'admin' && adminCount <= 1 && ['disable', 'demote'].includes(action)) {
    redirect(res, '/admin?error=cannot_remove_the_last_active_admin');
    return;
  }

  if (action === 'enable') {
    target.status = 'active';
    await writeJson(config.usersFile, data);
    redirect(res, '/admin?ok=user_enabled');
    return;
  }
  if (action === 'disable') {
    target.status = 'disabled';
    await writeJson(config.usersFile, data);
    await removeSessionsForUser(config, target.id);
    redirect(res, '/admin?ok=user_disabled');
    return;
  }
  if (action === 'promote') {
    target.role = 'admin';
    await writeJson(config.usersFile, data);
    redirect(res, '/admin?ok=user_promoted');
    return;
  }
  if (action === 'demote') {
    target.role = 'user';
    await writeJson(config.usersFile, data);
    redirect(res, '/admin?ok=user_demoted');
    return;
  }
  if (action === 'reset-password') {
    const password = createPassword();
    const passwordRecord = await hashPassword(password);
    target.passwordSalt = passwordRecord.salt;
    target.passwordHash = passwordRecord.hash;
    target.passwordChangedAt = nowIso();
    await writeJson(config.usersFile, data);
    await removeSessionsForUser(config, target.id);
    await renderAdmin(res, config, context, url, `Reset password for ${target.username}. New password: ${password}`);
    return;
  }

  throw new HttpError(400, 'Unknown user action');
}

async function createGist(req, res, config, context) {
  const user = requireUser(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const title = String(form.title || '').trim().slice(0, 120) || 'Untitled';
  const content = String(form.content || '');
  if (Buffer.byteLength(content, 'utf8') > config.maxTextBytes) {
    throw new HttpError(413, 'Submitted text is too large');
  }

  const data = await readJson(config.gistsFile, { gists: [] });
  let id = createId();
  for (let attempts = 0; data.gists.some((gist) => gist.id === id); attempts += 1) {
    if (attempts > 10) throw new HttpError(500, 'Could not allocate a gist id');
    id = createId();
  }

  const timestamp = nowIso();
  data.gists.push({
    id,
    ownerId: user.id,
    title,
    createdAt: timestamp,
    updatedAt: timestamp,
  });
  await writeTextFile(textFileFor(config, id), content);
  await writeJson(config.gistsFile, data);
  redirect(res, `/gists/${id}?ok=gist_created`);
}

async function renderGist(req, res, config, context, id, url) {
  if (!ID_PATTERN.test(id)) throw new HttpError(404, 'Gist not found');
  const gist = await findGist(config, id);
  if (!gist) throw new HttpError(404, 'Gist not found');

  const content = await fs.readFile(textFileFor(config, id), 'utf8').catch((error) => {
    if (error.code === 'ENOENT') return '';
    throw error;
  });
  const ownsGist = context.user && context.user.id === gist.ownerId;
  const rawPath = `/raw/${gist.id}`;
  const rawUrl = absoluteUrl(req, config, rawPath);

  const body = ownsGist
    ? `
      <h1>${htmlEscape(gist.title)}</h1>
      <section class="panel stack">
        <div>
          <div class="muted">Stable raw link</div>
          <a class="raw-link" href="${htmlEscape(rawPath)}">${htmlEscape(rawUrl)}</a>
        </div>
        <form method="post" action="/gists/${htmlEscape(gist.id)}" class="stack">
          <input type="hidden" name="csrf" value="${htmlEscape(context.user.csrf)}">
          <div class="field">
            <label for="title">Title</label>
            <input id="title" name="title" maxlength="120" value="${htmlEscape(gist.title)}">
          </div>
          <div class="field">
            <label for="content">Text</label>
            <textarea id="content" name="content" spellcheck="false">${htmlEscape(content)}</textarea>
          </div>
          <div class="actions">
            <button type="submit">Save changes</button>
            <a class="button ghost" href="${htmlEscape(rawPath)}">Open raw</a>
          </div>
        </form>
        <form method="post" action="/gists/${htmlEscape(gist.id)}/delete" class="inline-form">
          <input type="hidden" name="csrf" value="${htmlEscape(context.user.csrf)}">
          <button type="submit" class="danger">Delete gist</button>
        </form>
      </section>`
    : `
      <h1>${htmlEscape(gist.title)}</h1>
      <div class="stack">
        <p class="muted">Read-only public view. Raw link: <a class="raw-link" href="${htmlEscape(rawPath)}">${htmlEscape(rawUrl)}</a></p>
        <pre>${htmlEscape(content)}</pre>
      </div>`;

  send(res, 200, layout({ title: gist.title, user: context.user, body, flash: flashFrom(url) }));
}

async function updateGist(req, res, config, context, id) {
  const user = requireUser(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const data = await readJson(config.gistsFile, { gists: [] });
  const gist = data.gists.find((item) => item.id === id);
  if (!gist) throw new HttpError(404, 'Gist not found');
  if (gist.ownerId !== user.id) throw new HttpError(403, 'You can only edit your own gists');

  const title = String(form.title || '').trim().slice(0, 120) || 'Untitled';
  const content = String(form.content || '');
  if (Buffer.byteLength(content, 'utf8') > config.maxTextBytes) {
    throw new HttpError(413, 'Submitted text is too large');
  }

  gist.title = title;
  gist.updatedAt = nowIso();
  await writeTextFile(textFileFor(config, id), content);
  await writeJson(config.gistsFile, data);
  redirect(res, `/gists/${id}?ok=saved`);
}

async function deleteGist(req, res, config, context, id) {
  const user = requireUser(context);
  const form = await readForm(req, config);
  requireCsrf(form, context);

  const data = await readJson(config.gistsFile, { gists: [] });
  const gist = data.gists.find((item) => item.id === id);
  if (!gist) throw new HttpError(404, 'Gist not found');
  if (gist.ownerId !== user.id) throw new HttpError(403, 'You can only delete your own gists');

  await fs.unlink(textFileFor(config, id)).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
  });
  await writeJson(config.gistsFile, {
    gists: data.gists.filter((item) => item.id !== id),
  });
  redirect(res, '/?ok=gist_deleted');
}

async function sendRawGist(res, config, id) {
  if (!ID_PATTERN.test(id)) throw new HttpError(404, 'Gist not found');
  const gist = await findGist(config, id);
  if (!gist) throw new HttpError(404, 'Gist not found');
  const content = await fs.readFile(textFileFor(config, id), 'utf8').catch((error) => {
    if (error.code === 'ENOENT') return '';
    throw error;
  });
  sendText(res, 200, content);
}

async function handleRequest(req, res, config) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const context = await getRequestContext(req, config);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  if (req.method === 'GET' && pathname === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return;
  }
  if (req.method === 'GET' && pathname === '/robots.txt') {
    sendText(res, 200, 'User-agent: *\nDisallow:\n');
    return;
  }
  if (req.method === 'GET' && pathname === '/healthz') {
    sendText(res, 200, 'ok\n');
    return;
  }
  if (req.method === 'GET' && pathname === '/') {
    await renderHome(req, res, config, context, url);
    return;
  }
  if (req.method === 'POST' && pathname === '/register') {
    await handleRegister(req, res, config);
    return;
  }
  if (req.method === 'POST' && pathname === '/login') {
    await handleLogin(req, res, config);
    return;
  }
  if (req.method === 'POST' && pathname === '/logout') {
    await handleLogout(req, res, config, context);
    return;
  }
  if (req.method === 'GET' && pathname === '/account') {
    await renderAccount(res, context, url);
    return;
  }
  if (req.method === 'POST' && pathname === '/account/password') {
    await handleChangePassword(req, res, config, context);
    return;
  }
  if (req.method === 'GET' && pathname === '/admin') {
    await renderAdmin(res, config, context, url);
    return;
  }
  if (req.method === 'POST' && pathname === '/admin/settings') {
    await handleAdminSettings(req, res, config, context);
    return;
  }
  if (req.method === 'POST' && pathname === '/admin/users') {
    await handleAdminCreateUser(req, res, config, context, url);
    return;
  }
  if (req.method === 'POST' && pathname === '/gists') {
    await createGist(req, res, config, context);
    return;
  }

  const adminUserActionMatch = pathname.match(/^\/admin\/users\/([^/]+)\/action$/);
  if (req.method === 'POST' && adminUserActionMatch) {
    await handleAdminUserAction(req, res, config, context, adminUserActionMatch[1], url);
    return;
  }

  const rawMatch = pathname.match(/^\/raw\/([^/]+)$/);
  if (req.method === 'GET' && rawMatch) {
    await sendRawGist(res, config, rawMatch[1]);
    return;
  }

  const deleteMatch = pathname.match(/^\/gists\/([^/]+)\/delete$/);
  if (req.method === 'POST' && deleteMatch) {
    await deleteGist(req, res, config, context, deleteMatch[1]);
    return;
  }

  const gistMatch = pathname.match(/^\/gists\/([^/]+)$/);
  if (gistMatch) {
    if (req.method === 'GET') {
      await renderGist(req, res, config, context, gistMatch[1], url);
      return;
    }
    if (req.method === 'POST') {
      await updateGist(req, res, config, context, gistMatch[1]);
      return;
    }
  }

  throw new HttpError(404, 'Page not found');
}

function handleError(req, res, error) {
  const status = error instanceof HttpError ? error.status : 500;
  const message = status === 500 ? 'Internal server error' : error.message;

  if (status === 401) {
    redirect(res, `/?error=${encodeURIComponent(message)}`);
    return;
  }

  if (req.url.startsWith('/raw/')) {
    sendText(res, status, `${message}\n`);
    return;
  }

  send(
    res,
    status,
    layout({
      title: String(status),
      user: null,
      body: `<h1>${status}</h1><p>${htmlEscape(message)}</p><p><a href="/">Back home</a></p>`,
    }),
  );

  if (status === 500) {
    console.error(error);
  }
}

function createServer(options = {}) {
  const config = makeConfig(options);
  const ready = ensureStore(config);

  return http.createServer(async (req, res) => {
    try {
      await ready;
      await handleRequest(req, res, config);
    } catch (error) {
      handleError(req, res, error);
    }
  });
}

function start() {
  const config = makeConfig();
  const server = createServer(config);
  server.listen(config.port, config.host, () => {
    console.log(`Text Gists listening on http://${config.host}:${config.port}`);
    console.log(`Data directory: ${config.dataDir}`);
  });
}

if (require.main === module) {
  start();
}

module.exports = {
  createServer,
  ensureStore,
  makeConfig,
};