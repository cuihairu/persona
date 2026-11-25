// Config-switch effect animation pipeline (todo.md DOC-GIF).
//
// For every settings switch in the list, produce an off→on comparison image + GIF;
// the screenshots also assert the switch's UI effect (sidebar node appears /
// favicon image appears), doubling as a config-effect regression test — if a
// switch stops working (toggled with no response / effect lost), this script's
// assertion fails and it exits non-zero.
//
// Usage (build the latest dist in desktop/ first):
//   cd desktop && npm run build && cd ..
//   node scripts/doc-config-switch-gif.mjs [distDir] [outDir]
// Defaults: distDir=desktop/dist, outDir=docs/branding/ui/config-switches.
// Depends on playwright (resolved in order scripts/ → cwd → ~/.cache/persona-ui-shots)
// and ffmpeg (GIF composition). The artifacts are also copied to
// docs/src/public/ui/config-switches/ as the site copy (matching the existing
// docs/branding/ui ↔ docs/src/public/ui convention).

import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const dist = path.resolve(process.argv[2] ?? 'desktop/dist');
const outDir = path.resolve(process.argv[3] ?? 'docs/branding/ui/config-switches');
const siteDir = path.resolve('docs/src/public/ui/config-switches');
const PORT = 41881;

// playwright resolution: not installed in the repo, fall back to common locations (the local screenshot pipeline installs it in the cache directory)
let chromium;
for (const base of [path.resolve('scripts'), process.cwd(), path.join(os.homedir(), '.cache/persona-ui-shots')]) {
  try {
    chromium = createRequire(path.join(base, 'noop.js'))('playwright').chromium;
    break;
  } catch {
    /* try the next location */
  }
}
if (!chromium) {
  console.error('playwright not found: npm i -D playwright in scripts/, or install into ~/.cache/persona-ui-shots');
  process.exit(1);
}

// ---- Switch list (aligned with, and in the same order as, the FEATURE_ROWS in
// desktop/src/components/SettingsModal.tsx; nodes are assertion anchors, effect
// is the screenshot's effect region, and anchor is a scroll anchor that sits
// adjacent to the effect row and is present in both off/on states (keeping the
// rows that appear/disappear inside the screenshot viewport) ----
const SWITCHES = [
  { key: 'ssh_agent', slug: 'ssh-agent', title: 'SSH Agent', effect: 'sidebar-nav', anchor: 'nav-category-api_keys', nodes: ['nav-sshAgent', 'nav-category-ssh_keys'] },
  { key: 'wallet', slug: 'wallet', title: 'Wallet', effect: 'sidebar-nav', anchor: 'nav-watchtower', nodes: ['nav-wallets'] },
  { key: 'passkeys', slug: 'passkeys', title: 'Passkeys', effect: 'sidebar-nav', anchor: 'nav-category-passwords', nodes: ['nav-passkeys'] },
  { key: 'fetch_favicons', slug: 'fetch-favicons', title: 'Fetch Favicons', effect: 'credential-list', anchor: null },
];

const NOW = '2026-09-28T04:00:00Z';
const identity = { id: 'i-demo', name: 'demo', identity_type: 'Personal', description: 'Demo identity for screenshots', email: 'demo@example.com', phone: null, tags: ['daily'], attributes: {}, created_at: NOW, updated_at: NOW, is_active: true, travel_marked: false };
let seq = 0;
const cred = (name, credential_type, over = {}) => ({ id: `c${++seq}`, identity_id: 'i-demo', name, credential_type, security_level: 'High', data: {}, url: null, username: null, notes: null, tags: [], created_at: NOW, updated_at: NOW, last_accessed: NOW, is_active: true, is_favorite: false, ...over });
const credentials = [
  cred('GitHub', 'Password', { url: 'https://github.com', username: 'demo', is_favorite: true, tags: ['dev'] }),
  cred('GitLab', 'Password', { url: 'https://gitlab.com', username: 'demo', tags: ['dev', 'work'] }),
  cred('公司邮箱', 'Password', { url: 'https://mail.example.com', username: 'demo@example.com', tags: ['work'] }),
  cred('Cloud API Token', 'ApiKey', { url: 'https://api.example.com', tags: ['work'] }),
  cred('CI Deploy Key', 'ApiKey', { tags: ['dev'] }),
  cred('服务器 root 备忘', 'SecureNote', { tags: ['work'] }),
  cred('笔记本 SSH 密钥', 'SshKey', { is_favorite: true }),
  cred('游戏账号', 'GameAccount', { url: 'https://store.example.com' }),
];
// 16x16 monochrome placeholder icon (the favicon effect demo only needs "an image appears"; content is irrelevant)
const FAVICON_B64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAGUExURRajSv///7N4I0QAAAABYktHRAH/Ai3eAAAAB3RJTUUH6gsCDRwseqXJMwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0xMS0wMlQxMzoyODo0NCswMDowMFAz/GsAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMTEtMDJUMTM6Mjg6NDQrMDA6MDAhbkTXAAAAKHRFWHRkYXRlOnRpbWVzdGFtcAAyMDI2LTExLTAyVDEzOjI4OjQ0KzAwOjAwdntlCAAAAAxJREFUCNdjYCANAAAAMAABx6qFjgAAAABJRU5ErkJggg==';

// Serve dist statically + __TAURI_INTERNALS__ shim (the fixture mirrors the
// existing screenshot pipeline; features start all off, and set_feature_flags
// really mutates the mock state and returns the full settings)
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };
const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url ?? '/').split('?')[0]);
  let fp = path.join(dist, urlPath);
  if (!fp.startsWith(dist) || !fs.existsSync(fp) || fs.statSync(fp).isDirectory()) fp = path.join(dist, 'index.html');
  res.setHeader('Content-Type', MIME[path.extname(fp)] ?? 'application/octet-stream');
  fs.createReadStream(fp).pipe(res);
});
await new Promise((r) => server.listen(PORT, r));

// off/on single-frame screenshots + assertions + GIF/comparison image composition
async function main() {
  fs.mkdirSync(outDir, { recursive: true });
  const browser = await chromium.launch({ channel: 'chromium' });
  const context = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 1 });
  await context.addInitScript(() => {
    localStorage.setItem('persona-theme', 'light');
    const NOW = '2026-09-28T04:00:00Z';
    const identity = { id: 'i-demo', name: 'demo', identity_type: 'Personal', description: 'Demo identity for screenshots', email: 'demo@example.com', phone: null, tags: ['daily'], attributes: {}, created_at: NOW, updated_at: NOW, is_active: true, travel_marked: false };
    let seq = 0;
    const cred = (name, credential_type, over = {}) => ({ id: `c${++seq}`, identity_id: 'i-demo', name, credential_type, security_level: 'High', data: {}, url: null, username: null, notes: null, tags: [], created_at: NOW, updated_at: NOW, last_accessed: NOW, is_active: true, is_favorite: false, ...over });
    const credentials = [
      cred('GitHub', 'Password', { url: 'https://github.com', username: 'demo', is_favorite: true, tags: ['dev'] }),
      cred('GitLab', 'Password', { url: 'https://gitlab.com', username: 'demo', tags: ['dev', 'work'] }),
      cred('公司邮箱', 'Password', { url: 'https://mail.example.com', username: 'demo@example.com', tags: ['work'] }),
      cred('Cloud API Token', 'ApiKey', { url: 'https://api.example.com', tags: ['work'] }),
      cred('CI Deploy Key', 'ApiKey', { tags: ['dev'] }),
      cred('服务器 root 备忘', 'SecureNote', { tags: ['work'] }),
      cred('笔记本 SSH 密钥', 'SshKey', { is_favorite: true }),
      cred('游戏账号', 'GameAccount', { url: 'https://store.example.com' }),
    ];
    const FAVICON_B64 = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAAIGNIUk0AAHomAACAhAAA+gAAAIDoAAB1MAAA6mAAADqYAAAXcJy6UTwAAAAGUExURRajSv///7N4I0QAAAABYktHRAH/Ai3eAAAAB3RJTUUH6gsCDRwseqXJMwAAACV0RVh0ZGF0ZTpjcmVhdGUAMjAyNi0xMS0wMlQxMzoyODo0NCswMDowMFAz/GsAAAAldEVYdGRhdGU6bW9kaWZ5ADIwMjYtMTEtMDJUMTM6Mjg6NDQrMDA6MDAhbkTXAAAAKHRFWHRkYXRlOnRpbWVzdGFtcAAyMDI2LTExLTAyVDEzOjI4OjQ0KzAwOjAwdntlCAAAAAxJREFUCNdjYCANAAAAMAABx6qFjgAAAABJRU5ErkJggg==';
    const ok = (data) => ({ success: true, data });
    const features = { ssh_agent: false, wallet: false, passkeys: false, fetch_favicons: false };
    const settings = () => ({ encryption_enabled: true, auto_backup_hours: 24, backup_retention_count: 7, session_timeout_seconds: 3600, require_confirmation: true, default_identity_type: 'personal', locale: 'zh-CN', features: { ...features }, sync: null, password_expiry_days: null, travel_mode: false, travel_entered_at: null, quick_access_enabled: false, quick_access_hotkey: null });
    const handlers = {
      is_service_unlocked: () => ok(true),
      get_workspace_settings: () => ok(settings()),
      set_feature_flags: (args) => {
        features.ssh_agent = args.ssh_agent;
        features.wallet = args.wallet;
        features.passkeys = args.passkeys;
        features.fetch_favicons = args.fetch_favicons;
        return ok(settings());
      },
      get_identities: () => ok([identity]),
      get_active_identity: () => ok(identity),
      get_credentials_for_identity: () => ok(credentials),
      list_attachments: () => ok([]),
      get_favicons: (args) => ok((args.hosts || []).map((h) => ({ host: h, mime_type: 'image/png', data: FAVICON_B64 }))),
      get_statistics: () => ok({ total_identities: 1, total_credentials: credentials.length, active_credentials: credentials.length, favorite_credentials: 2, credential_types: { Password: 3, ApiKey: 2, SecureNote: 1, SshKey: 1, GameAccount: 1 }, security_levels: { High: 8 } }),
    };
    Object.defineProperty(window, '__TAURI_INTERNALS__', {
      configurable: true,
      value: { invoke: async (cmd, args) => (handlers[cmd] ? handlers[cmd](args) : ok(null)) },
    });
  });

  const page = await context.newPage();
  const failures = [];

  const openApp = async () => {
    await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'networkidle' });
    await page.waitForSelector('[data-testid="app-sidebar"]', { timeout: 15000 });
    await page.waitForTimeout(700);
  };
  const openSettings = async () => {
    await page.click('[data-testid="sidebar-footer"] button:first-child');
    await page.waitForSelector('[data-testid="feature-toggle-ssh_agent"]', { timeout: 8000 });
    await page.waitForTimeout(200);
  };
  const closeSettings = async () => {
    await page.keyboard.press('Escape');
    await page.waitForTimeout(500);
  };
  // Effect-region screenshot: scroll to the anchor first (so appearing/disappearing rows land in view), then capture the effect region
  const captureEffect = async (sw, dir, name) => {
    if (sw.anchor) {
      // Center the anchor: the effect row (adjacent to the anchor) has slack above and below, so it is not clipped at the edge
      await page.locator(`[data-testid="${sw.anchor}"]`).evaluate((el) => el.scrollIntoView({ block: 'center' }));
      await page.waitForTimeout(250);
    }
    await page.locator(`[data-testid="${sw.effect}"]`).screenshot({ path: path.join(dir, name) });
  };

  for (const sw of SWITCHES) {
    // Each switch starts from an all-off baseline: a full page reload, which also resets the mock state
    await openApp();

    const faviconOff = sw.effect === 'credential-list' ? await page.locator('[data-testid="favicon-img"]').count() : null;
    const navOff = sw.nodes ? await Promise.all(sw.nodes.map((n) => page.locator(`[data-testid="${n}"]`).count())) : null;

    await page.screenshot({ path: path.join(outDir, `${sw.slug}-off.png`) });
    await captureEffect(sw, os.tmpdir(), `docgif-${sw.slug}-off.png`);

    await openSettings();
    await page.click(`[data-testid="feature-toggle-${sw.key}"]`);
    await page.waitForTimeout(600); // set_feature_flags round-trip + optimistic backfill
    const checked = await page.locator(`[data-testid="feature-toggle-${sw.key}"]`).getAttribute('aria-checked');
    await closeSettings();
    await page.waitForTimeout(600);

    await page.screenshot({ path: path.join(outDir, `${sw.slug}-on.png`) });
    await captureEffect(sw, os.tmpdir(), `docgif-${sw.slug}-on.png`);

    // Regression assertion: the effect is absent when off and present when on (a broken switch fails right here)
    const assertOff = [];
    if (sw.nodes) {
      sw.nodes.forEach((n, i) => assertOff.push([`${n} hidden when off`, navOff[i] === 0, navOff[i]]));
      for (const n of sw.nodes) {
        const on = await page.locator(`[data-testid="${n}"]`).count();
        assertOff.push([`${n} visible when on`, on === 1, on]);
      }
    } else {
      assertOff.push(['favicon imgs absent when off', faviconOff === 0, faviconOff]);
      const on = await page.locator('[data-testid="favicon-img"]').count();
      assertOff.push(['favicon imgs present when on', on > 0, on]);
    }
    assertOff.push([`${sw.key} toggled`, checked === 'true', checked]);

    for (const [name, pass, got] of assertOff) {
      if (!pass) failures.push(`${sw.slug}: ${name} (got ${got})`);
      console.log(`  ${pass ? 'ok' : 'FAIL'}  ${sw.slug}: ${name}${pass ? '' : ` (got ${got})`}`);
    }

    // GIF: hold off for 1.2s → 0.4s fade into on → hold on for 1.2s, then loop
    const offPng = path.join(os.tmpdir(), `docgif-${sw.slug}-off.png`);
    const onPng = path.join(os.tmpdir(), `docgif-${sw.slug}-on.png`);
    execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-loop', '1', '-t', '1.6', '-i', offPng, '-loop', '1', '-t', '1.6', '-i', onPng, '-filter_complex', '[0:v]fps=12,format=rgba,setpts=PTS-STARTPTS[a];[1:v]fps=12,format=rgba,setpts=PTS-STARTPTS[b];[a][b]xfade=transition=fade:duration=0.4:offset=1.2,split[x][y];[x]palettegen=max_colors=128[p];[y][p]paletteuse=dither=bayer:bayer_scale=3', path.join(outDir, `${sw.slug}.gif`)]);
    // off/on comparison image: the effect region tiled side by side
    execFileSync('convert', [offPng, onPng, '+append', '-bordercolor', '#e5e7eb', '-border', '1', path.join(outDir, `${sw.slug}-off-on.png`)]);
    console.log(`done ${sw.slug}`);
  }

  await browser.close();

  if (failures.length > 0) {
    console.error(`\n${failures.length} assertion(s) failed:`);
    for (const f of failures) console.error(`  - ${f}`);
    process.exitCode = 1;
  } else {
    // Site copy (consistent with the docs/branding/ui ↔ docs/src/public/ui convention)
    fs.rmSync(siteDir, { recursive: true, force: true });
    fs.cpSync(outDir, siteDir, { recursive: true });
    console.log(`\nall switches verified; assets in ${outDir} (+ site copy in ${siteDir})`);
  }
}

main().finally(() => server.close());
