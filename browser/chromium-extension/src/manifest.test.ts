/**
 * manifest 契约测试：MV3 装配的三条硬约定。
 *
 * 1. webauthnHook（MAIN world）只在顶层 frame 注入：给每个第三方 iframe 都包
 *    一层 navigator.credentials 侵入性太大，而且跨源 iframe 的 passkey 会退回
 *    浏览器原生流程（设计决定，见 README）。这条断言防止有人顺手改 all_frames。
 * 2. content.js 覆盖所有 frame（含 about:blank/srcdoc），批 B 的 iframe 登录
 *    自动填充依赖它。
 * 3. content.js 必须留在 ISOLATED world（不写 world 字段即默认）——MAIN world
 *    里能碰到页面脚本的任何东西。
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

interface ContentScriptEntry {
    matches?: string[];
    js?: string[];
    run_at?: string;
    world?: string;
    all_frames?: boolean;
    match_about_blank?: boolean;
}

interface Manifest {
    manifest_version: number;
    version: string;
    permissions?: string[];
    background?: { service_worker?: string; type?: string };
    action?: { default_popup?: string };
    content_scripts?: ContentScriptEntry[];
}

const manifest: Manifest = JSON.parse(
    readFileSync(join(__dirname, '..', 'public', 'manifest.json'), 'utf8')
);

function entryFor(file: string): ContentScriptEntry {
    const entry = manifest.content_scripts?.find((candidate) => candidate.js?.includes(file));
    if (!entry) throw new Error(`no content_scripts entry injects ${file}`);
    return entry;
}

describe('manifest — webauthn hook (passkey interception)', () => {
    it('runs in the MAIN world at document_start, top frame only', () => {
        const entry = entryFor('webauthnHook.js');
        expect(entry.world).toBe('MAIN');
        expect(entry.run_at).toBe('document_start');
        expect(entry.all_frames).toBe(false);
    });

    it('matches all urls so the top-frame ceremony is always interceptable', () => {
        expect(entryFor('webauthnHook.js').matches).toContain('<all_urls>');
    });
});

describe('manifest — content script (autofill + save bar)', () => {
    it('covers every frame, including about:blank/srcdoc frames', () => {
        const entry = entryFor('content.js');
        expect(entry.all_frames).toBe(true);
        expect(entry.match_about_blank).toBe(true);
    });

    it('stays in the ISOLATED world at document_idle', () => {
        const entry = entryFor('content.js');
        expect(entry.world).toBeUndefined();
        expect(entry.run_at).toBe('document_idle');
    });

    it('matches all urls', () => {
        expect(entryFor('content.js').matches).toContain('<all_urls>');
    });
});

describe('manifest — host wiring', () => {
    it('is MV3 with the module service worker and the native-messaging permission', () => {
        expect(manifest.manifest_version).toBe(3);
        expect(manifest.background?.service_worker).toBe('background.js');
        expect(manifest.background?.type).toBe('module');
        expect(manifest.permissions).toEqual(
            expect.arrayContaining(['nativeMessaging', 'storage', 'scripting', 'activeTab'])
        );
    });

    it('keeps the action popup wired', () => {
        expect(manifest.action?.default_popup).toBe('popup.html');
    });
});