import { defineConfig } from 'umi';

export default defineConfig({
  title: 'Persona - Your Digital Identity Guardian',
  metas: [
    { name: 'description', content: 'Persona is a modern, open-source password manager with SSH Agent and digital wallet support. Built for developers who value security and privacy.' },
  ],
  routes: [
    { path: '/', component: 'index' },
    { path: '/features', component: 'features' },
    { path: '/download', component: 'download' },
    { path: '/docs', component: 'docs' },
    { path: '/pricing', component: 'pricing' },
  ],
  npmClient: 'pnpm',
  plugins: [
    '@umijs/plugins/dist/antd',
  ],
  antd: {
    configProvider: {},
  },
  hash: true,
  history: {
    type: 'browser',
  },
  links: [
    { rel: 'icon', href: '/favicon.ico' },
  ],
  headScripts: [],
  styles: [],
});
