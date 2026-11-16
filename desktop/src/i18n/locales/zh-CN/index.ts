/**
 * 简体中文资源（基准语言——新增文案先在这里定稿，en.ts 跟随）。
 * 顶层 key 按组件/领域分 namespace：common 为跨组件复用词。
 */
import common from './shell';
import settingsPack from './settings';
import credentials from './credentials';
import ssh from './ssh';
import wallet from './wallet';
import tools from './tools';

export default {
  ...common,
  ...settingsPack,
  ...credentials,
  ...ssh,
  ...wallet,
  ...tools,
};
