/**
 * English resources. zh-CN is the source of truth; keep keys in sync
 * (a missing key falls back to zh-CN by init config).
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
