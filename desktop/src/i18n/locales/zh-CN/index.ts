/**
 * Simplified Chinese resources (base locale - finalise new copy here first, en.ts follows).
 * Top-level keys are namespaced by component/domain: common holds words reused across components.
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
