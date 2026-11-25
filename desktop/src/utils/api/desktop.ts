import { invoke } from './invoke';

import type {
  ApiResponse,
  QuickAccessStatus,
  FillTargetStatus,
  DesktopFillResult,
  GeneratorStatus,
} from '@/types';

export const desktopApi = {

  // -------------------------------------------------------------------------
  // Quick Access (OS-level global hotkey + floating panel)
  // -------------------------------------------------------------------------

  /** Reads the status surface (no unlock needed): configured = the DB truth, registered = the actual grab result */
  async quickAccessStatus(): Promise<ApiResponse<QuickAccessStatus>> {
    return invoke('quick_access_status');
  },


  /**
   * Changes the switch / binding. Passing null or an empty string for
   * accelerator restores the platform default binding.
   * An `error` in the response means the binding was persisted but the OS grab
   * failed (the settings page displays it as-is).
   */
  async quickAccessSet(
    enabled: boolean,
    accelerator: string | null,
  ): Promise<ApiResponse<QuickAccessStatus>> {
    return invoke('quick_access_set', { enabled, accelerator });
  },


  /** Brings up the floating panel (tray / settings-page entry; the fallback when the hotkey is taken) */
  async quickAccessOpen(): Promise<ApiResponse<boolean>> {
    return invoke('quick_access_open');
  },


  /** Floating panel → main window cross-window jump (switch identity + select entry + bring the main window to front) */
  async quickAccessOpenCredential(
    identityId: string,
    credentialId: string,
  ): Promise<ApiResponse<boolean>> {
    return invoke('quick_access_open_credential', {
      request: { identity_id: identityId, credential_id: credentialId },
    });
  },


  /** Desktop fill injection target status (#12: probing whether the panel's fill action is available + target info for the confirmation surface) */
  async fillTargetStatus(): Promise<ApiResponse<FillTargetStatus>> {
    return invoke('fill_target_status');
  },


  /**
   * In-app desktop fill injection (#12: injects into the foreground window
   * from before the floating panel was raised). `confirmed` must come from the
   * user's explicit confirmation on the panel's confirmation surface (target
   * app name + window title) — the backend refuses confirmed=false outright, so
   * there is no silent-injection path. `snapshotId` is the snapshot
   * identifier the confirmation surface gets from fill_target_status (the P1
   * confirmation binding): the backend uses it to bind the confirmation to that
   * specific snapshot — if the target is recaptured or the panel collapses while
   * the request is in flight, it refuses honestly
   * (FILL_TARGET_CHANGED / FILL_TARGET_DISCARDED) and never redirects to a
   * new target.
   */
  async desktopFillCredential(
    credentialId: string,
    confirmed: boolean,
    snapshotId: string,
  ): Promise<ApiResponse<DesktopFillResult>> {
    return invoke('desktop_fill_credential', {
      credential_id: credentialId,
      confirmed,
      snapshot_id: snapshotId,
    });
  },


  /** Brings the main window to the front (the "go unlock" exit out of the panel's locked state) */
  async focusMainWindow(): Promise<ApiResponse<boolean>> {
    return invoke('focus_main_window');
  },


  // -------------------------------------------------------------------------
  // Generator hotkey (remaining gap #9: OS-level summoning of the generator
  // panel; the same gating / persistence / grab semantics as Quick Access, with
  // its own window and slot)
  // -------------------------------------------------------------------------

  /** Reads the generator hotkey status surface (no unlock needed, same as quickAccessStatus) */
  async generatorStatus(): Promise<ApiResponse<GeneratorStatus>> {
    return invoke('generator_status');
  },


  /**
   * Changes the generator switch / binding. Passing null or an empty string for
   * accelerator restores the platform default binding.
   * An `error` in the response means the binding was persisted but the OS grab
   * failed (the settings page displays it as-is).
   */
  async generatorSet(
    enabled: boolean,
    accelerator: string | null,
  ): Promise<ApiResponse<GeneratorStatus>> {
    return invoke('generator_set', { enabled, accelerator });
  },


  /** Brings up the generator panel (tray / settings-page entry; the fallback when the hotkey is taken) */
  async generatorOpen(): Promise<ApiResponse<boolean>> {
    return invoke('generator_open');
  },
};