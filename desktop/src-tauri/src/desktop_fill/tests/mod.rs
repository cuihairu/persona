use super::*;

#[cfg(target_os = "windows")]
use super::win;

#[cfg(target_os = "windows")]
mod tests_win;

#[cfg(not(target_os = "windows"))]
mod tests_nonwin;

mod tests_confirm_binding;
