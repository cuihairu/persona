pub mod authentication;
pub mod auto_lock;
pub mod auto_lock_cached;
pub mod auto_lock_dashboard;
pub mod biometric;
pub mod permissions;
pub mod remote;
pub mod security_strategies;
pub mod session;

pub use authentication::*;
pub use auto_lock::*;
pub use biometric::*;
pub use permissions::*;
pub use remote::*;
pub use session::*;

// The three newer modules (auto_lock_cached, auto_lock_dashboard,
// security_strategies) are intentionally NOT glob re-exported: they define
// names (PerformanceMetrics, AuthMethod, …) that would collide with the
// existing re-exports above. Reference them through their module paths.
