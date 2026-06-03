//! `sentinel-core` — the portable, OS-agnostic heart of Sentinel.
//!
//! Zero I/O lives here on purpose: this crate is reused unchanged by the desktop
//! app (via a platform provider) and, later, by SentinelOS's security subsystem.
pub mod model;
pub mod provider;
pub mod diff;
pub mod monitor;
