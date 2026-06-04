//! The SentinelOS **security subsystem** — safe kernel code, zero TCB growth.
//!
//! This module is the first home of SentinelOS's "agent-native, reversible,
//! tamper-evident" direction. It carries the crate's `#![forbid(unsafe_code)]`
//! and adds **no** new `unsafe` and **no** new TCB surface: every privileged
//! primitive it needs (ATA block I/O, the PIT tick counter, the sanctioned
//! [`SpinMutex`](hal::mm::sync::SpinMutex)) is already wrapped by the `hal` TCB
//! and reached through its **safe** surface. This is the framekernel thesis
//! working as designed (spec §5.1).
//!
//! # Components
//!
//! * [`sha256`] — a hand-rolled, pure-safe-Rust SHA-256 (the chain hash).
//! * [`audit`] — the kernel-native, append-only, hash-chained audit log: the
//!   substrate under the agent-native (#1), reversible (#2), and tamper-evident
//!   (#4) north-star goals.
//!
//! # Future home (spec §5.2)
//!
//! When the subsystem grows a second component (a capability engine, the
//! reversibility journal-replayer, a `no_std` `sentinel-core` port), this module
//! is promoted to a `crates/security` crate and the byte-codec helpers shared with
//! `fs.rs` move to a small `serde`-free internal codec module — flagged as a future
//! architecture review.

pub mod audit;
pub mod sha256;
