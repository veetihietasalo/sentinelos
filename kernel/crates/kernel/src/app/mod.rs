//! The desktop **app model** — the object-safe [`App`] trait every window's
//! content implements, plus the [`AppKind`] catalogue the launcher spawns from.
//!
//! An app is a cooperative heap object owned by a window in the
//! [`crate::wm::WindowManager`]. It draws its content into its window's content
//! rectangle, handles key events while focused, and may self-update on a periodic
//! tick. Apps only ever draw through the safe `ui`/[`hal::framebuffer`] API, so —
//! like the rest of the kernel — this module carries the crate's
//! `#![forbid(unsafe_code)]` and never reaches below the framebuffer abstraction.
//!
//! Two apps ship in this milestone:
//! * [`terminal::Terminal`] — the interactive shell, rendered into a window.
//! * [`system_panel::SystemPanel`] — a live read-only memory/uptime panel that
//!   refreshes once a second, proving the compositor handles a second,
//!   independently-updating window.

pub mod system_panel;
pub mod terminal;

use alloc::boxed::Box;

use ui::Rect;

use crate::input::KeyEvent;

/// The content behind a window: it draws into its content rect, handles key
/// events while focused, and may self-update on a periodic tick.
///
/// The trait is **object-safe** so the window manager can hold a heterogeneous
/// list of `Box<dyn App>`. Every method draws/acts only through the safe
/// `ui`/`hal` API; an app overrunning its `area` is a safe no-op (the
/// `Framebuffer` clips), never undefined behaviour.
///
/// The `on_key`/`tick` methods return a `bool` "dirtied?" flag rather than
/// reaching into the WM: the window manager owns all damage bookkeeping centrally
/// and enqueues a content-rect repaint whenever an app reports a visible change.
pub trait App {
    /// The stable title shown centred in the window's title bar.
    fn title(&self) -> &str;

    /// Draw the app's content into `area` — the window's content rectangle, in
    /// absolute framebuffer coordinates (already inset past the window chrome by
    /// `ui::content_rect`). The WM draws the surrounding glass chrome separately,
    /// then calls this. Drawing is clipped by the `Framebuffer`, so an oversized
    /// or overrunning draw is a safe no-op.
    fn render(&self, fb: &hal::framebuffer::Framebuffer, area: Rect);

    /// Handle one decoded key event while this app is focused. Returns `true` if
    /// the app's visible content changed, so the WM enqueues a content-rect
    /// damage and re-composites this window on the next frame.
    fn on_key(&mut self, event: KeyEvent) -> bool;

    /// Optional periodic update; `now_ticks` is the current PIT tick count.
    /// Returns `true` if the app's content changed (e.g. the system panel
    /// refreshing its stats once a second), so the WM damages just this window.
    /// The default is a no-op that reports no change.
    fn tick(&mut self, _now_ticks: u64) -> bool {
        false
    }
}

/// The catalogue of app types the launcher can spawn a new window from.
///
/// Each variant maps to a concrete `App` constructor in [`spawn`]. Adding an app
/// is a matter of adding a variant here, a label in [`AppKind::label`], and a
/// match arm in [`spawn`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppKind {
    /// The interactive shell (the [`terminal::Terminal`] app).
    Terminal,
    /// The live memory/uptime panel (the [`system_panel::SystemPanel`] app).
    System,
}

impl AppKind {
    /// The human-readable label shown for this app in the launcher menu.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            AppKind::Terminal => "Terminal",
            AppKind::System => "System",
        }
    }
}

/// Construct a fresh boxed [`App`] of the requested [`AppKind`].
///
/// Allocates on the kernel heap, so it must be called after `memory::init` has
/// installed the global allocator (always true on the desktop). The window
/// manager calls this from `spawn` to build a launcher-selected app.
#[must_use]
pub fn spawn(kind: AppKind) -> Box<dyn App> {
    match kind {
        AppKind::Terminal => Box::new(terminal::Terminal::new()),
        AppKind::System => Box::new(system_panel::SystemPanel::new()),
    }
}
