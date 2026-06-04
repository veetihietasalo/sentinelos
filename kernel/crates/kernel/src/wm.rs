//! The in-kernel **window manager** (WM) and **compositor** — the policy layer
//! that owns the desktop's windows, focus, z-order, and damage tracking, and
//! drives the `ui` drawing primitives to paint them.
//!
//! # Boundary
//!
//! `ui` owns *drawing* (how a glass window/panel looks, how to erase a region back
//! to the Cyber Dusk backdrop); this module owns *policy* — which windows exist,
//! where they are tiled, which is focused, what changed since the last frame.
//! Like the rest of the kernel it is `#![forbid(unsafe_code)]` and reaches the
//! screen only through the bounds-checked `ui`/[`hal::framebuffer`] API.
//!
//! # Model
//!
//! A [`Window`] pairs a rectangle and a title with a boxed [`App`] (its content).
//! The [`WindowManager`] holds an unordered `Vec<Window>` plus a separate
//! `z_order` (indices, back→front) and a `focused` index, so re-stacking is a
//! cheap index shuffle that never invalidates a [`WindowId`] or moves a
//! `Box<dyn App>`. Windows are **tiled non-overlapping** by default (side by side
//! below the top bar, above the dock); because the glass composites analytically
//! over the gradient backdrop, a tiled layout is pixel-exact (spec §4.4).
//!
//! # Damage-driven compositing
//!
//! The WM never repaints the whole screen on a steady frame. A [`DamageQueue`]
//! collects dirty rectangles; [`WindowManager::composite`] erases each damaged
//! window's bounds back to the backdrop (`ui::clear_rect`), then redraws the
//! window chrome (`ui::draw_window_chrome`) and the app's content into the inner
//! `ui::content_rect`. Only windows whose `needs_redraw` is set are repainted.
//! Opening the launcher draws a glass overlay; closing it damages every window so
//! the region it covered repaints cleanly.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use ui::{Rect, WindowChrome};

use crate::app::{self, App, AppKind};
use crate::input::KeyEvent;

/// A stable external handle to a window — a newtype over `u32` that survives
/// re-stacking (unlike the internal `Vec` index, which is recomputed as needed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowId(pub u32);

/// A desktop window: a rectangle + title + the boxed [`App`] behind it, plus a
/// per-window dirty flag the compositor consults.
pub struct Window {
    /// Stable handle, unique for this WM's lifetime.
    pub id: WindowId,
    /// Outer rectangle including the title-bar chrome, absolute fb coordinates.
    pub bounds: Rect,
    /// Title shown centred in the title bar (captured from the app at spawn).
    pub title: String,
    /// The content + key handler.
    pub app: Box<dyn App>,
    /// `true` when the window's content/chrome changed since the last composite.
    pub needs_redraw: bool,
    /// `true` when the window's *bounds* changed (spawn / close / re-tile), so the
    /// compositor must first erase the old/new region back to the backdrop with
    /// `ui::clear_rect`. A pure content change (a keystroke, a stat refresh) leaves
    /// the bounds intact and only needs the glass repaint, skipping the backdrop
    /// clear — `draw_window_chrome` recomposites the whole glass body, erasing any
    /// stale content beneath it without a separate clear pass.
    pub needs_clear: bool,
}

/// A queue of dirty rectangles to repaint on the next composite pass.
///
/// Kept deliberately small: the desktop has a handful of windows, so a simple
/// bounding-box coalesce is enough to cut overdraw without a full region algebra.
#[derive(Default)]
pub struct DamageQueue {
    rects: Vec<Rect>,
}

impl DamageQueue {
    /// A fresh, empty damage queue.
    #[must_use]
    pub const fn new() -> Self {
        Self { rects: Vec::new() }
    }

    /// Enqueue a dirty rectangle (a zero-size rect is dropped — nothing to paint).
    pub fn push(&mut self, r: Rect) {
        if r.w == 0 || r.h == 0 {
            return;
        }
        self.rects.push(r);
    }

    /// Merge overlapping/adjacent rectangles into their bounding boxes to reduce
    /// overdraw. A simple O(n²) pass over the few rects we ever hold: repeatedly
    /// fuse any two that touch until no more merges happen.
    pub fn coalesce(&mut self) {
        let mut merged = true;
        while merged {
            merged = false;
            let mut i = 0;
            while i < self.rects.len() {
                let mut j = i + 1;
                while j < self.rects.len() {
                    if rects_touch(self.rects[i], self.rects[j]) {
                        self.rects[i] = bounding_box(self.rects[i], self.rects[j]);
                        self.rects.remove(j);
                        merged = true;
                    } else {
                        j += 1;
                    }
                }
                i += 1;
            }
        }
    }

    /// Take all queued rectangles, leaving the queue empty.
    #[must_use]
    pub fn drain(&mut self) -> Vec<Rect> {
        core::mem::take(&mut self.rects)
    }

    /// `true` when there is nothing to repaint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rects.is_empty()
    }
}

/// `true` if `a` and `b` overlap or touch (share an edge), so they should fuse.
#[inline]
fn rects_touch(a: Rect, b: Rect) -> bool {
    a.x <= b.right() && b.x <= a.right() && a.y <= b.bottom() && b.y <= a.bottom()
}

/// `true` if rectangle `outer` fully contains `inner`.
#[inline]
fn rect_contains(outer: Rect, inner: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.right() <= outer.right()
        && inner.bottom() <= outer.bottom()
}

/// The smallest rectangle containing both `a` and `b`.
#[inline]
fn bounding_box(a: Rect, b: Rect) -> Rect {
    let x = a.x.min(b.x);
    let y = a.y.min(b.y);
    let right = a.right().max(b.right());
    let bottom = a.bottom().max(b.bottom());
    Rect::new(x, y, right - x, bottom - y)
}

/// Left-button bit in a PS/2 mouse packet's button bitmap (mirrors
/// `hal::mouse::BTN_LEFT`; kept local so the WM does not depend on the TCB's
/// bit layout beyond this one well-known flag).
const MOUSE_BTN_LEFT: u8 = 1 << 0;

/// Add a signed delta to an unsigned coordinate, clamped to `[0, max]` (saturating
/// at both ends). Used to advance the cursor without wrapping past a screen edge.
#[inline]
fn clamp_add(value: usize, delta: i16, max: usize) -> usize {
    let signed = value as i64 + i64::from(delta);
    if signed < 0 {
        0
    } else {
        (signed as usize).min(max)
    }
}

/// Build a [`Rect`] from a `(x, y, w, h)` tuple (as returned by
/// [`ui::cursor_rect`]).
#[inline]
fn rect_from_tuple(t: (usize, usize, usize, usize)) -> Rect {
    Rect::new(t.0, t.1, t.2, t.3)
}

/// `true` if the point `(px, py)` lies inside `rect` (left/top inclusive,
/// right/bottom exclusive).
#[inline]
fn point_in_rect(px: usize, py: usize, rect: Rect) -> bool {
    px >= rect.x && py >= rect.y && px < rect.right() && py < rect.bottom()
}

/// The keyboard launcher: a glass overlay listing the apps that can be spawned,
/// plus a "Close focused" action, navigated by digit-select + Enter.
pub struct Launcher {
    /// Whether the launcher overlay is currently shown.
    open: bool,
    /// The highlighted menu index (`0..items.len()`).
    selected: usize,
}

/// The launcher menu items, in order: the spawnable app kinds then a close action.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LauncherItem {
    /// Spawn a new window of this app kind.
    Spawn(AppKind),
    /// Close the currently-focused window.
    CloseFocused,
}

/// The launcher menu length: every spawnable app kind ([`AppKind::ALL`]) plus the
/// trailing "Close focused" action. Data-driven, so adding an app to `AppKind::ALL`
/// extends the launcher with no change here.
const fn launcher_len() -> usize {
    AppKind::ALL.len() + 1
}

/// The launcher menu item at `idx`: the spawnable app kinds in order, then the
/// "Close focused" action as the final item.
const fn launcher_item(idx: usize) -> LauncherItem {
    if idx < AppKind::ALL.len() {
        LauncherItem::Spawn(AppKind::ALL[idx])
    } else {
        LauncherItem::CloseFocused
    }
}

impl Launcher {
    /// A closed launcher with the first item highlighted.
    #[must_use]
    const fn new() -> Self {
        Self {
            open: false,
            selected: 0,
        }
    }
}

impl Default for Launcher {
    fn default() -> Self {
        Self::new()
    }
}

/// What a routed key event asked the WM's owner (the idle loop) to do, so the
/// caller knows whether a re-composite is needed and can log structural events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WmAction {
    /// Nothing changed; no repaint needed.
    None,
    /// Something visible changed; the caller should call [`WindowManager::composite`].
    Redraw,
}

/// Maximum number of windows, so a launcher-spam can't exhaust the heap (§11).
const MAX_WINDOWS: usize = 6;

/// The window manager: the desktop's window list, z-order, focus, launcher, and
/// damage queue. Lives in the `Desktop` state and is ticked from the idle loop.
pub struct WindowManager {
    /// Unordered window storage, indexed by position in the `Vec`.
    windows: Vec<Window>,
    /// Indices into `windows`, back (0) → front (last). The focused window is
    /// always the last entry.
    z_order: Vec<usize>,
    /// Index (into `windows`) of the focused window, or `None` if there are none.
    focused: Option<usize>,
    /// The open-app launcher overlay.
    launcher: Launcher,
    /// Dirty rectangles to repaint on the next composite.
    damage: DamageQueue,
    /// Monotonic id source for [`WindowId`]s.
    next_id: u32,
    /// Cached framebuffer dimensions, so tiling is computed once on entry.
    screen_w: usize,
    screen_h: usize,
    /// Cursor hotspot position in absolute framebuffer pixels, clamped to the
    /// screen. The compositor draws the arrow sprite here **last**, on top of
    /// every window, each composite.
    cursor_x: usize,
    cursor_y: usize,
    /// The button bitmap from the previous mouse packet, so
    /// [`on_mouse`](Self::on_mouse) can edge-detect a left-button *press* (0 → 1)
    /// for click-to-focus rather than re-firing every packet while it is held.
    prev_buttons: u8,
}

impl WindowManager {
    /// Create an empty window manager sized to a `screen_w × screen_h` framebuffer.
    ///
    /// The caller seeds it (e.g. one Terminal window) with [`spawn`](Self::spawn)
    /// and then [`composite`](Self::composite)s once on entering the desktop.
    #[must_use]
    pub fn new(screen_w: usize, screen_h: usize) -> Self {
        Self {
            windows: Vec::new(),
            z_order: Vec::new(),
            focused: None,
            launcher: Launcher::new(),
            damage: DamageQueue::new(),
            next_id: 1,
            screen_w,
            screen_h,
            // Start the cursor at the screen centre so it is visible the moment
            // the desktop appears, regardless of the first mouse delta's sign.
            cursor_x: screen_w / 2,
            cursor_y: screen_h / 2,
            prev_buttons: 0,
        }
    }

    /// The desktop work area: the screen below the top status bar and above the
    /// dock, where windows are tiled. Mirrors `ui`'s status-bar / dock geometry so
    /// tiles never collide with the chrome.
    fn work_area(&self) -> Rect {
        let w = self.screen_w;
        let h = self.screen_h;
        // Top status bar height (see `ui::draw_desktop`: h/16 clamped 24..=56).
        let bar_h = (h / 16).clamp(24, 56);
        // Dock height: tile ≈ h/11 (clamped 28..=96) plus its bottom margin h/14.
        let dock_tile = (h / 11).clamp(28, 96);
        let dock_band = dock_tile + h / 14 + h / 40;
        // Leave a margin around the work area for visual breathing room.
        let margin = (w / 80).max(8);
        let top = bar_h + margin;
        let bottom = h.saturating_sub(dock_band).saturating_sub(margin);
        let left = margin;
        let right = w.saturating_sub(margin);
        Rect::new(
            left,
            top,
            right.saturating_sub(left),
            bottom.saturating_sub(top),
        )
    }

    /// Re-tile every window into non-overlapping slots across the work area and
    /// mark them all for redraw (their bounds changed). With one window it fills
    /// the work area; with N it splits into N side-by-side columns — a layout the
    /// analytic compositor renders pixel-exact (spec §4.4).
    ///
    /// Slots follow the **stable storage order** (`windows` index), not z-order, so
    /// a window keeps its column for its whole life — cycling focus never makes
    /// windows physically swap places (only their focus accent changes). Tiling
    /// runs only on a structural change that actually alters the set of windows
    /// (spawn / close), not on focus changes.
    fn retile(&mut self) {
        let n = self.windows.len();
        if n == 0 {
            return;
        }
        let area = self.work_area();
        if area.w == 0 || area.h == 0 {
            return;
        }
        let gap = (area.w / 60).max(6);
        // Total inter-column gap, then the per-column width.
        let total_gap = gap * (n.saturating_sub(1));
        let col_w = area.w.saturating_sub(total_gap) / n;
        // Tile in stable storage order so each window owns a fixed column.
        for slot in 0..n {
            let x = area.x + slot * (col_w + gap);
            // The last column takes any rounding remainder so tiles meet the edge.
            let this_w = if slot + 1 == n {
                area.right().saturating_sub(x)
            } else {
                col_w
            };
            self.windows[slot].bounds = Rect::new(x, area.y, this_w, area.h);
            self.windows[slot].needs_redraw = true;
            // Bounds changed → the compositor must erase before repainting.
            self.windows[slot].needs_clear = true;
        }
    }

    /// Spawn a new window for `kind`, tile it in, focus + raise it to front, and
    /// damage the whole work area so the new layout repaints. Capped at
    /// [`MAX_WINDOWS`]; over the cap it is a no-op (returns `None`).
    pub fn spawn(&mut self, kind: AppKind) -> Option<WindowId> {
        if self.windows.len() >= MAX_WINDOWS {
            return None;
        }
        let app = app::spawn(kind);
        let id = WindowId(self.next_id);
        self.next_id += 1;
        let title = app.title().to_string();
        let window = Window {
            id,
            // Placeholder bounds; `retile` assigns the real slot immediately.
            bounds: Rect::new(0, 0, 0, 0),
            title,
            app,
            needs_redraw: true,
            needs_clear: true,
        };
        let new_index = self.windows.len();
        self.windows.push(window);
        // New window goes to the front of the z-order and takes focus.
        self.z_order.push(new_index);
        self.focused = Some(new_index);
        self.refresh_focus_flags();
        // Re-tile (bounds change for all) and damage the whole work area.
        self.retile();
        let area = self.work_area();
        self.damage.push(area);
        Some(id)
    }

    /// Close the focused window, drop its app, re-tile the survivors, and damage
    /// the whole work area so the exposed region (and the new layout) repaints.
    /// A no-op when there are no windows.
    pub fn close_focused(&mut self) -> Option<WindowId> {
        let focused = self.focused?;
        let closed_id = self.windows[focused].id;
        let closed_bounds = self.windows[focused].bounds;

        // Remove from storage; shift all higher indices down by one.
        self.windows.remove(focused);
        self.z_order.retain(|&i| i != focused);
        for idx in &mut self.z_order {
            if *idx > focused {
                *idx -= 1;
            }
        }

        // New focus is the new front of the z-order (or none).
        self.focused = self.z_order.last().copied();
        self.refresh_focus_flags();

        // Damage the closed window's old rect (expose) and re-tile the rest.
        self.damage.push(closed_bounds);
        self.retile();
        self.damage.push(self.work_area());
        Some(closed_id)
    }

    /// Cycle focus to the next window (in stable storage order), wrapping round.
    ///
    /// Windows keep their tiled columns — only the focus accent moves — so this
    /// repaints just the previously-focused and newly-focused windows (their
    /// title-bar/border accent flips) and raises the new focus to the front of the
    /// z-order. A no-op with fewer than two windows.
    pub fn cycle_focus(&mut self) {
        let n = self.windows.len();
        if n < 2 {
            return;
        }
        let old = self.focused;
        let next = match self.focused {
            Some(i) => (i + 1) % n,
            None => 0,
        };
        self.focused = Some(next);
        // Raise the newly-focused window to the front of the z-order (it draws
        // last); harmless for tiled, non-overlapping windows but keeps z-order
        // meaningful for a future overlapping mode.
        self.z_order.retain(|&i| i != next);
        self.z_order.push(next);
        // Repaint only the two windows whose focus state changed.
        if let Some(o) = old {
            self.windows[o].needs_redraw = true;
            self.damage.push(self.windows[o].bounds);
        }
        self.windows[next].needs_redraw = true;
        self.damage.push(self.windows[next].bounds);
    }

    /// Re-derive every window's focus flag, marking all windows for redraw. Used
    /// on structural changes (spawn / close) that already damage the work area, so
    /// each window repaints with the correct (possibly changed) focus accent.
    fn refresh_focus_flags(&mut self) {
        for w in &mut self.windows {
            w.needs_redraw = true;
        }
    }

    /// Route one mouse event: move the cursor and, on a left-button *press*,
    /// click-to-focus the topmost window under the pointer.
    ///
    /// `dx`/`dy` are the relative deltas from a PS/2 packet (right is +x; PS/2
    /// reports **up** as +y, so we negate `dy` for screen-down). `buttons` is the
    /// packet's button bitmap (bit 0 = left).
    ///
    /// Behaviour:
    /// 1. **Move.** The cursor hotspot is advanced by `(dx, -dy)` and clamped to
    ///    the screen. Both the old and new cursor rectangles are pushed to the
    ///    damage queue so the compositor repaints the desktop under the cursor's
    ///    former spot and then draws the arrow at its new spot on top.
    /// 2. **Click-to-focus.** On the rising edge of the left button (it was up in
    ///    the previous packet and is down now), hit-test the topmost window whose
    ///    bounds contain the cursor hotspot and focus + raise it. A click on empty
    ///    desktop changes nothing.
    ///
    /// Always returns [`WmAction::Redraw`] when the cursor moved or focus changed
    /// (so the idle loop composites); [`WmAction::None`] only when a zero-delta,
    /// no-edge packet did nothing.
    pub fn on_mouse(&mut self, dx: i16, dy: i16, buttons: u8) -> WmAction {
        let mut changed = false;

        // 1) Move the cursor, clamped to the screen. PS/2 y is up-positive; flip it
        //    so pushing the mouse forward moves the cursor up the screen.
        let old = ui::cursor_rect(self.cursor_x, self.cursor_y);
        let new_x = clamp_add(self.cursor_x, dx, self.screen_w.saturating_sub(1));
        let new_y = clamp_add(self.cursor_y, -dy, self.screen_h.saturating_sub(1));
        if new_x != self.cursor_x || new_y != self.cursor_y {
            let old_rect = rect_from_tuple(old);
            self.cursor_x = new_x;
            self.cursor_y = new_y;
            let new_rect = rect_from_tuple(ui::cursor_rect(self.cursor_x, self.cursor_y));
            // Damage the old position (so the desktop/window under it repaints) and
            // the new position (so the arrow is composited there).
            self.damage.push(old_rect);
            self.damage.push(new_rect);
            // The compositor erases damage to the backdrop only where no window
            // covers it, and otherwise repaints whole windows flagged
            // `needs_redraw`. So any window the cursor's *old* footprint overlapped
            // must be flagged, or the arrow would ghost where it sat over a window.
            for w in &mut self.windows {
                if rects_touch(w.bounds, old_rect) {
                    w.needs_redraw = true;
                }
            }
            changed = true;
        }

        // 2) Click-to-focus on the left-button rising edge.
        let left_now = buttons & MOUSE_BTN_LEFT != 0;
        let left_was = self.prev_buttons & MOUSE_BTN_LEFT != 0;
        self.prev_buttons = buttons;
        if left_now && !left_was && self.focus_window_at(self.cursor_x, self.cursor_y) {
            changed = true;
        }

        if changed {
            WmAction::Redraw
        } else {
            WmAction::None
        }
    }

    /// Hit-test the topmost window whose bounds contain `(px, py)` and, if found
    /// and not already focused, focus + raise it (click-to-focus). Returns `true`
    /// when focus actually changed (so the caller composites).
    ///
    /// "Topmost" means the front of the z-order: we scan `z_order` from front
    /// (last) to back (first) and pick the first window covering the point. The
    /// previously- and newly-focused windows are damaged so their focus accents
    /// repaint.
    fn focus_window_at(&mut self, px: usize, py: usize) -> bool {
        // Find the front-most window under the point.
        let mut hit: Option<usize> = None;
        for &wi in self.z_order.iter().rev() {
            if point_in_rect(px, py, self.windows[wi].bounds) {
                hit = Some(wi);
                break;
            }
        }
        let Some(target) = hit else {
            return false; // clicked empty desktop
        };
        if self.focused == Some(target) {
            return false; // already focused — nothing to do
        }
        let old = self.focused;
        self.focused = Some(target);
        // Raise the clicked window to the front of the z-order (it draws last).
        self.z_order.retain(|&i| i != target);
        self.z_order.push(target);
        // Repaint the two windows whose focus accent changed.
        if let Some(o) = old {
            self.windows[o].needs_redraw = true;
            self.damage.push(self.windows[o].bounds);
        }
        self.windows[target].needs_redraw = true;
        self.damage.push(self.windows[target].bounds);
        true
    }

    /// Route one decoded key event. Global WM hotkeys are handled here; anything
    /// else goes to the launcher (if open) or the focused app. Returns whether a
    /// re-composite is needed.
    pub fn on_key(&mut self, event: KeyEvent) -> WmAction {
        // Escape always toggles the launcher (open ↔ closed).
        if event == KeyEvent::Escape {
            self.toggle_launcher();
            return WmAction::Redraw;
        }

        if self.launcher.open {
            return self.launcher_key(event);
        }

        // Tab cycles focus between windows.
        if event == KeyEvent::Tab {
            self.cycle_focus();
            return WmAction::Redraw;
        }

        // Otherwise route to the focused app.
        if let Some(focused) = self.focused {
            if self.windows[focused].app.on_key(event) {
                self.windows[focused].needs_redraw = true;
                let content =
                    ui::content_rect(self.windows[focused].bounds, &WindowChrome::cyber_dusk());
                self.damage.push(content);
                return WmAction::Redraw;
            }
        }
        WmAction::None
    }

    /// Open or close the launcher overlay, damaging the work area so it draws or
    /// the windows behind it repaint.
    fn toggle_launcher(&mut self) {
        self.launcher.open = !self.launcher.open;
        self.launcher.selected = 0;
        if !self.launcher.open {
            // Closing: the overlay covered the work area — repaint it.
            for w in &mut self.windows {
                w.needs_redraw = true;
            }
            self.damage.push(self.work_area());
        }
    }

    /// Handle a key while the launcher is open: a digit `1..=N` selects + acts,
    /// Up/Down move the highlight, Enter acts on the highlighted item.
    fn launcher_key(&mut self, event: KeyEvent) -> WmAction {
        match event {
            KeyEvent::UpArrowPressed => {
                if self.launcher.selected == 0 {
                    self.launcher.selected = launcher_len() - 1;
                } else {
                    self.launcher.selected -= 1;
                }
                WmAction::Redraw
            }
            KeyEvent::DownArrowPressed => {
                self.launcher.selected = (self.launcher.selected + 1) % launcher_len();
                WmAction::Redraw
            }
            KeyEvent::Char(c) if c.is_ascii_digit() && c != '0' => {
                let idx = (c as usize) - ('1' as usize);
                if idx < launcher_len() {
                    self.launcher.selected = idx;
                    self.activate_launcher_item();
                    WmAction::Redraw
                } else {
                    WmAction::None
                }
            }
            KeyEvent::EnterPressed => {
                self.activate_launcher_item();
                WmAction::Redraw
            }
            _ => WmAction::None,
        }
    }

    /// Act on the highlighted launcher item (spawn or close), then close the
    /// launcher so the freshly-laid-out desktop shows.
    fn activate_launcher_item(&mut self) {
        let item = launcher_item(self.launcher.selected);
        // Close the overlay first so its region is damaged for repaint.
        self.launcher.open = false;
        for w in &mut self.windows {
            w.needs_redraw = true;
        }
        self.damage.push(self.work_area());
        match item {
            LauncherItem::Spawn(kind) => {
                if let Some(id) = self.spawn(kind) {
                    log_spawn(kind, id);
                }
            }
            LauncherItem::CloseFocused => {
                if let Some(id) = self.close_focused() {
                    log_close(id);
                }
            }
        }
    }

    /// Advance every app's periodic tick. Returns whether any app reported a
    /// content change (so the caller composites). Each dirtied app damages just
    /// its own content rect.
    pub fn tick(&mut self, now_ticks: u64) -> WmAction {
        let chrome = WindowChrome::cyber_dusk();
        let mut any = false;
        for w in &mut self.windows {
            if w.app.tick(now_ticks) {
                w.needs_redraw = true;
                self.damage.push(ui::content_rect(w.bounds, &chrome));
                any = true;
            }
        }
        if any {
            WmAction::Redraw
        } else {
            WmAction::None
        }
    }

    /// `true` when nothing is dirty (no damage queued and no window needs redraw),
    /// so the idle loop can skip [`composite`](Self::composite) entirely.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.damage.is_empty() && self.windows.iter().all(|w| !w.needs_redraw)
    }

    /// Composite the dirty windows onto `fb`, repainting only damaged regions.
    ///
    /// For each window whose `needs_redraw` is set, this erases its bounds back to
    /// the backdrop (`ui::clear_rect`), draws the glass chrome
    /// (`ui::draw_window_chrome`, focus-aware), and renders the app into the inner
    /// `ui::content_rect`. Windows are tiled non-overlapping, so each window's
    /// repaint is self-contained. Finally, if the launcher is open, its glass
    /// overlay is drawn on top. The damage queue is coalesced then drained.
    pub fn composite(&mut self, fb: &hal::framebuffer::Framebuffer) {
        let chrome = WindowChrome::cyber_dusk();

        // Coalesce + drain the damage queue. A drained rect that no surviving
        // window covers (e.g. the region a just-closed window vacated) must be
        // erased back to the backdrop here; windows that intersect it then redraw
        // on top. Per-window `needs_redraw`/`needs_clear` drive the window repaints.
        self.damage.coalesce();
        let damaged = self.damage.drain();
        for rect in &damaged {
            // Only the portion of this damage rect not covered by any window needs
            // a backdrop erase. Cheap and correct for the few rects we hold: if no
            // window fully covers it, clear it (windows repaint over it below).
            let covered = self.windows.iter().any(|w| rect_contains(w.bounds, *rect));
            if !covered {
                ui::clear_rect(fb, *rect);
            }
        }

        // Paint windows back-to-front so the focused (front) window draws last.
        for &wi in &self.z_order {
            let win = &mut self.windows[wi];
            if !win.needs_redraw {
                continue;
            }
            let focused = self.focused == Some(wi);
            // 1) Erase to the bare backdrop ONLY when the bounds changed (spawn /
            //    close / re-tile), so a region the window no longer covers shows
            //    the backdrop. A pure content change skips this — the glass repaint
            //    below recomposites the whole body and erases stale content itself.
            if win.needs_clear {
                ui::clear_rect(fb, win.bounds);
                win.needs_clear = false;
            }
            // 2) Repaint the glass chrome (title bar, border, focus accent). This
            //    recomposites the translucent body over the gradient, overwriting
            //    any previous content beneath it.
            ui::draw_window_chrome(fb, win.bounds, &win.title, focused);
            // 3) Draw the app's content into the inner content rect.
            let content = ui::content_rect(win.bounds, &chrome);
            win.app.render(fb, content);
            win.needs_redraw = false;
        }

        // 4) The launcher overlay sits on top of everything when open.
        if self.launcher.open {
            self.draw_launcher(fb);
        }

        // 5) The mouse cursor is drawn LAST, so the arrow always sits on top of
        //    the windows and the launcher. Its previous position was damaged in
        //    `on_mouse`, so the desktop/window under it has already been repainted
        //    above; here we just stamp the arrow at the current hotspot.
        ui::draw_cursor(fb, self.cursor_x, self.cursor_y);
    }

    /// Draw the launcher glass overlay: a centred Cyber Dusk card listing the
    /// spawnable apps + the close action, with the highlighted row accented.
    fn draw_launcher(&self, fb: &hal::framebuffer::Framebuffer) {
        let w = self.screen_w;
        let h = self.screen_h;
        if w == 0 || h == 0 {
            return;
        }
        // A centred card sized to the menu. Reuse the window-chrome drawer as the
        // glass card (focused styling = brightest), with a title bar of its own.
        let card_w = (w * 34 / 100).clamp(220, w.saturating_sub(40));
        let row_h = ui::font::GLYPH_SIZE * 2 + 10;
        let chrome = WindowChrome::cyber_dusk();
        let card_h = (chrome.titlebar_h + chrome.border + row_h * (launcher_len() + 1))
            .min(h.saturating_sub(40));
        let card_x = (w.saturating_sub(card_w)) / 2;
        let card_y = (h.saturating_sub(card_h)) / 2;
        let bounds = Rect::new(card_x, card_y, card_w, card_h);

        ui::draw_window_chrome(fb, bounds, "Launcher", true);

        let content = ui::content_rect(bounds, &chrome);
        let x0 = content.x + 8;
        let mut y = content.y + 4;

        let primary = fb.pack_rgb(0xe8, 0xf6, 0xff);
        let accent = fb.pack_rgb(0x7a, 0xd7, 0xff);
        let dim = fb.pack_rgb(0x9a, 0xb6, 0xd6);

        ui::font::draw_text(fb, x0, y, "pick an app  (digit / Enter)", 2, dim);
        y += row_h + 4;

        // Each menu item, numbered "1 Terminal", with the selection in cyan.
        let mut buf = [0u8; 2];
        for i in 0..launcher_len() {
            let item = launcher_item(i);
            let selected = i == self.launcher.selected;
            let color = if selected { accent } else { primary };
            // Number prefix "N ".
            buf[0] = b'1' + i as u8;
            buf[1] = b' ';
            let prefix = core::str::from_utf8(&buf).unwrap_or("? ");
            ui::font::draw_text(fb, x0, y, prefix, 2, color);
            let label_x = x0 + ui::font::text_width(prefix, 2);
            let label = match item {
                LauncherItem::Spawn(kind) => kind.label(),
                LauncherItem::CloseFocused => "Close focused",
            };
            ui::font::draw_text(fb, label_x, y, label, 2, color);
            y += row_h;
        }
    }

    /// The number of live windows (for tests / introspection).
    #[must_use]
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// The id of the focused window, if any (for tests / logging).
    #[must_use]
    pub fn focused_id(&self) -> Option<WindowId> {
        self.focused.map(|i| self.windows[i].id)
    }

    /// Whether the launcher overlay is open (for tests).
    #[must_use]
    pub fn launcher_open(&self) -> bool {
        self.launcher.open
    }

    /// The cursor hotspot position in absolute framebuffer pixels (for tests /
    /// introspection).
    #[must_use]
    pub fn cursor_pos(&self) -> (usize, usize) {
        (self.cursor_x, self.cursor_y)
    }
}

// --- fmt-free serial logging for structural WM events -------------------------

/// Log a window spawn via the fmt-arg-free serial helper (`core::fmt` integer
/// args fault on this target — see `hal::serial`) **and** append a first-class
/// audit record.
///
/// Spec §9.4 resolution: the audit log *subsumes* `log_spawn`. We keep the
/// `[wm] spawned <label>` serial line (a useful boot trace) and additionally
/// append a `Principal::WindowManager / Action::AppSpawn` record (`target =
/// kind.label()`), making the window manager the first *real* producer feeding the
/// audit log — structural events already logged informally graduate to first-class
/// auditable events.
fn log_spawn(kind: AppKind, _id: WindowId) {
    // fmt-free "[wm] spawned <label>" — data-driven over AppKind::label() so new
    // app variants (Files, Net, …) need no per-variant arm here.
    hal::serial::write_str("[wm] spawned ");
    hal::serial::print_line(kind.label());

    crate::security::audit::append(
        crate::security::audit::Principal::WindowManager,
        crate::security::audit::Action::AppSpawn,
        kind.label(),
        "",
    );
}

/// Log a window close via the fmt-free serial helper **and** append an audit
/// record (spec §9.4 — the audit log subsumes `log_close`).
fn log_close(_id: WindowId) {
    hal::serial::print_line("[wm] closed focused window");

    crate::security::audit::append(
        crate::security::audit::Principal::WindowManager,
        crate::security::audit::Action::AppClose,
        "window",
        "",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh WM has no windows and a closed launcher.
    #[test]
    fn new_wm_is_empty() {
        let wm = WindowManager::new(1024, 768);
        assert_eq!(wm.window_count(), 0);
        assert!(!wm.launcher_open());
        assert!(wm.focused_id().is_none());
    }

    /// Spawning seeds a focused window and tiles it; spawning a second tiles both.
    #[test]
    fn spawn_focuses_and_tiles() {
        let mut wm = WindowManager::new(1024, 768);
        let a = wm.spawn(AppKind::Terminal).unwrap();
        assert_eq!(wm.window_count(), 1);
        assert_eq!(wm.focused_id(), Some(a));
        let b = wm.spawn(AppKind::System).unwrap();
        assert_eq!(wm.window_count(), 2);
        assert_eq!(wm.focused_id(), Some(b));
        // The two tiles must not overlap horizontally.
        let bounds: Vec<Rect> = wm.windows.iter().map(|w| w.bounds).collect();
        assert!(bounds[0].right() <= bounds[1].x || bounds[1].right() <= bounds[0].x);
    }

    /// Tab cycles focus between the two windows.
    #[test]
    fn tab_cycles_focus() {
        let mut wm = WindowManager::new(1024, 768);
        let a = wm.spawn(AppKind::Terminal).unwrap();
        let b = wm.spawn(AppKind::System).unwrap();
        assert_eq!(wm.focused_id(), Some(b));
        wm.cycle_focus();
        assert_eq!(wm.focused_id(), Some(a));
        wm.cycle_focus();
        assert_eq!(wm.focused_id(), Some(b));
    }

    /// Closing the focused window drops it and refocuses a survivor.
    #[test]
    fn close_focused_refocuses() {
        let mut wm = WindowManager::new(1024, 768);
        let a = wm.spawn(AppKind::Terminal).unwrap();
        let _b = wm.spawn(AppKind::System).unwrap();
        wm.close_focused();
        assert_eq!(wm.window_count(), 1);
        assert_eq!(wm.focused_id(), Some(a));
        wm.close_focused();
        assert_eq!(wm.window_count(), 0);
        assert!(wm.focused_id().is_none());
    }

    /// Escape toggles the launcher open then closed.
    #[test]
    fn escape_toggles_launcher() {
        let mut wm = WindowManager::new(1024, 768);
        assert!(!wm.launcher_open());
        assert_eq!(wm.on_key(KeyEvent::Escape), WmAction::Redraw);
        assert!(wm.launcher_open());
        assert_eq!(wm.on_key(KeyEvent::Escape), WmAction::Redraw);
        assert!(!wm.launcher_open());
    }

    /// A digit in the open launcher spawns the matching app and closes the menu.
    #[test]
    fn launcher_digit_spawns_app() {
        let mut wm = WindowManager::new(1024, 768);
        wm.on_key(KeyEvent::Escape); // open launcher
        assert!(wm.launcher_open());
        // "2" → System app.
        wm.on_key(KeyEvent::Char('2'));
        assert!(!wm.launcher_open());
        assert_eq!(wm.window_count(), 1);
        assert_eq!(wm.windows[0].title, "System");
    }

    /// The window cap is enforced so a spawn-spam can't grow without bound.
    #[test]
    fn window_count_is_capped() {
        let mut wm = WindowManager::new(1024, 768);
        for _ in 0..(MAX_WINDOWS + 3) {
            wm.spawn(AppKind::Terminal);
        }
        assert_eq!(wm.window_count(), MAX_WINDOWS);
    }

    /// The damage queue coalesces touching rectangles into their bounding box.
    #[test]
    fn damage_coalesces_touching_rects() {
        let mut q = DamageQueue::new();
        q.push(Rect::new(0, 0, 10, 10));
        q.push(Rect::new(10, 0, 10, 10)); // shares the right edge
        q.coalesce();
        let drained = q.drain();
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0], Rect::new(0, 0, 20, 10));
    }

    /// Disjoint damage rectangles are kept separate.
    #[test]
    fn damage_keeps_disjoint_rects() {
        let mut q = DamageQueue::new();
        q.push(Rect::new(0, 0, 10, 10));
        q.push(Rect::new(100, 100, 10, 10));
        q.coalesce();
        assert_eq!(q.drain().len(), 2);
    }

    /// A fresh WM starts the cursor at the screen centre.
    #[test]
    fn cursor_starts_centred() {
        let wm = WindowManager::new(1024, 768);
        assert_eq!(wm.cursor_pos(), (512, 384));
    }

    /// Mouse motion moves the cursor; PS/2 up-positive y maps to screen-up.
    #[test]
    fn mouse_motion_moves_cursor_and_flips_y() {
        let mut wm = WindowManager::new(1024, 768);
        // dx=+10 right, dy=+10 (PS/2 up) → screen y decreases by 10.
        assert_eq!(wm.on_mouse(10, 10, 0), WmAction::Redraw);
        assert_eq!(wm.cursor_pos(), (522, 374));
    }

    /// The cursor clamps to the screen edges and never wraps.
    #[test]
    fn cursor_clamps_to_screen() {
        let mut wm = WindowManager::new(1024, 768);
        // Slam left and down far past the edges.
        wm.on_mouse(-10_000, 10_000, 0); // far left, far up (PS/2 +y) ...
        assert_eq!(wm.cursor_pos(), (0, 0));
        wm.on_mouse(10_000, -10_000, 0); // ... far right, far down
        assert_eq!(wm.cursor_pos(), (1023, 767));
    }

    /// A zero-delta, no-button packet does nothing (no needless composite).
    #[test]
    fn idle_mouse_packet_is_noop() {
        let mut wm = WindowManager::new(1024, 768);
        assert_eq!(wm.on_mouse(0, 0, 0), WmAction::None);
    }

    /// A left-click over a window focuses + raises it (click-to-focus); only the
    /// rising edge fires (a held button does not re-focus).
    #[test]
    fn left_click_focuses_window_under_cursor() {
        let mut wm = WindowManager::new(1024, 768);
        let a = wm.spawn(AppKind::Terminal).unwrap();
        let b = wm.spawn(AppKind::System).unwrap();
        // Two tiles side by side; `b` is focused (spawned last).
        assert_eq!(wm.focused_id(), Some(b));
        // Move the cursor into window `a`'s tile and left-click.
        let a_bounds = wm.windows[0].bounds; // storage order = spawn order
        let target_x = a_bounds.x + a_bounds.w / 2;
        let target_y = a_bounds.y + a_bounds.h / 2;
        let (cx, cy) = wm.cursor_pos();
        // Drive the cursor there with a single delta, then press left.
        let dx = target_x as i16 - cx as i16;
        // PS/2 y is up-positive, so to move DOWN to target_y we send negative dy.
        let dy = -(target_y as i16 - cy as i16);
        wm.on_mouse(dx, dy, 0); // move, no button
        assert_eq!(wm.on_mouse(0, 0, MOUSE_BTN_LEFT), WmAction::Redraw); // press
        assert_eq!(wm.focused_id(), Some(a));
        // Holding the button (same bitmap) must not re-fire focus logic.
        assert_eq!(wm.on_mouse(0, 0, MOUSE_BTN_LEFT), WmAction::None);
    }

    /// A left-click on empty desktop (no window under the cursor) changes nothing.
    #[test]
    fn left_click_on_empty_desktop_is_noop() {
        let mut wm = WindowManager::new(1024, 768);
        wm.spawn(AppKind::Terminal);
        // Park the cursor at the very top-left (status bar region, above tiles).
        wm.on_mouse(-10_000, 10_000, 0);
        let before = wm.focused_id();
        assert_eq!(wm.on_mouse(0, 0, MOUSE_BTN_LEFT), WmAction::None);
        assert_eq!(wm.focused_id(), before);
    }

    /// `clamp_add` saturates at both ends and never wraps.
    #[test]
    fn clamp_add_saturates() {
        assert_eq!(clamp_add(5, -10, 100), 0);
        assert_eq!(clamp_add(95, 20, 100), 100);
        assert_eq!(clamp_add(50, 7, 100), 57);
    }
}
