//! Linear framebuffer surface — the first pixels SentinelOS can draw.
//!
//! This module is part of the TCB. It owns the [`limine`] **framebuffer request**
//! (so the bootloader hands us a linear framebuffer) and exposes the resulting
//! mapping as a safe [`Framebuffer`] surface. The only `unsafe` here is:
//!
//! 1. reading the Limine response (a raw pointer the bootloader filled in), and
//! 2. **volatile** writes to the framebuffer's MMIO pixel store.
//!
//! Both are confined to [`get`] / the private pixel helpers, each block carrying
//! a `// SAFETY:` justification; see `kernel/docs/hal-tcb.md` (§2d) for the
//! registry. All drawing primitives the `kernel` / `ui` crates use are **safe**
//! and **bounds-checked**: an out-of-range coordinate is a no-op, never UB.
//!
//! # Pixel format
//!
//! Limine reports the framebuffer's actual channel layout as per-channel mask
//! *shift* and *size* (in bits). We do **not** assume `0x00RRGGBB`: [`pack_rgb`]
//! consults the live masks so a packed `u32` is correct for whatever layout the
//! firmware chose. Writes honour the reported bytes-per-pixel ([`bpp`] / 8).
//!
//! [`bpp`]: Framebuffer::bpp

use core::ptr;

use limine::request::FramebufferRequest;

/// Limine framebuffer request.
///
/// Limine scans the loaded image for this tagged structure (matched by its magic
/// `id`) and, on success, fills in a response describing one or more linear
/// framebuffers. `#[used]` keeps the linker from stripping it; the matching
/// `BaseRevision` marker that gates the whole protocol lives in the `boot` crate
/// (Limine scans the binary for *all* such markers, so this request being in
/// `hal` is fine).
#[used]
static FRAMEBUFFER_REQUEST: FramebufferRequest = FramebufferRequest::new();

/// A single colour channel's position within a packed pixel: how many bits it
/// occupies and how far it is shifted left from bit 0.
#[derive(Clone, Copy, Debug)]
struct Channel {
    /// Bit offset of the channel's least-significant bit within the pixel.
    shift: u8,
    /// Width of the channel in bits.
    size: u8,
}

impl Channel {
    /// Pack an 8-bit intensity into this channel's bits.
    ///
    /// The input is treated as an 8-bit value and scaled down to the channel's
    /// actual width (e.g. a 5-bit channel keeps the top 5 bits), then shifted
    /// into position. A zero-size channel contributes nothing.
    #[inline]
    const fn pack(self, value: u8) -> u32 {
        if self.size == 0 {
            return 0;
        }
        // Take the top `size` bits of the 8-bit input so full intensity (0xFF)
        // maps to the channel's all-ones value regardless of channel width.
        let scaled = (value as u32) >> (8 - self.size as u32);
        scaled << self.shift
    }
}

/// A safe handle to a linear (RGB) framebuffer provided by the bootloader.
///
/// Construct one with [`Framebuffer::get`]. The handle owns only plain scalars
/// copied out of the Limine response (base pointer, geometry, and channel
/// masks) — it carries no borrow of the response, so it is freely movable and
/// `'static`-friendly for the `ui` crate to build a raster library on top.
///
/// All drawing methods are safe and bounds-checked. The framebuffer memory is
/// treated as MMIO and written **volatile**, so writes are never elided or
/// reordered away by the optimiser.
#[derive(Clone, Copy, Debug)]
pub struct Framebuffer {
    /// Base address of the visible framebuffer (row 0, column 0).
    base: *mut u8,
    /// Visible width in pixels.
    width: usize,
    /// Visible height in pixels.
    height: usize,
    /// Distance between the start of consecutive rows, in **bytes**. May exceed
    /// `width * bytes_per_pixel` due to padding the firmware adds for alignment.
    pitch: usize,
    /// Bytes occupied by one pixel (e.g. 4 for a 32-bpp framebuffer).
    bytes_per_pixel: usize,
    /// Red channel mask (shift + size, in bits).
    red: Channel,
    /// Green channel mask (shift + size, in bits).
    green: Channel,
    /// Blue channel mask (shift + size, in bits).
    blue: Channel,
}

impl Framebuffer {
    /// Acquire the framebuffer from the Limine response.
    ///
    /// Returns `None` if the bootloader provided no response (e.g. the request
    /// was not honoured), if it reported zero framebuffers, or if the first
    /// framebuffer's base pointer is null. On success the first framebuffer's
    /// geometry and channel masks are copied into the returned handle.
    ///
    /// This is the **only** place the Limine response is dereferenced.
    #[must_use]
    pub fn get() -> Option<Self> {
        // SAFETY: `get_response()` returns `Some(&FramebufferResponse)` only when
        // Limine populated the response slot of our `#[used]` request with a
        // valid, fully-initialised response (it sets the pointer atomically
        // before jumping to `_start`). We never mutate the request, so the
        // shared reference handed back is sound. Walking `framebuffers()` /
        // reading the geometry accessors below only dereferences pointers the
        // bootloader filled in and keeps the borrow inside this expression — we
        // copy out plain scalars and drop the borrow before returning.
        let response = FRAMEBUFFER_REQUEST.get_response()?;
        let fb = response.framebuffers().next()?;

        let base = fb.addr();
        if base.is_null() {
            return None;
        }

        Some(Self {
            base,
            width: fb.width() as usize,
            height: fb.height() as usize,
            pitch: fb.pitch() as usize,
            // Round bits-per-pixel up to whole bytes; a linear RGB framebuffer
            // is always byte-aligned per pixel in practice (commonly 32 bpp).
            bytes_per_pixel: (fb.bpp() as usize).div_ceil(8),
            red: Channel {
                shift: fb.red_mask_shift(),
                size: fb.red_mask_size(),
            },
            green: Channel {
                shift: fb.green_mask_shift(),
                size: fb.green_mask_size(),
            },
            blue: Channel {
                shift: fb.blue_mask_shift(),
                size: fb.blue_mask_size(),
            },
        })
    }

    /// Visible width of the framebuffer, in pixels.
    #[inline]
    #[must_use]
    pub const fn width(&self) -> usize {
        self.width
    }

    /// Visible height of the framebuffer, in pixels.
    #[inline]
    #[must_use]
    pub const fn height(&self) -> usize {
        self.height
    }

    /// Distance between consecutive rows, in **bytes** (the *pitch* / *stride*).
    ///
    /// This may be larger than `width() * (bpp()/8)` because the firmware can pad
    /// each row for alignment; always index rows by `pitch`, never by `width`.
    #[inline]
    #[must_use]
    pub const fn pitch(&self) -> usize {
        self.pitch
    }

    /// Bytes occupied by a single pixel (e.g. `4` for a 32-bpp framebuffer).
    #[inline]
    #[must_use]
    pub const fn bytes_per_pixel(&self) -> usize {
        self.bytes_per_pixel
    }

    /// Bits per pixel as reported by the firmware (`bytes_per_pixel * 8`).
    #[inline]
    #[must_use]
    pub const fn bpp(&self) -> usize {
        self.bytes_per_pixel * 8
    }

    /// `(shift, size)` in bits of the red channel within a packed pixel.
    #[inline]
    #[must_use]
    pub const fn red_mask(&self) -> (u8, u8) {
        (self.red.shift, self.red.size)
    }

    /// `(shift, size)` in bits of the green channel within a packed pixel.
    #[inline]
    #[must_use]
    pub const fn green_mask(&self) -> (u8, u8) {
        (self.green.shift, self.green.size)
    }

    /// `(shift, size)` in bits of the blue channel within a packed pixel.
    #[inline]
    #[must_use]
    pub const fn blue_mask(&self) -> (u8, u8) {
        (self.blue.shift, self.blue.size)
    }

    /// Pack an 8-bit-per-channel RGB colour into a native framebuffer pixel.
    ///
    /// The result respects the framebuffer's **actual** channel masks (shift and
    /// size), so it is correct whether the firmware chose `0x00RRGGBB`,
    /// `0x00BBGGRR`, a 16-bit `5-6-5` layout, or anything else Limine reports.
    /// Pass this value to [`put_pixel`](Self::put_pixel) /
    /// [`fill_rect`](Self::fill_rect).
    #[inline]
    #[must_use]
    pub const fn pack_rgb(&self, r: u8, g: u8, b: u8) -> u32 {
        self.red.pack(r) | self.green.pack(g) | self.blue.pack(b)
    }

    /// Byte offset of pixel `(x, y)` from the framebuffer base, or `None` if the
    /// coordinate lies outside the visible surface.
    #[inline]
    const fn byte_offset(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        // y < height and x < width, both bounded by the firmware-reported
        // geometry, so this offset is within `height * pitch` bytes — i.e. inside
        // the mapping Limine handed us. (`pitch >= width * bytes_per_pixel`.)
        Some(y * self.pitch + x * self.bytes_per_pixel)
    }

    /// Write a single packed pixel at `(x, y)`.
    ///
    /// `color` is a value produced by [`pack_rgb`](Self::pack_rgb). The write is
    /// **bounds-checked**: a coordinate outside `width() × height()` is a no-op.
    /// Only the framebuffer's `bytes_per_pixel` low bytes of `color` are stored.
    #[inline]
    pub fn put_pixel(&self, x: usize, y: usize, color: u32) {
        if let Some(offset) = self.byte_offset(x, y) {
            // SAFETY: `byte_offset` returned `Some` only because `x < width` and
            // `y < height`, so `offset .. offset + bytes_per_pixel` lies within
            // the `height * pitch`-byte framebuffer region the bootloader mapped
            // for us (`pitch >= width * bytes_per_pixel`). `base` is the non-null
            // base of that region (checked in `get`). We are single-core on the
            // boot path and nothing else writes the framebuffer, so the pointer
            // is unaliased for this write.
            unsafe { self.write_pixel_at(offset, color) };
        }
    }

    /// Fill an axis-aligned rectangle with a single packed colour.
    ///
    /// The rectangle is **clipped** to the visible surface, so any portion (or
    /// all) of it lying off-screen is silently dropped — never UB. A zero-area
    /// rectangle does nothing. `color` comes from [`pack_rgb`](Self::pack_rgb).
    pub fn fill_rect(&self, x: usize, y: usize, w: usize, h: usize, color: u32) {
        // Clip to the visible region; saturating math keeps the bounds sane even
        // for absurd inputs.
        let x_end = x.saturating_add(w).min(self.width);
        let y_end = y.saturating_add(h).min(self.height);
        if x >= x_end || y >= y_end {
            return;
        }
        for row in y..y_end {
            // `row < height` and `x < width`, so this offset is valid and the run
            // of `(x_end - x)` pixels stays within the row.
            let mut offset = row * self.pitch + x * self.bytes_per_pixel;
            for _ in x..x_end {
                // SAFETY: `offset` starts at pixel `(x, row)` with `x < x_end <=
                // width` and `row < y_end <= height`, and is advanced by exactly
                // `bytes_per_pixel` per pixel for fewer than `(x_end - x)` steps,
                // so every write stays within row `row` and thus within the
                // mapped `height * pitch` framebuffer region. `base` is non-null
                // (checked in `get`) and unaliased on the single-core boot path.
                unsafe { self.write_pixel_at(offset, color) };
                offset += self.bytes_per_pixel;
            }
        }
    }

    /// Volatile-write the low `bytes_per_pixel` bytes of `color` at `offset`.
    ///
    /// # Safety
    ///
    /// `offset` must address a complete pixel inside the mapped framebuffer:
    /// `offset + bytes_per_pixel <= height * pitch`. The caller must also ensure
    /// the framebuffer is not concurrently accessed (single-core boot path).
    #[inline]
    unsafe fn write_pixel_at(&self, offset: usize, color: u32) {
        // SAFETY: the caller guarantees `offset + bytes_per_pixel` is within the
        // framebuffer mapping, so `base.add(offset)` is in bounds and stays in
        // bounds for each of the `bytes_per_pixel` (<= 4) byte writes below. Each
        // `write_volatile` of a `u8` is naturally aligned (alignment 1) and the
        // framebuffer bytes are valid for writes (the bootloader mapped them
        // writable). Volatile guarantees the MMIO stores are actually performed
        // and not coalesced/elided. We deliberately write byte-by-byte so a 24-
        // or 16-bpp framebuffer is handled correctly without an over-wide store.
        unsafe {
            let pixel = self.base.add(offset);
            let bytes = color.to_le_bytes();
            let mut i = 0;
            while i < self.bytes_per_pixel {
                ptr::write_volatile(pixel.add(i), bytes[i]);
                i += 1;
            }
        }
    }
}

/// Acquire the boot framebuffer, or `None` if the bootloader provided none.
///
/// Module-level convenience wrapper over [`Framebuffer::get`] so callers can
/// write `hal::framebuffer::get()`.
#[must_use]
pub fn get() -> Option<Framebuffer> {
    Framebuffer::get()
}

// The framebuffer base is a raw MMIO pointer the bootloader handed us; it is
// valid for the life of the kernel and the handle stores only plain scalars
// beyond it. Sending/sharing the handle across cores is sound for the read-only
// geometry; concurrent *writes* are the caller's responsibility (documented on
// the drawing methods, single-core at bring-up).
//
// SAFETY: `Framebuffer` is `Copy` and contains a raw pointer to a region that
// lives for the whole program; moving or sharing the handle does not invalidate
// the pointer, and no interior mutability is exposed.
unsafe impl Send for Framebuffer {}
// SAFETY: see the `Send` justification above; the geometry/mask fields are
// immutable and the pixel store is MMIO whose write coordination is documented
// on the drawing methods.
unsafe impl Sync for Framebuffer {}
