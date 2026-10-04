//! Bit operations over an on-disk bitmap (spec §7.4).
//!
//! Bit `i` lives in byte `i / 8` at bit position `i % 8` (least significant
//! bit first), so the encoding is endian-independent. A set bit means "in
//! use", a clear bit "free".
//!
//! Every function here is pure and total: indices past the slice report
//! `None` / are clamped, and every loop is bounded by the slice length (at most
//! one 4 KiB block in production) — never by a count read from disk. The Kani
//! harnesses in `proofs` discharge the contracts over a 64-bit bitmap (A19;
//! the run search's first-fit property over 32 bits, for solver time).

/// Number of bits in `bits`, saturating at `u32::MAX` (production slices are
/// 4032 bytes, so this never saturates in practice).
fn nbits(bits: &[u8]) -> u32 {
    u32::try_from(bits.len()).map_or(u32::MAX, |n| n.saturating_mul(8))
}

/// Byte index and mask of bit `i`, if it is inside `bits`. Shifts and masks,
/// not `/` and `%`: the same arithmetic, cheaper for the model checker.
fn locate(bits: &[u8], i: u32) -> Option<(usize, u8)> {
    if i >= nbits(bits) {
        return None;
    }
    Some(((i >> 3) as usize, 1u8 << (i & 7)))
}

/// Whether bit `i` is set, counting a bit past the end as set (never free).
fn is_used(bits: &[u8], i: u32) -> bool {
    bits.get((i >> 3) as usize)
        .is_none_or(|b| b & (1u8 << (i & 7)) != 0)
}

/// Bit `i`, or `None` past the end.
#[must_use]
pub fn get(bits: &[u8], i: u32) -> Option<bool> {
    let (byte, mask) = locate(bits, i)?;
    bits.get(byte).map(|b| b & mask != 0)
}

/// Set bit `i`; returns its previous value, or `None` past the end (nothing
/// changed).
pub fn set(bits: &mut [u8], i: u32) -> Option<bool> {
    let (byte, mask) = locate(bits, i)?;
    let b = bits.get_mut(byte)?;
    let was = *b & mask != 0;
    *b |= mask;
    Some(was)
}

/// Clear bit `i`; returns its previous value, or `None` past the end (nothing
/// changed).
pub fn clear(bits: &mut [u8], i: u32) -> Option<bool> {
    let (byte, mask) = locate(bits, i)?;
    let b = bits.get_mut(byte)?;
    let was = *b & mask != 0;
    *b &= !mask;
    Some(was)
}

/// The first clear bit in `[from, limit)` (with `limit` clamped to the slice),
/// or `None` if every bit in the range is set. First-fit, so the result is a
/// function of the bitmap contents only (deterministic allocation, §7.4).
#[must_use]
pub fn find_zero(bits: &[u8], from: u32, limit: u32) -> Option<u32> {
    let end = limit.min(nbits(bits));
    let mut i = from;
    while i < end {
        let byte = *bits.get((i >> 3) as usize)?;
        // Skip a whole in-use byte when aligned and fully inside the range.
        if i & 7 == 0 && byte == 0xFF && end - i >= 8 {
            i += 8;
            continue;
        }
        if byte & (1u8 << (i & 7)) == 0 {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// The first index `s` in `[from, limit)` such that bits `[s, s + len)` are
/// all clear and inside the range, or `None`. `len == 0` is refused (`None`).
/// One pass, first-fit.
#[must_use]
pub fn find_zero_run(bits: &[u8], len: u32, from: u32, limit: u32) -> Option<u32> {
    find_zero_run_except(bits, len, from, limit, None)
}

/// [`find_zero_run`] with bit `except` (if any) counted as in use: the run
/// first-fit would find once that bit is set, computed without setting it.
/// The allocator uses it to place a run *around* the block its bitmap's
/// copy-on-write is about to take, before it changes anything.
#[must_use]
pub fn find_zero_run_except(
    bits: &[u8],
    len: u32,
    from: u32,
    limit: u32,
    except: Option<u32>,
) -> Option<u32> {
    if len == 0 {
        return None;
    }
    let end = limit.min(nbits(bits));
    let mut run_start = from;
    let mut run_len = 0u32;
    let mut i = from;
    while i < end {
        if is_used(bits, i) || except == Some(i) {
            run_len = 0;
            run_start = i + 1;
        } else {
            run_len += 1;
            if run_len == len {
                return Some(run_start);
            }
        }
        i += 1;
    }
    None
}

/// Number of clear bits in `[0, limit)` (with `limit` clamped to the slice).
#[must_use]
pub fn count_zeros(bits: &[u8], limit: u32) -> u32 {
    let end = limit.min(nbits(bits));
    let full = (end >> 3) as usize;
    let mut zeros: u32 = bits
        .get(..full)
        .map_or(0, |s| s.iter().map(|b| b.count_zeros()).sum());
    let rem = end & 7;
    if rem != 0 {
        if let Some(b) = bits.get(full) {
            let mask = (1u8 << rem) - 1;
            zeros += (!b & mask).count_ones();
        }
    }
    zeros
}

/// Whether every bit in `[from, limit)` (clamped) is set.
#[must_use]
pub fn all_set(bits: &[u8], from: u32, limit: u32) -> bool {
    find_zero(bits, from, limit).is_none()
}

/// Set every bit in `[from, limit)` (clamped).
pub fn set_range(bits: &mut [u8], from: u32, limit: u32) {
    let end = limit.min(nbits(bits));
    let mut i = from;
    while i < end {
        if i & 7 == 0 && end - i >= 8 {
            if let Some(b) = bits.get_mut((i >> 3) as usize) {
                *b = 0xFF;
            }
            i += 8;
            continue;
        }
        let _ = set(bits, i);
        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_clear_round_trip_and_report_previous() {
        let mut b = [0u8; 4];
        assert_eq!(set(&mut b, 9), Some(false));
        assert_eq!(b, [0, 0b10, 0, 0]);
        assert_eq!(get(&b, 9), Some(true));
        assert_eq!(set(&mut b, 9), Some(true));
        assert_eq!(clear(&mut b, 9), Some(true));
        assert_eq!(clear(&mut b, 9), Some(false));
        assert_eq!(get(&b, 32), None);
        assert_eq!(set(&mut b, 32), None);
        assert_eq!(clear(&mut b, u32::MAX), None);
        assert_eq!(b, [0; 4]);
    }

    #[test]
    fn find_zero_is_first_fit_and_skips_full_bytes() {
        let mut b = [0xFFu8, 0xFF, 0b1110_1111, 0];
        assert_eq!(find_zero(&b, 0, 32), Some(20));
        assert_eq!(find_zero(&b, 21, 32), Some(24));
        assert_eq!(find_zero(&b, 0, 20), None);
        b[2] = 0xFF;
        b[3] = 0xFF;
        assert_eq!(find_zero(&b, 0, 32), None);
        assert_eq!(find_zero(&b, 0, 1000), None);
        let z = [0u8; 2];
        assert_eq!(find_zero(&z, 5, 16), Some(5));
        assert_eq!(find_zero(&z, 16, 16), None);
    }

    #[test]
    fn find_zero_run_finds_the_first_long_enough_gap() {
        // bits: 0..4 used, 4..6 free (2), 6 used, 7..12 free (5), rest used.
        let mut b = [0xFFu8; 4];
        for i in [4u32, 5, 7, 8, 9, 10, 11] {
            clear(&mut b, i);
        }
        assert_eq!(find_zero_run(&b, 1, 0, 32), Some(4));
        assert_eq!(find_zero_run(&b, 2, 0, 32), Some(4));
        assert_eq!(find_zero_run(&b, 3, 0, 32), Some(7));
        assert_eq!(find_zero_run(&b, 5, 0, 32), Some(7));
        assert_eq!(find_zero_run(&b, 6, 0, 32), None);
        assert_eq!(
            find_zero_run(&b, 5, 0, 11),
            None,
            "run must end inside limit"
        );
        assert_eq!(find_zero_run(&b, 0, 0, 32), None);
    }

    #[test]
    fn find_zero_run_except_treats_the_excepted_bit_as_used() {
        // bits: 0..4 used, 4..6 free (2), 6 used, 7..12 free (5), rest used.
        let mut b = [0xFFu8; 4];
        for i in [4u32, 5, 7, 8, 9, 10, 11] {
            clear(&mut b, i);
        }
        assert_eq!(find_zero_run_except(&b, 2, 0, 32, None), Some(4));
        // Taking bit 4 (where a copy-on-write would land) splits the first gap.
        assert_eq!(find_zero_run_except(&b, 2, 0, 32, Some(4)), Some(7));
        assert_eq!(find_zero_run_except(&b, 1, 0, 32, Some(4)), Some(5));
        assert_eq!(find_zero_run_except(&b, 5, 0, 32, Some(9)), None);
        assert_eq!(find_zero_run_except(&b, 2, 0, 32, Some(20)), Some(4));
        // Identical to setting the bit first.
        for except in 0..34u32 {
            for len in 1..7u32 {
                let mut set_first = b;
                let _ = set(&mut set_first, except);
                assert_eq!(
                    find_zero_run_except(&b, len, 0, 32, Some(except)),
                    find_zero_run(&set_first, len, 0, 32),
                    "len {len} except {except}"
                );
            }
        }
    }

    #[test]
    fn count_zeros_and_ranges() {
        let mut b = [0u8; 3];
        assert_eq!(count_zeros(&b, 24), 24);
        assert_eq!(count_zeros(&b, 5), 5);
        assert_eq!(count_zeros(&b, 1000), 24);
        set_range(&mut b, 3, 21);
        assert_eq!(count_zeros(&b, 24), 6);
        assert!(all_set(&b, 3, 21));
        assert!(!all_set(&b, 2, 21));
        assert_eq!(get(&b, 2), Some(false));
        assert_eq!(get(&b, 21), Some(false));
        set_range(&mut b, 0, 24);
        assert_eq!(b, [0xFF; 3]);
        assert_eq!(count_zeros(&b, 24), 0);
    }
}

/// Kani proof harnesses over a 64-bit bitmap (A19) — first-fit over 32 bits,
/// see `bitmap_find_zero_run_is_first_fit_32`. Compiled only under
/// `cargo kani`.
#[cfg(kani)]
mod proofs {
    use super::*;

    const BYTES: usize = 8;
    const BITS: u32 = 64;

    /// `set`/`clear`/`get` are coherent: the touched bit takes the new value,
    /// the previous value is reported truthfully, and no other bit moves.
    #[kani::proof]
    #[kani::unwind(9)]
    fn bitmap_set_clear_get_are_coherent_64() {
        let orig: [u8; BYTES] = kani::any();
        let i: u32 = kani::any();
        let j: u32 = kani::any();
        kani::assume(j < BITS && j != i);
        let mut b = orig;
        let was = get(&orig, i);
        match set(&mut b, i) {
            None => {
                assert!(i >= BITS);
                assert!(b == orig);
            }
            Some(prev) => {
                assert!(Some(prev) == was);
                assert!(get(&b, i) == Some(true));
                assert!(get(&b, j) == get(&orig, j));
                assert!(clear(&mut b, i) == Some(true));
                assert!(get(&b, i) == Some(false));
                assert!(get(&b, j) == get(&orig, j));
            }
        }
    }

    /// `find_zero` is first-fit: a result is clear, inside `[from, limit)`, and
    /// every bit before it in the range is set; `None` means the whole range is
    /// set.
    #[kani::proof]
    #[kani::unwind(66)]
    fn bitmap_find_zero_is_first_fit_64() {
        let b: [u8; BYTES] = kani::any();
        let from: u32 = kani::any();
        let limit: u32 = kani::any();
        kani::assume(from <= BITS + 1 && limit <= BITS + 1);
        let k: u32 = kani::any();
        match find_zero(&b, from, limit) {
            Some(r) => {
                assert!(r >= from && r < limit && r < BITS);
                assert!(get(&b, r) == Some(false));
                if k >= from && k < r {
                    assert!(get(&b, k) == Some(true));
                }
            }
            None => {
                if k >= from && k < limit && k < BITS {
                    assert!(get(&b, k) == Some(true));
                }
            }
        }
    }

    /// Whether a run of `len` clear bits, none of them `except`, starts at `k`
    /// and ends inside `limit` — the specification `find_zero_run_except` is
    /// checked against, written as directly as possible.
    fn run_fits(b: &[u8], k: u32, len: u32, limit: u32, except: Option<u32>) -> bool {
        let mut j = 0;
        while j < len {
            let at = k + j;
            if at >= limit || except == Some(at) || get(b, at) != Some(false) {
                return false;
            }
            j += 1;
        }
        true
    }

    /// An arbitrary `except`: none, or any bit (inside the bitmap or not).
    fn any_except() -> Option<u32> {
        if kani::any() {
            Some(kani::any())
        } else {
            None
        }
    }

    /// `find_zero_run_except` (and so `find_zero_run`, its `except = None`
    /// case) is sound over a 64-bit bitmap: a result `s` starts a run of `len`
    /// clear bits, none of them `except`, inside `[from, limit)` (every bit
    /// `k` of the run, `k` arbitrary).
    #[kani::proof]
    #[kani::unwind(66)]
    fn bitmap_find_zero_run_is_sound_64() {
        let b: [u8; BYTES] = kani::any();
        let len: u32 = kani::any();
        let from: u32 = kani::any();
        let limit: u32 = kani::any();
        kani::assume(len <= 4 && from <= BITS && limit <= BITS);
        let except = any_except();
        let k: u32 = kani::any();
        if let Some(s) = find_zero_run_except(&b, len, from, limit, except) {
            assert!(len >= 1);
            assert!(s >= from);
            assert!(s + len <= limit);
            if k >= s && k < s + len {
                assert!(get(&b, k) == Some(false));
                assert!(except != Some(k));
            }
        }
    }

    /// ... and first-fit: **no** run starts at any `k` in `[from, s)`, and
    /// `None` means no run starts anywhere in `[from, limit)` — the property
    /// deterministic allocation rests on (§7.4).
    ///
    /// Over a 32-bit bitmap: this property relates every earlier window to
    /// the scan's state, and CBMC's cost grows steeply with the width (at 64
    /// bits it took ~330 s against the 60 s cap). The scan has no
    /// width-dependent path besides its bound, and 32 bits still cross three
    /// byte boundaries, so every path is exercised; soundness is proven at 64
    /// bits above.
    #[kani::proof]
    #[kani::unwind(34)]
    fn bitmap_find_zero_run_is_first_fit_32() {
        const BITS32: u32 = 32;
        let b: [u8; 4] = kani::any();
        let len: u32 = kani::any();
        let from: u32 = kani::any();
        let limit: u32 = kani::any();
        kani::assume(len <= 4 && from <= BITS32 && limit <= BITS32);
        let except = any_except();
        let k: u32 = kani::any();
        kani::assume(k < BITS32);
        match find_zero_run_except(&b, len, from, limit, except) {
            Some(s) => {
                if k >= from && k < s {
                    assert!(!run_fits(&b, k, len, limit, except));
                }
            }
            None => {
                if len >= 1 && k >= from {
                    assert!(!run_fits(&b, k, len, limit, except));
                }
            }
        }
    }

    /// `count_zeros` moves by exactly one when a clear bit inside the counted
    /// range is set (and not at all when it was already set).
    #[kani::proof]
    #[kani::unwind(10)]
    fn bitmap_count_zeros_tracks_set_64() {
        let orig: [u8; BYTES] = kani::any();
        let i: u32 = kani::any();
        kani::assume(i < BITS);
        let before = count_zeros(&orig, BITS);
        assert!(before <= BITS);
        let mut b = orig;
        let was = set(&mut b, i);
        let after = count_zeros(&b, BITS);
        if was == Some(false) {
            assert!(after + 1 == before);
        } else {
            assert!(after == before);
        }
    }
}
