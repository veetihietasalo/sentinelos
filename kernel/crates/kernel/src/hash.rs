//! SHA-256 — pure, allocation-free, `no_std`, safe Rust.
//!
//! The component model (`docs/specs/2026-09-18-component-model-design.md` §6)
//! identifies every component by the hash of *what it is*: the host hashes the
//! bytes it is about to run and refuses to instantiate anything whose hash is
//! not the one the requester named. That makes this module load-bearing for the
//! "the kernel knows what it runs" claim, so it is deliberately boring: the
//! FIPS 180-4 algorithm over `u32` words, a fixed 64-byte block buffer, no
//! tables beyond the round constants, and nothing `unsafe`.
//!
//! Verification: NIST test vectors (empty, `"abc"`, the two-block message, a
//! block-boundary message) plus an incremental-vs-one-shot equivalence test on
//! the host; a bounded Kani harness proves the padding arithmetic is total and
//! always lands on a 64-byte multiple (`proofs::padding_is_total_and_aligned`).

/// Digest size in bytes.
pub const DIGEST_LEN: usize = 32;
/// Block size in bytes.
pub const BLOCK_LEN: usize = 64;

/// A 256-bit digest.
pub type Digest = [u8; DIGEST_LEN];

/// FIPS 180-4 §4.2.2 round constants: the first 32 bits of the fractional parts
/// of the cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 §5.3.3 initial hash value: the first 32 bits of the fractional
/// parts of the square roots of the first 8 primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Streaming SHA-256 state. `update` any number of times, then `finalize`.
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// Partial block awaiting more input; `buf[..buf_len]` is live.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Total bytes absorbed. Wraps at 2^64 bytes, which no in-kernel input
    /// approaches; FIPS 180-4 caps message length at 2^64 bits anyway.
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hasher.
    pub const fn new() -> Self {
        Self {
            state: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            total_len: 0,
        }
    }

    /// Absorb `data`. May be called any number of times with any split.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        // Top up a partial block first.
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                compress(&mut self.state, &block);
                self.buf_len = 0;
            }
        }
        // Whole blocks straight from the input.
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        // Stash the tail.
        if !rest.is_empty() {
            self.buf[..rest.len()].copy_from_slice(rest);
            self.buf_len = rest.len();
        }
    }

    /// Pad, absorb the length, and return the digest.
    pub fn finalize(mut self) -> Digest {
        let bit_len = self.total_len.wrapping_mul(8);
        let pad = padding_len(self.buf_len);
        // 0x80, then `pad` zero bytes, then the 64-bit big-endian bit length:
        // at most two more blocks. Feed them through `update`'s block logic by
        // hand so the buffer bookkeeping stays in one place.
        let mut tail = [0u8; 2 * BLOCK_LEN];
        tail[0] = 0x80;
        let len_at = 1 + pad;
        tail[len_at..len_at + 8].copy_from_slice(&bit_len.to_be_bytes());
        let tail_len = len_at + 8;
        // `total_len` must not count the padding; bypass `update`'s counter.
        let mut data: &[u8] = &tail[..tail_len];
        if self.buf_len > 0 {
            let take = (BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            // By construction of `pad`, the buffer is now exactly one block.
            let block = self.buf;
            compress(&mut self.state, &block);
            self.buf_len = 0;
        }
        let (blocks, rest) = data.as_chunks::<BLOCK_LEN>();
        for block in blocks {
            compress(&mut self.state, block);
        }
        debug_assert!(rest.is_empty(), "padding did not land on a block boundary");

        let mut out = [0u8; DIGEST_LEN];
        for (chunk, word) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state.iter()) {
            *chunk = word.to_be_bytes();
        }
        out
    }
}

/// One-shot convenience: `Sha256::new()` + `update(data)` + `finalize()`.
pub fn sha256(data: &[u8]) -> Digest {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// Number of zero bytes between the `0x80` terminator and the 8-byte length so
/// that `buf_len + 1 + pad + 8` is a multiple of [`BLOCK_LEN`]. Pure; the Kani
/// harness proves it total and aligned for every `buf_len < BLOCK_LEN`.
pub(crate) fn padding_len(buf_len: usize) -> usize {
    // Bytes already committed once the terminator is appended.
    let used = (buf_len + 1) % BLOCK_LEN;
    // Room needed for the length field.
    if used <= BLOCK_LEN - 8 {
        BLOCK_LEN - 8 - used
    } else {
        2 * BLOCK_LEN - 8 - used
    }
}

/// FIPS 180-4 §6.2.2: absorb one 64-byte block into `state`.
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u32; 64];
    for (i, chunk) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*chunk);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Parse a 64-character lowercase/uppercase hex string into a digest. Test and
/// manifest helper; `None` on any malformed input.
pub const fn digest_from_hex(hex: &str) -> Option<Digest> {
    let bytes = hex.as_bytes();
    if bytes.len() != 2 * DIGEST_LEN {
        return None;
    }
    let mut out = [0u8; DIGEST_LEN];
    let mut i = 0;
    while i < DIGEST_LEN {
        let hi = match hex_nibble(bytes[2 * i]) {
            Some(v) => v,
            None => return None,
        };
        let lo = match hex_nibble(bytes[2 * i + 1]) {
            Some(v) => v,
            None => return None,
        };
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

const fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{digest_from_hex, padding_len, sha256, Sha256, BLOCK_LEN};
    use alloc::vec;

    fn hex(s: &str) -> [u8; 32] {
        digest_from_hex(s).expect("valid hex")
    }

    #[test]
    fn nist_empty_message() {
        assert_eq!(
            sha256(b""),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
    }

    #[test]
    fn nist_abc() {
        assert_eq!(
            sha256(b"abc"),
            hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn nist_two_block_message() {
        // 56 bytes: the padding + length spill into a second block.
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn exact_block_boundary_message() {
        // 64 bytes of input: the terminator starts a fresh block.
        let msg = [b'a'; BLOCK_LEN];
        assert_eq!(
            sha256(&msg),
            hex("ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb")
        );
    }

    #[test]
    fn incremental_matches_one_shot_for_every_split() {
        let msg: alloc::vec::Vec<u8> = (0..200u32).map(|i| (i * 7 % 251) as u8).collect();
        let expect = sha256(&msg);
        for split in 0..=msg.len() {
            let mut h = Sha256::new();
            h.update(&msg[..split]);
            h.update(&msg[split..]);
            assert_eq!(h.finalize(), expect, "split at {split}");
        }
        // Byte-at-a-time too.
        let mut h = Sha256::new();
        for b in &msg {
            h.update(&[*b]);
        }
        assert_eq!(h.finalize(), expect);
    }

    #[test]
    fn padding_lands_on_a_block_boundary() {
        for buf_len in 0..BLOCK_LEN {
            let pad = padding_len(buf_len);
            assert_eq!((buf_len + 1 + pad + 8) % BLOCK_LEN, 0, "buf_len {buf_len}");
            assert!(pad < BLOCK_LEN);
        }
    }

    #[test]
    fn digest_from_hex_rejects_malformed_input() {
        assert!(digest_from_hex("").is_none());
        assert!(digest_from_hex("zz").is_none());
        let bad = vec![b'g'; 64];
        assert!(digest_from_hex(core::str::from_utf8(&bad).unwrap()).is_none());
    }
}

/// Kani proof harnesses for the pure padding arithmetic. Compiled only under
/// `cargo kani` (`#[cfg(kani)]`), like `sched::proofs`.
#[cfg(kani)]
mod proofs {
    use super::{padding_len, BLOCK_LEN};

    /// For every partial-block length the padding is total (no overflow, no
    /// panic), leaves room for the 8-byte length, and lands the padded message
    /// exactly on a block boundary — the property `finalize` relies on to feed
    /// at most two blocks and never leave a remainder.
    #[kani::proof]
    fn padding_is_total_and_aligned() {
        let buf_len: usize = kani::any();
        kani::assume(buf_len < BLOCK_LEN);
        let pad = padding_len(buf_len);
        assert!(pad < BLOCK_LEN);
        assert!((buf_len + 1 + pad + 8) % BLOCK_LEN == 0);
    }
}
