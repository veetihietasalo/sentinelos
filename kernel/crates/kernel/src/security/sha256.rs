//! A hand-rolled, pure-safe-Rust SHA-256 (FIPS 180-4) — the hash powering the
//! audit log's tamper-evidence chain.
//!
//! # Why hand-rolled
//!
//! The spec ([`docs/specs/2026-06-04-audit-log-and-agent-native-architecture.md`])
//! locks SHA-256 as the chain hash because CRC-32/FNV are integrity-only
//! (trivially forgeable), whereas SHA-256 is pre-image/collision-resistant and so
//! makes a disk rewrite *detectable* relative to a trusted head hash. We roll it
//! by hand rather than pull a crate because:
//!
//! * **Zero new dependencies** — every external crate is attack surface; this is
//!   ~250 lines of pure integer arithmetic with no `unsafe`, no `alloc` in the
//!   compression function, and no `core::fmt` (which faults on this target).
//! * **A tractable verification target** — fixed-size buffers and a bounded round
//!   loop make it a strong future Kani/Miri harness (spec §8.3).
//!
//! This module carries the crate's `#![forbid(unsafe_code)]`. It is `no_std` and
//! allocation-free in the hashing path: [`Sha256::update`] streams bytes through a
//! 64-byte block buffer and [`Sha256::finish`] returns a fixed `[u8; 32]`.
//!
//! # Correctness
//!
//! The unit tests below check the published NIST SHA-256 test vectors (empty
//! string, `"abc"`, the 56-byte two-block message, and a millon-`a` long input),
//! which is acceptance criterion §10.6 of the spec.

/// The SHA-256 digest length in bytes.
pub const DIGEST_LEN: usize = 32;

/// The SHA-256 block size in bytes (512 bits).
const BLOCK_LEN: usize = 64;

/// The first 32 bits of the fractional parts of the cube roots of the first 64
/// primes — the SHA-256 round constants `K` (FIPS 180-4 §4.2.2).
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// The initial hash value `H(0)` — the first 32 bits of the fractional parts of
/// the square roots of the first 8 primes (FIPS 180-4 §5.3.3).
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A streaming SHA-256 hasher.
///
/// Feed bytes with [`update`](Self::update) (any number of calls, any chunk
/// sizes) and finalise with [`finish`](Self::finish), which consumes the hasher
/// and returns the 32-byte digest. The compression function allocates nothing.
#[derive(Clone)]
pub struct Sha256 {
    /// The eight running hash words `H`.
    state: [u32; 8],
    /// Partial-block buffer holding `0..BLOCK_LEN` bytes not yet compressed.
    buffer: [u8; BLOCK_LEN],
    /// Number of valid bytes currently in `buffer`.
    buffered: usize,
    /// Total message length in bytes (for the length-padding suffix). Wraps after
    /// 2^64 bytes, which we never reach; SHA-256 is defined modulo 2^64 bits.
    total_len: u64,
}

impl Sha256 {
    /// Create a fresh hasher initialised to `H(0)`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            total_len: 0,
        }
    }

    /// Absorb `data` into the running hash. May be called any number of times.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);
        let mut input = data;

        // Top up a partially-filled buffer first; compress when it is full.
        if self.buffered > 0 {
            let need = BLOCK_LEN - self.buffered;
            let take = need.min(input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == BLOCK_LEN {
                let block = self.buffer;
                compress(&mut self.state, &block);
                self.buffered = 0;
            }
        }

        // Compress as many full 64-byte blocks straight from the input as we can.
        while input.len() >= BLOCK_LEN {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&input[..BLOCK_LEN]);
            compress(&mut self.state, &block);
            input = &input[BLOCK_LEN..];
        }

        // Stash any trailing partial block for the next call / finalisation.
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffered = input.len();
        }
    }

    /// Finalise the hash: append the FIPS 180-4 padding (a `0x80` byte, zero
    /// padding, then the 64-bit big-endian bit length), compress the final
    /// block(s), and return the 32-byte digest. Consumes the hasher.
    #[must_use]
    pub fn finish(mut self) -> [u8; DIGEST_LEN] {
        // Bit length of the whole message (BEFORE adding any padding bytes).
        let bit_len = self.total_len.wrapping_mul(8);

        // Append the mandatory 0x80 terminator byte.
        self.update(&[0x80]);

        // Pad with zeros until the buffer is 56 bytes (mod 64), leaving room for
        // the 8-byte length suffix. If the buffer is already past 56 we wrap into
        // a fresh block — `update` handles the block boundary for us.
        while self.buffered != BLOCK_LEN - 8 {
            self.update(&[0x00]);
        }

        // Append the 64-bit big-endian message bit length, completing the block.
        self.update(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buffered, 0, "padding must land on a block boundary");

        // Serialise the eight state words big-endian into the digest.
        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// One-shot convenience: SHA-256 of a single contiguous byte slice.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

/// One-shot convenience: SHA-256 of the concatenation `a ‖ b`, without allocating
/// a joined buffer. This is the chain primitive — `sha256(prev_hash ‖ body)`.
#[must_use]
pub fn hash_two(a: &[u8], b: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finish()
}

/// The SHA-256 compression function: mix one 512-bit `block` into `state`.
///
/// Pure integer arithmetic over fixed-size arrays — no allocation, no `unsafe`.
/// All shifts/rotates are within `u32` and all additions are explicitly wrapping,
/// so this never panics (even under `overflow-checks`) and is a clean bounded
/// target for Kani/Miri (spec §8.3).
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    // Build the 64-word message schedule `w`.
    let mut w = [0u32; 64];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    // Initialise the eight working variables from the current state.
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // 64 rounds.
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    // Add the compressed chunk back into the running state.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Render a digest as lowercase hex for comparison against NIST vectors.
    fn hex(digest: &[u8; DIGEST_LEN]) -> alloc::string::String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = alloc::string::String::with_capacity(64);
        for &byte in digest {
            s.push(HEX[(byte >> 4) as usize] as char);
            s.push(HEX[(byte & 0xF) as usize] as char);
        }
        s
    }

    /// NIST vector: the empty message.
    #[test]
    fn nist_empty() {
        assert_eq!(
            hex(&hash(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    /// NIST vector: `"abc"` — the canonical single-block test.
    #[test]
    fn nist_abc() {
        assert_eq!(
            hex(&hash(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// NIST vector: the 56-byte two-block message (exercises the multi-block path
    /// and the padding-into-a-fresh-block edge case).
    #[test]
    fn nist_two_block() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            hex(&hash(msg)),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// NIST vector: one million `'a'` characters (long-message / streaming path).
    #[test]
    fn nist_million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Streaming in awkward chunk sizes must match a one-shot hash of the same
    /// bytes (proves the block-buffering logic).
    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..200u32).map(|i| (i % 256) as u8).collect();
        let one_shot = hash(&data);

        let mut h = Sha256::new();
        for chunk in data.chunks(7) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), one_shot);
    }

    /// `hash_two(a, b)` must equal `hash(a ‖ b)` — the chain primitive's contract.
    #[test]
    fn hash_two_matches_concatenation() {
        let a = b"prev-hash-bytes-here-32-wide!!!!";
        let b = b"the encoded record body bytes";
        let mut joined = Vec::new();
        joined.extend_from_slice(a);
        joined.extend_from_slice(b);
        assert_eq!(hash_two(a, b), hash(&joined));
    }

    /// The digest is always exactly 32 bytes (a structural invariant the future
    /// Kani harness asserts — spec §8.3).
    #[test]
    fn digest_is_32_bytes() {
        assert_eq!(hash(b"anything").len(), DIGEST_LEN);
    }
}
