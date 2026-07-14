//! CPU identification via the `cpuid` instruction — part of the TCB.
//!
//! `cpuid` is the architectural way to ask the processor what it is and what it
//! can do: a *leaf* number in `eax` (and a *sub-leaf* in `ecx` for some leaves)
//! selects which register window the instruction returns in `eax`/`ebx`/`ecx`/
//! `edx`. This module wraps the one privileged-but-unprivileged instruction in a
//! **safe** API that returns structured data the `kernel` crate formats for the
//! `cpuinfo` shell command; the kernel never writes `unsafe`.
//!
//! The only `unsafe` here is the single inline-`cpuid` primitive [`raw`], whose
//! `# Safety` section is documented below and registered in
//! `kernel/docs/hal-tcb.md` (§7). Every public function builds on it with plain,
//! safe bit arithmetic.
//!
//! # Leaves used
//!
//! - **Leaf 0** — the maximum *standard* leaf the CPU supports (in `eax`) and the
//!   12-byte vendor string (in `ebx`, `edx`, `ecx`, in that order).
//! - **Leaf 1** — the family/model/stepping word (`eax`) and the bulk of the
//!   feature flags (`ecx` + `edx`).
//! - **Leaf 7, sub-leaf 0** — the extended feature flags (`ebx`/`ecx`), source of
//!   AVX2, BMI, SHA, etc.
//! - **Leaves `0x8000_0000`..** — the maximum *extended* leaf (`eax`); when it is
//!   at least `0x8000_0004` the 48-byte processor **brand string** is available in
//!   leaves `0x8000_0002..=0x8000_0004` (16 bytes each).
//!
//! Every value is read directly off the live CPU, so the report answers "does the
//! kernel know the machine's specs" from the hardware itself, not a guess.

use core::arch::asm;

/// The four 32-bit registers a `cpuid` invocation returns.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuidResult {
    /// Contents of `eax` after the instruction.
    pub eax: u32,
    /// Contents of `ebx` after the instruction.
    pub ebx: u32,
    /// Contents of `ecx` after the instruction.
    pub ecx: u32,
    /// Contents of `edx` after the instruction.
    pub edx: u32,
}

/// Execute `cpuid` for the given `leaf` (`eax`) and `sub_leaf` (`ecx`).
///
/// This is the single privileged primitive of the module. It is **safe** to call:
/// `cpuid` has no operands beyond `eax`/`ecx`, writes only `eax`/`ebx`/`ecx`/`edx`,
/// touches no memory, and is available at every privilege level (the kernel always
/// runs ring 0 here regardless). Callers should first check that `leaf` is within
/// the supported range via [`max_standard_leaf`] / [`max_extended_leaf`]; an
/// unsupported leaf returns implementation-defined values (often all-zero or the
/// highest supported leaf's data), never UB.
#[must_use]
pub fn raw(leaf: u32, sub_leaf: u32) -> CpuidResult {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    // SAFETY: `cpuid` is a serialising instruction that takes its leaf in `eax`
    // and sub-leaf in `ecx` and overwrites `eax`/`ebx`/`ecx`/`edx` with the
    // selected information word. It accesses no memory (`nomem`), uses no stack
    // (`nostack`), and does not affect RFLAGS (`preserves_flags`). It is legal at
    // CPL 3 and above, so the kernel (CPL 0) may always issue it. We must hand
    // `ebx` to the assembler via a scratch general-purpose register and swap it
    // around the instruction because LLVM reserves `rbx` as its frame/base
    // register and forbids naming it directly in `inout`/`out`. Reading CPU
    // identification cannot create undefined behaviour or alter memory
    // validity/aliasing — it only observes the processor's own description.
    unsafe {
        asm!(
            "mov {ebx_tmp:r}, rbx",   // preserve LLVM's reserved rbx
            "cpuid",
            "xchg {ebx_tmp:r}, rbx",  // recover cpuid's ebx, restore rbx
            ebx_tmp = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") sub_leaf => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    CpuidResult { eax, ebx, ecx, edx }
}

/// The highest *standard* `cpuid` leaf the processor supports (leaf 0 → `eax`).
#[must_use]
pub fn max_standard_leaf() -> u32 {
    raw(0, 0).eax
}

/// The highest *extended* `cpuid` leaf the processor supports
/// (leaf `0x8000_0000` → `eax`). Values below `0x8000_0000` mean no extended
/// leaves are available.
#[must_use]
pub fn max_extended_leaf() -> u32 {
    raw(0x8000_0000, 0).eax
}

/// A fixed-capacity ASCII text buffer used for the vendor (12 bytes) and brand
/// (48 bytes) strings, so the report needs no heap and stays `no_std`-clean.
///
/// CPUID writes plain ASCII bytes into the register window; we collect them here,
/// trimming trailing NUL/space padding, and expose the populated prefix as a
/// `&str` via [`as_str`](CpuidString::as_str).
#[derive(Clone, Copy, Debug)]
pub struct CpuidString {
    bytes: [u8; 48],
    len: usize,
}

impl CpuidString {
    /// An empty string.
    const fn new() -> Self {
        Self {
            bytes: [0; 48],
            len: 0,
        }
    }

    /// Append the four little-endian bytes of `word` (a CPUID register).
    fn push_word(&mut self, word: u32) {
        let chunk = word.to_le_bytes();
        let mut i = 0;
        while i < 4 && self.len < self.bytes.len() {
            self.bytes[self.len] = chunk[i];
            self.len += 1;
            i += 1;
        }
    }

    /// The populated prefix as a `&str`, with trailing NUL/space padding trimmed.
    ///
    /// Non-ASCII bytes (which a conforming CPU never emits in these strings) are
    /// excluded by truncating at the first one, so the result is always valid
    /// UTF-8 and safe to render.
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Find the first NUL or non-ASCII byte; everything before it is the name.
        let mut end = 0;
        while end < self.len {
            let b = self.bytes[end];
            if b == 0 || !b.is_ascii() {
                break;
            }
            end += 1;
        }
        // Trim trailing spaces (Intel pads the brand string with leading spaces;
        // those leading ones are meaningful alignment we leave to the formatter).
        let mut trimmed = end;
        while trimmed > 0 && self.bytes[trimmed - 1] == b' ' {
            trimmed -= 1;
        }
        // `bytes[..trimmed]` is all printable ASCII ⇒ valid UTF-8.
        core::str::from_utf8(&self.bytes[..trimmed]).unwrap_or("")
    }
}

/// Decoded `cpuid` leaf-1 `eax` family/model/stepping fields.
///
/// The "display" family/model apply the extended-field combining rules from the
/// Intel/AMD manuals: when the base family is `0x0F`, the extended family is
/// *added*; the extended model is *prepended* (shifted into the high nibble) when
/// the base family is `0x06` or `0x0F`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FamilyModelStepping {
    /// Effective ("display") family after combining the extended-family field.
    pub family: u32,
    /// Effective ("display") model after combining the extended-model field.
    pub model: u32,
    /// Stepping id (leaf-1 `eax` bits 3:0).
    pub stepping: u32,
}

impl FamilyModelStepping {
    /// Decode the family/model/stepping from a leaf-1 `eax` value.
    #[must_use]
    pub const fn from_eax(eax: u32) -> Self {
        let base_family = (eax >> 8) & 0xF;
        let base_model = (eax >> 4) & 0xF;
        let stepping = eax & 0xF;
        let ext_family = (eax >> 20) & 0xFF;
        let ext_model = (eax >> 16) & 0xF;

        let family = if base_family == 0xF {
            base_family + ext_family
        } else {
            base_family
        };
        let model = if base_family == 0x6 || base_family == 0xF {
            (ext_model << 4) | base_model
        } else {
            base_model
        };
        Self {
            family,
            model,
            stepping,
        }
    }
}

/// One CPU feature flag: its human name and whether the live CPU reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Feature {
    /// Short human-readable name (e.g. `"sse2"`, `"avx2"`).
    pub name: &'static str,
    /// Whether the processor advertises support for it.
    pub present: bool,
}

/// The x86 CPU vendor, decoded from the leaf-0 vendor-id string.
///
/// Kept as a typed enum (rather than string compares scattered through the
/// kernel) so vendor-specific paths — AMD SME/SEV vs Intel TME/TDX memory
/// encryption, `AuthenticAMD` vs `GenuineIntel` errata, APIC quirks — branch on
/// one authoritative value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vendor {
    /// `GenuineIntel`.
    Intel,
    /// `AuthenticAMD` (also the historical `AMDisbetter!` engineering-sample id).
    Amd,
    /// Any other or unrecognised vendor (hypervisor stubs, VIA/Zhaoxin, …).
    Other,
}

impl Vendor {
    /// Classify a 12-byte CPUID leaf-0 vendor-id string.
    #[must_use]
    pub fn from_id(id: &str) -> Self {
        match id {
            "GenuineIntel" => Vendor::Intel,
            "AuthenticAMD" | "AMDisbetter!" => Vendor::Amd,
            _ => Vendor::Other,
        }
    }

    /// A short human label for the `cpuinfo` report (`"Intel"`, `"AMD"`, `"other"`).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Vendor::Intel => "Intel",
            Vendor::Amd => "AMD",
            Vendor::Other => "other",
        }
    }
}

/// Selected leaf-1 `edx` feature bits (the classic baseline ISA features).
struct Leaf1Edx;
impl Leaf1Edx {
    const FPU: u32 = 1 << 0;
    const TSC: u32 = 1 << 4;
    const MSR: u32 = 1 << 5;
    const PAE: u32 = 1 << 6;
    const APIC: u32 = 1 << 9;
    const MMX: u32 = 1 << 23;
    const SSE: u32 = 1 << 25;
    const SSE2: u32 = 1 << 26;
}

/// Selected leaf-1 `ecx` feature bits (SSE3+ and friends).
struct Leaf1Ecx;
impl Leaf1Ecx {
    const SSE3: u32 = 1 << 0;
    const SSSE3: u32 = 1 << 9;
    const FMA: u32 = 1 << 12;
    const PCID: u32 = 1 << 17;
    const SSE4_1: u32 = 1 << 19;
    const SSE4_2: u32 = 1 << 20;
    const X2APIC: u32 = 1 << 21;
    const AES: u32 = 1 << 25;
    const XSAVE: u32 = 1 << 26;
    const AVX: u32 = 1 << 28;
    const RDRAND: u32 = 1 << 30;
}

/// Selected leaf-7 sub-leaf-0 `ebx` extended-feature bits.
struct Leaf7Ebx;
impl Leaf7Ebx {
    const BMI1: u32 = 1 << 3;
    const AVX2: u32 = 1 << 5;
    const SMEP: u32 = 1 << 7;
    const BMI2: u32 = 1 << 8;
    const AVX512F: u32 = 1 << 16;
    const RDSEED: u32 = 1 << 18;
    const SMAP: u32 = 1 << 20;
    const SHA: u32 = 1 << 29;
}

/// Selected leaf-7 sub-leaf-0 `ecx` feature bits (privilege-hardening + newer ISA).
struct Leaf7Ecx;
impl Leaf7Ecx {
    /// User-Mode Instruction Prevention — faults `sgdt`/`sidt`/… in ring 3.
    const UMIP: u32 = 1 << 2;
    /// CET shadow stack (control-flow integrity, return-address protection).
    const CET_SS: u32 = 1 << 7;
    /// 5-level paging / 57-bit linear addresses.
    const LA57: u32 = 1 << 16;
    const RDPID: u32 = 1 << 22;
}

/// Selected leaf-7 sub-leaf-0 `edx` feature bits (speculation-control + CET).
struct Leaf7Edx;
impl Leaf7Edx {
    /// CET indirect-branch tracking (forward-edge control-flow integrity).
    const CET_IBT: u32 = 1 << 20;
    /// IBRS/IBPB via the `IA32_SPEC_CTRL`/`IA32_PRED_CMD` MSRs (Spectre v2).
    const SPEC_CTRL: u32 = 1 << 26;
    /// Single-Thread Indirect Branch Predictors.
    const STIBP: u32 = 1 << 27;
    /// L1 data-cache flush MSR (`IA32_FLUSH_CMD`) — L1TF mitigation.
    const L1D_FLUSH: u32 = 1 << 28;
    /// Speculative Store Bypass Disable (Spectre v4).
    const SSBD: u32 = 1 << 31;
}

/// Selected extended leaf `0x8000_0001` `edx` bits (long mode + NX).
struct Ext1Edx;
impl Ext1Edx {
    const SYSCALL: u32 = 1 << 11;
    /// No-eXecute page permission (data pages non-executable) — W^X foundation.
    const NX: u32 = 1 << 20;
    /// 1 GiB huge pages.
    const PDPE1GB: u32 = 1 << 26;
    const RDTSCP: u32 = 1 << 27;
    /// Long mode (x86-64).
    const LM: u32 = 1 << 29;
}

/// Selected extended leaf `0x8000_0001` `ecx` bits.
struct Ext1Ecx;
impl Ext1Ecx {
    /// AMD Secure Virtual Machine (AMD-V) hardware virtualization.
    const SVM: u32 = 1 << 2;
}

/// AMD memory-encryption features — extended leaf `0x8000_001F` `eax`.
///
/// Directly relevant to SentinelOS's privacy mission: SME transparently encrypts
/// DRAM; SEV/SEV-ES/SEV-SNP extend that to per-VM encryption with register-state
/// and integrity protection. Intel's counterparts (TME/TDX) are probed via MSRs,
/// not this leaf, and are tracked separately.
struct Ext1FEax;
impl Ext1FEax {
    const SME: u32 = 1 << 0;
    const SEV: u32 = 1 << 1;
    const SEV_ES: u32 = 1 << 3;
    const SEV_SNP: u32 = 1 << 4;
}

/// Capacity ceiling for the feature list [`info`] reports (bits inspected across
/// leaf 1, leaf 7, and the extended leaves below). Callers can size a buffer to
/// this; the `add` helper never writes past it.
pub const MAX_FEATURES: usize = 48;

/// A structured, heap-free snapshot of what `cpuid` reports about this CPU.
///
/// Produced by [`info`]. Holds the vendor and brand strings, the decoded
/// family/model/stepping, and a fixed-capacity list of named feature flags (only
/// the first [`feature_count`](Self::feature_count) of which are valid).
#[derive(Clone, Copy, Debug)]
pub struct CpuInfo {
    /// 12-byte vendor id string (e.g. `"GenuineIntel"`, `"AuthenticAMD"`).
    pub vendor: CpuidString,
    /// 48-byte processor brand string, or empty if the CPU has no leaf
    /// `0x8000_0004`.
    pub brand: CpuidString,
    /// Decoded family/model/stepping from leaf 1.
    pub fms: FamilyModelStepping,
    /// Feature flags; only `[..feature_count]` are populated.
    features: [Feature; MAX_FEATURES],
    /// Number of valid entries in `features`.
    feature_count: usize,
}

impl CpuInfo {
    /// The populated feature-flag slice (name + present).
    #[must_use]
    pub fn features(&self) -> &[Feature] {
        &self.features[..self.feature_count]
    }

    /// The decoded CPU [`Vendor`] (Intel / AMD / other) from the vendor-id string.
    #[must_use]
    pub fn vendor_kind(&self) -> Vendor {
        Vendor::from_id(self.vendor.as_str())
    }
}

/// A placeholder feature used to pad the fixed-size array before population.
const EMPTY_FEATURE: Feature = Feature {
    name: "",
    present: false,
};

/// Query the live CPU and return a structured [`CpuInfo`].
///
/// Reads leaf 0 (vendor + max standard leaf), leaf 1 (family/model/stepping +
/// the baseline feature flags), leaf 7 sub-leaf 0 (extended feature flags, when
/// the CPU supports leaf 7), and the brand-string leaves `0x8000_0002..=0004`
/// (when the CPU supports leaf `0x8000_0004`). Leaves the CPU does not support are
/// skipped, so the corresponding flags simply read as `present: false` and the
/// brand string is empty — never UB.
#[must_use]
pub fn info() -> CpuInfo {
    // Leaf 0: vendor string (ebx, edx, ecx order) + highest standard leaf.
    let leaf0 = raw(0, 0);
    let max_std = leaf0.eax;
    let mut vendor = CpuidString::new();
    vendor.push_word(leaf0.ebx);
    vendor.push_word(leaf0.edx);
    vendor.push_word(leaf0.ecx);

    // Leaf 1: family/model/stepping + baseline feature flags.
    let (fms, edx1, ecx1) = if max_std >= 1 {
        let leaf1 = raw(1, 0);
        (
            FamilyModelStepping::from_eax(leaf1.eax),
            leaf1.edx,
            leaf1.ecx,
        )
    } else {
        (FamilyModelStepping::default(), 0, 0)
    };

    // Leaf 7 sub-leaf 0: extended feature flags (ebx/ecx/edx), when supported.
    let (ebx7, ecx7, edx7) = if max_std >= 7 {
        let l = raw(7, 0);
        (l.ebx, l.ecx, l.edx)
    } else {
        (0, 0, 0)
    };

    // Extended leaves. `0x8000_0001` carries NX / long-mode / AMD-V; `0x8000_001F`
    // carries AMD memory encryption (SME/SEV). Each is read only when the CPU
    // advertises that far, so unsupported leaves read as absent, never UB.
    let max_ext = max_extended_leaf();
    let (ext1_edx, ext1_ecx) = if max_ext >= 0x8000_0001 {
        let l = raw(0x8000_0001, 0);
        (l.edx, l.ecx)
    } else {
        (0, 0)
    };
    let ext1f_eax = if max_ext >= 0x8000_001F {
        raw(0x8000_001F, 0).eax
    } else {
        0
    };

    // Brand string from the extended leaves, when supported.
    let mut brand = CpuidString::new();
    if max_ext >= 0x8000_0004 {
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            let r = raw(leaf, 0);
            brand.push_word(r.eax);
            brand.push_word(r.ebx);
            brand.push_word(r.ecx);
            brand.push_word(r.edx);
        }
    }

    // Build the feature table. Order is roughly oldest → newest ISA.
    let mut features = [EMPTY_FEATURE; MAX_FEATURES];
    let mut n = 0;
    let mut add = |name: &'static str, bits: u32, mask: u32| {
        if n < MAX_FEATURES {
            features[n] = Feature {
                name,
                present: bits & mask != 0,
            };
            n += 1;
        }
    };

    add("fpu", edx1, Leaf1Edx::FPU);
    add("tsc", edx1, Leaf1Edx::TSC);
    add("msr", edx1, Leaf1Edx::MSR);
    add("pae", edx1, Leaf1Edx::PAE);
    add("apic", edx1, Leaf1Edx::APIC);
    add("mmx", edx1, Leaf1Edx::MMX);
    add("sse", edx1, Leaf1Edx::SSE);
    add("sse2", edx1, Leaf1Edx::SSE2);
    add("sse3", ecx1, Leaf1Ecx::SSE3);
    add("ssse3", ecx1, Leaf1Ecx::SSSE3);
    add("fma", ecx1, Leaf1Ecx::FMA);
    add("sse4.1", ecx1, Leaf1Ecx::SSE4_1);
    add("sse4.2", ecx1, Leaf1Ecx::SSE4_2);
    add("x2apic", ecx1, Leaf1Ecx::X2APIC);
    add("aes", ecx1, Leaf1Ecx::AES);
    add("xsave", ecx1, Leaf1Ecx::XSAVE);
    add("avx", ecx1, Leaf1Ecx::AVX);
    add("rdrand", ecx1, Leaf1Ecx::RDRAND);
    add("bmi1", ebx7, Leaf7Ebx::BMI1);
    add("avx2", ebx7, Leaf7Ebx::AVX2);
    add("smep", ebx7, Leaf7Ebx::SMEP);
    add("bmi2", ebx7, Leaf7Ebx::BMI2);
    add("rdseed", ebx7, Leaf7Ebx::RDSEED);
    add("smap", ebx7, Leaf7Ebx::SMAP);
    add("sha", ebx7, Leaf7Ebx::SHA);
    // Wide vectors (leaf 7 ebx) — relevant to CPU-side ML kernels.
    add("avx512f", ebx7, Leaf7Ebx::AVX512F);
    // Privilege & control-flow hardening (leaf 1 ecx, leaf 7 ecx/edx).
    add("pcid", ecx1, Leaf1Ecx::PCID);
    add("umip", ecx7, Leaf7Ecx::UMIP);
    add("cet_ss", ecx7, Leaf7Ecx::CET_SS);
    add("la57", ecx7, Leaf7Ecx::LA57);
    add("rdpid", ecx7, Leaf7Ecx::RDPID);
    add("cet_ibt", edx7, Leaf7Edx::CET_IBT);
    add("spec_ctrl", edx7, Leaf7Edx::SPEC_CTRL);
    add("stibp", edx7, Leaf7Edx::STIBP);
    add("l1d_flush", edx7, Leaf7Edx::L1D_FLUSH);
    add("ssbd", edx7, Leaf7Edx::SSBD);
    // Extended leaf 0x8000_0001: long mode, NX (W^X), 1 GiB pages, AMD-V.
    add("syscall", ext1_edx, Ext1Edx::SYSCALL);
    add("nx", ext1_edx, Ext1Edx::NX);
    add("pdpe1gb", ext1_edx, Ext1Edx::PDPE1GB);
    add("rdtscp", ext1_edx, Ext1Edx::RDTSCP);
    add("lm", ext1_edx, Ext1Edx::LM);
    add("svm", ext1_ecx, Ext1Ecx::SVM);
    // AMD memory encryption (leaf 0x8000_001F) — privacy-relevant.
    add("sme", ext1f_eax, Ext1FEax::SME);
    add("sev", ext1f_eax, Ext1FEax::SEV);
    add("sev_es", ext1f_eax, Ext1FEax::SEV_ES);
    add("sev_snp", ext1f_eax, Ext1FEax::SEV_SNP);

    CpuInfo {
        vendor,
        brand,
        fms,
        features,
        feature_count: n,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_model_stepping_combines_extended_fields() {
        // A typical Intel "Skylake"-ish leaf-1 eax: base family 0x6, base model
        // 0xE, extended model 0x5 → display model 0x5E, family 0x6, stepping 0x3.
        let eax = (0x5 << 16) | (0x6 << 8) | (0xE << 4) | 0x3;
        let fms = FamilyModelStepping::from_eax(eax);
        assert_eq!(fms.family, 0x6);
        assert_eq!(fms.model, 0x5E);
        assert_eq!(fms.stepping, 0x3);
    }

    #[test]
    fn family_extended_is_added_when_base_is_0xf() {
        // Base family 0xF with extended family 0x10 → display family 0x1F.
        let eax = (0x10 << 20) | (0xF << 8);
        let fms = FamilyModelStepping::from_eax(eax);
        assert_eq!(fms.family, 0xF + 0x10);
    }

    #[test]
    fn base_family_below_6_ignores_extended_model() {
        // Base family 0x5: extended model must NOT be combined.
        let eax = (0x7 << 16) | (0x5 << 8) | (0xA << 4) | 0x1;
        let fms = FamilyModelStepping::from_eax(eax);
        assert_eq!(fms.family, 0x5);
        assert_eq!(fms.model, 0xA);
        assert_eq!(fms.stepping, 0x1);
    }

    #[test]
    fn cpuid_string_collects_words_and_trims_padding() {
        let mut s = CpuidString::new();
        // "Genu" "ineI" "ntel" little-endian per word == "GenuineIntel".
        s.push_word(u32::from_le_bytes(*b"Genu"));
        s.push_word(u32::from_le_bytes(*b"ineI"));
        s.push_word(u32::from_le_bytes(*b"ntel"));
        assert_eq!(s.as_str(), "GenuineIntel");
    }

    #[test]
    fn cpuid_string_stops_at_nul() {
        let mut s = CpuidString::new();
        s.push_word(u32::from_le_bytes(*b"AB\0C"));
        assert_eq!(s.as_str(), "AB");
    }

    #[test]
    fn empty_cpuid_string_is_empty() {
        let s = CpuidString::new();
        assert_eq!(s.as_str(), "");
    }

    #[test]
    fn vendor_classifies_intel_and_amd() {
        assert_eq!(Vendor::from_id("GenuineIntel"), Vendor::Intel);
        assert_eq!(Vendor::from_id("AuthenticAMD"), Vendor::Amd);
        assert_eq!(Vendor::from_id("AMDisbetter!"), Vendor::Amd);
        assert_eq!(Vendor::from_id("VIA VIA VIA "), Vendor::Other);
        assert_eq!(Vendor::from_id(""), Vendor::Other);
    }

    #[test]
    fn vendor_labels_are_stable() {
        assert_eq!(Vendor::Intel.label(), "Intel");
        assert_eq!(Vendor::Amd.label(), "AMD");
        assert_eq!(Vendor::Other.label(), "other");
    }
}
