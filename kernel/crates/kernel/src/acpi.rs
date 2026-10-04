//! `kernel::acpi` — ACPI RSDP → RSDT/XSDT → MADT parsing (safe, no heap growth).
//!
//! SMP phase 3b-ii (IOAPIC routing, `docs/specs/2026-07-14-smp-x2apic-design.md`
//! "Phase 2") needs three things only the firmware knows: where each IOAPIC's
//! register window is, which global system interrupts (GSIs) it serves, and how
//! the ISA IRQs are wired onto those GSIs (the *Interrupt Source Overrides* —
//! under QEMU the PIT's ISA IRQ0 arrives on GSI 2). All three live in the ACPI
//! **MADT**, reached by walking `RSDP → RSDT|XSDT → "APIC"`.
//!
//! # Shape: `&[u8] -> Result` decoders plus one fetch-sequencing walker
//!
//! Every decoder here is a pure function of a byte slice — [`parse_rsdp`],
//! [`sdt_length`], [`root_entry`], [`parse_madt`] — returning `Result`/`Option`
//! and never panicking: this is what the Kani harnesses and the mutation-fuzz
//! test drive directly, with no reader, no memory model and no allocation in the
//! way. The one function that *fetches* ([`discover_madt`]) only sequences reads
//! through an injected `FnMut(phys, &mut [u8]) -> bool` that copies firmware
//! bytes into caller-owned buffers (production: `hal::acpi::read_phys`; tests: a
//! closure over a byte arena). The closure shape stays because the walk needs
//! bytes at addresses only known mid-walk (the RSDP names the root table, the root
//! table names the MADT); the copy-into-buffer contract (rather than handing out a
//! `&'static [u8]` over firmware memory, as the salvaged 2026-07-17 draft did) means
//! the kernel never holds a reference into memory it does not own, and the buffers
//! are allocated once at a **fixed** size — no length read from firmware ever sizes
//! an allocation.
//!
//! # What is checked
//!
//! Signatures, declared lengths against the bytes actually present, and the ACPI
//! checksums (RSDP v1 and v2 fields, every SDT). In the MADT, every
//! interrupt-controller structure must fit inside the table and be at least as
//! long as its type requires: a zero/one-byte length, a structure running past the
//! end, a too-short known structure, a reserved polarity/trigger encoding, a
//! duplicate override for one ISA source, or more IOAPICs/overrides/NMI entries
//! than [`MadtInfo`] has room for is an `Err` — never a panic, never a partial
//! result. Unknown structure types are skipped by their own length, so future
//! ACPI revisions do not break the walk. Every loop is bounded by the table
//! length (each iteration consumes ≥ 2 bytes).

/// Why an ACPI structure failed to parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// Fewer bytes were available than the structure being read requires.
    Truncated,
    /// The RSDP's `"RSD PTR "` signature did not match.
    BadRsdpSignature,
    /// An SDT's 4-byte signature did not match what the caller expected.
    BadSignature,
    /// A checksum (RSDP or SDT) did not sum to zero.
    BadChecksum,
    /// A declared length is inconsistent (shorter than its own header, or a
    /// MADT structure shorter than its type requires / shorter than 2 bytes).
    Malformed,
    /// A table is larger than the fixed buffer the caller provided.
    TooLarge,
    /// More IOAPICs, overrides or NMI structures than [`MadtInfo`] holds.
    Capacity,
    /// The reader could not supply bytes at a physical address.
    Unreadable,
    /// The root table was walked but no entry led to a valid MADT.
    NoMadt,
}

/// Length of the ACPI 1.0 RSDP (signature, checksum, OEM id, revision, RSDT).
pub const RSDP_V1_LEN: usize = 20;
/// Length of the ACPI 2.0+ RSDP (adds length, XSDT address, extended checksum).
pub const RSDP_V2_LEN: usize = 36;
/// Length of the common System Description Table header.
pub const SDT_HEADER_LEN: usize = 36;
/// Offset of the first interrupt-controller structure in the MADT (header plus
/// the 4-byte Local APIC Address and 4-byte Flags fields).
pub const MADT_ENTRIES_OFFSET: usize = SDT_HEADER_LEN + 8;

/// Logical CPUs recorded in [`MadtInfo::cpus`]; more are counted, not stored.
pub const MAX_CPUS: usize = 64;
/// IOAPICs [`MadtInfo`] holds; a table listing more is [`AcpiError::Capacity`].
pub const MAX_IOAPICS: usize = 8;
/// Interrupt Source Overrides [`MadtInfo`] holds (ISA has only 16 sources).
pub const MAX_OVERRIDES: usize = 16;
/// Local-APIC NMI structures (types 4 and 0xA) [`MadtInfo`] holds.
pub const MAX_LAPIC_NMIS: usize = 8;
/// NMI-source structures (type 3) [`MadtInfo`] holds.
pub const MAX_NMI_SOURCES: usize = 4;

const RSDP_SIGNATURE: [u8; 8] = *b"RSD PTR ";
const RSDT_SIGNATURE: [u8; 4] = *b"RSDT";
const XSDT_SIGNATURE: [u8; 4] = *b"XSDT";
const MADT_SIGNATURE: [u8; 4] = *b"APIC";

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let s = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let s = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let s = bytes.get(offset..offset.checked_add(8)?)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(s);
    Some(u64::from_le_bytes(a))
}

/// Whether `bytes` sums to zero mod 256 (the ACPI checksum rule).
#[must_use]
pub fn checksum_ok(bytes: &[u8]) -> bool {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b)) == 0
}

/// Which root table the RSDP names, and where it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootTable {
    /// ACPI 1.0 RSDT: 32-bit physical pointers (QEMU's `pc`/`q35` use this).
    Rsdt(u64),
    /// ACPI 2.0+ XSDT: 64-bit physical pointers.
    Xsdt(u64),
}

impl RootTable {
    /// Physical address of the root table.
    #[must_use]
    pub const fn addr(self) -> u64 {
        match self {
            RootTable::Rsdt(a) | RootTable::Xsdt(a) => a,
        }
    }
    const fn signature(self) -> &'static [u8; 4] {
        match self {
            RootTable::Rsdt(_) => &RSDT_SIGNATURE,
            RootTable::Xsdt(_) => &XSDT_SIGNATURE,
        }
    }
    const fn entry_size(self) -> usize {
        match self {
            RootTable::Rsdt(_) => 4,
            RootTable::Xsdt(_) => 8,
        }
    }
}

/// Parse an RSDP. `bytes` should hold [`RSDP_V2_LEN`] bytes where available; a
/// revision-0 RSDP needs only the first [`RSDP_V1_LEN`].
///
/// A revision ≥ 2 RSDP with a non-zero XSDT address and a valid extended
/// checksum selects the XSDT; otherwise the RSDT is used (ACPI says an OS must
/// prefer the XSDT when present).
///
/// # Errors
///
/// [`AcpiError::Truncated`], [`AcpiError::BadRsdpSignature`],
/// [`AcpiError::BadChecksum`] (v1 checksum), [`AcpiError::Malformed`] (no usable
/// root pointer).
pub fn parse_rsdp(bytes: &[u8]) -> Result<RootTable, AcpiError> {
    let v1 = bytes.get(..RSDP_V1_LEN).ok_or(AcpiError::Truncated)?;
    if v1[0..8] != RSDP_SIGNATURE {
        return Err(AcpiError::BadRsdpSignature);
    }
    if !checksum_ok(v1) {
        return Err(AcpiError::BadChecksum);
    }
    let revision = v1[15];
    if revision >= 2 {
        if let Some(v2) = bytes.get(..RSDP_V2_LEN) {
            let xsdt = read_u64(v2, 24).unwrap_or(0);
            let len = read_u32(v2, 20).unwrap_or(0) as usize;
            let ext_ok = len >= RSDP_V2_LEN && checksum_ok(v2);
            if xsdt != 0 && ext_ok {
                return Ok(RootTable::Xsdt(xsdt));
            }
        }
    }
    let rsdt = u64::from(read_u32(v1, 16).unwrap_or(0));
    if rsdt == 0 {
        return Err(AcpiError::Malformed);
    }
    Ok(RootTable::Rsdt(rsdt))
}

/// Check an SDT header's signature against `expect` and return its declared
/// total length (≥ [`SDT_HEADER_LEN`]).
///
/// # Errors
///
/// [`AcpiError::Truncated`], [`AcpiError::BadSignature`], or
/// [`AcpiError::Malformed`] if the declared length is shorter than the header.
pub fn sdt_length(bytes: &[u8], expect: &[u8; 4]) -> Result<usize, AcpiError> {
    let h = bytes.get(..SDT_HEADER_LEN).ok_or(AcpiError::Truncated)?;
    if &h[0..4] != expect {
        return Err(AcpiError::BadSignature);
    }
    let len = read_u32(h, 4).ok_or(AcpiError::Truncated)? as usize;
    if len < SDT_HEADER_LEN {
        return Err(AcpiError::Malformed);
    }
    Ok(len)
}

/// Validate a whole SDT: signature, declared length present in `bytes`,
/// checksum over exactly that length. Returns the table's bytes.
///
/// # Errors
///
/// As [`sdt_length`], plus [`AcpiError::Truncated`] if fewer than the declared
/// length are present and [`AcpiError::BadChecksum`].
pub fn validate_sdt<'a>(bytes: &'a [u8], expect: &[u8; 4]) -> Result<&'a [u8], AcpiError> {
    let len = sdt_length(bytes, expect)?;
    let table = bytes.get(..len).ok_or(AcpiError::Truncated)?;
    if !checksum_ok(table) {
        return Err(AcpiError::BadChecksum);
    }
    Ok(table)
}

/// Number of whole pointers in a validated root table of `kind`.
#[must_use]
pub fn root_entry_count(table: &[u8], kind: RootTable) -> usize {
    table.len().saturating_sub(SDT_HEADER_LEN) / kind.entry_size()
}

/// Pointer `index` of a validated root table of `kind`, or `None` past the end.
#[must_use]
pub fn root_entry(table: &[u8], kind: RootTable, index: usize) -> Option<u64> {
    let off = SDT_HEADER_LEN.checked_add(index.checked_mul(kind.entry_size())?)?;
    match kind {
        RootTable::Rsdt(_) => read_u32(table, off).map(u64::from),
        RootTable::Xsdt(_) => read_u64(table, off),
    }
}

// ── MADT model ──────────────────────────────────────────────────────────────

/// One logical CPU (MADT type 0 Processor Local APIC or type 9 x2APIC).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CpuEntry {
    /// The APIC ID (x2APIC ID for type 9, zero-extended for type 0).
    pub apic_id: u32,
    /// ACPI `Enabled` flag (bit 0).
    pub enabled: bool,
}

/// One IOAPIC (MADT type 1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoApicEntry {
    /// The IOAPIC's ID.
    pub id: u8,
    /// Physical address of its register window (IOREGSEL at +0, IOWIN at +0x10).
    pub address: u32,
    /// First GSI its pin 0 serves.
    pub gsi_base: u32,
}

/// Interrupt polarity from MPS INTI flags bits 0–1.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Polarity {
    /// `00`: conforms to the bus (ISA: active high).
    #[default]
    Conforms,
    /// `01`: active high.
    ActiveHigh,
    /// `11`: active low.
    ActiveLow,
}

/// Trigger mode from MPS INTI flags bits 2–3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Trigger {
    /// `00`: conforms to the bus (ISA: edge).
    #[default]
    Conforms,
    /// `01`: edge.
    Edge,
    /// `11`: level.
    Level,
}

/// Decode MPS INTI flags; `None` for the reserved `10` encoding of either field.
#[must_use]
pub const fn decode_inti_flags(flags: u16) -> Option<(Polarity, Trigger)> {
    let polarity = match flags & 0b11 {
        0b00 => Polarity::Conforms,
        0b01 => Polarity::ActiveHigh,
        0b11 => Polarity::ActiveLow,
        _ => return None,
    };
    let trigger = match (flags >> 2) & 0b11 {
        0b00 => Trigger::Conforms,
        0b01 => Trigger::Edge,
        0b11 => Trigger::Level,
        _ => return None,
    };
    Some((polarity, trigger))
}

/// One Interrupt Source Override (MADT type 2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IsoEntry {
    /// Bus (0 = ISA, the only value ACPI defines).
    pub bus: u8,
    /// The bus-relative IRQ (the ISA IRQ number).
    pub source: u8,
    /// The GSI that source is wired to.
    pub gsi: u32,
    /// Decoded polarity.
    pub polarity: Polarity,
    /// Decoded trigger mode.
    pub trigger: Trigger,
}

/// A Local APIC NMI structure (type 4, or type 0xA for x2APIC UIDs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LapicNmi {
    /// ACPI processor UID (`0xFF` / `0xFFFF_FFFF` = all processors).
    pub uid: u32,
    /// Decoded polarity.
    pub polarity: Polarity,
    /// Decoded trigger mode.
    pub trigger: Trigger,
    /// Which LINT pin (0 or 1) the NMI is wired to.
    pub lint: u8,
}

/// An NMI source (type 3): a GSI that must be programmed as NMI.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NmiSource {
    /// The GSI.
    pub gsi: u32,
    /// Decoded polarity.
    pub polarity: Polarity,
    /// Decoded trigger mode.
    pub trigger: Trigger,
}

/// Everything the MADT says that the kernel uses — fixed size, no heap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MadtInfo {
    /// The 32-bit Local APIC physical address field.
    pub lapic_addr: u32,
    /// MADT flags (bit 0 `PCAT_COMPAT`: dual 8259s present, must be masked).
    pub flags: u32,
    /// First [`MAX_CPUS`] CPU entries, in table order.
    pub cpus: [CpuEntry; MAX_CPUS],
    /// CPU entries seen (may exceed [`MAX_CPUS`]; only the first are stored).
    pub cpus_seen: u32,
    /// IOAPICs, in table order.
    pub ioapics: [IoApicEntry; MAX_IOAPICS],
    /// Valid entries in `ioapics`.
    pub ioapic_count: u8,
    /// Interrupt Source Overrides, in table order.
    pub overrides: [IsoEntry; MAX_OVERRIDES],
    /// Valid entries in `overrides`.
    pub override_count: u8,
    /// Local APIC NMI structures (types 4 and 0xA).
    pub lapic_nmis: [LapicNmi; MAX_LAPIC_NMIS],
    /// Valid entries in `lapic_nmis`.
    pub lapic_nmi_count: u8,
    /// NMI sources (type 3).
    pub nmi_sources: [NmiSource; MAX_NMI_SOURCES],
    /// Valid entries in `nmi_sources`.
    pub nmi_source_count: u8,
}

impl MadtInfo {
    const EMPTY: Self = Self {
        lapic_addr: 0,
        flags: 0,
        cpus: [CpuEntry {
            apic_id: 0,
            enabled: false,
        }; MAX_CPUS],
        cpus_seen: 0,
        ioapics: [IoApicEntry {
            id: 0,
            address: 0,
            gsi_base: 0,
        }; MAX_IOAPICS],
        ioapic_count: 0,
        overrides: [IsoEntry {
            bus: 0,
            source: 0,
            gsi: 0,
            polarity: Polarity::Conforms,
            trigger: Trigger::Conforms,
        }; MAX_OVERRIDES],
        override_count: 0,
        lapic_nmis: [LapicNmi {
            uid: 0,
            polarity: Polarity::Conforms,
            trigger: Trigger::Conforms,
            lint: 0,
        }; MAX_LAPIC_NMIS],
        lapic_nmi_count: 0,
        nmi_sources: [NmiSource {
            gsi: 0,
            polarity: Polarity::Conforms,
            trigger: Trigger::Conforms,
        }; MAX_NMI_SOURCES],
        nmi_source_count: 0,
    };

    /// The valid IOAPIC entries.
    #[must_use]
    pub fn ioapics(&self) -> &[IoApicEntry] {
        &self.ioapics[..usize::from(self.ioapic_count).min(MAX_IOAPICS)]
    }

    /// The valid override entries.
    #[must_use]
    pub fn overrides(&self) -> &[IsoEntry] {
        &self.overrides[..usize::from(self.override_count).min(MAX_OVERRIDES)]
    }

    /// The stored CPU entries.
    #[must_use]
    pub fn cpus(&self) -> &[CpuEntry] {
        &self.cpus[..(self.cpus_seen as usize).min(MAX_CPUS)]
    }

    /// The override for ISA IRQ `source`, if the firmware declared one.
    #[must_use]
    pub fn override_for_isa(&self, source: u8) -> Option<IsoEntry> {
        self.overrides()
            .iter()
            .copied()
            .find(|o| o.bus == 0 && o.source == source)
    }
}

/// Push `item` into a fixed array, or fail with [`AcpiError::Capacity`].
fn push<T: Copy, const N: usize>(
    arr: &mut [T; N],
    count: &mut u8,
    item: T,
) -> Result<(), AcpiError> {
    let i = usize::from(*count);
    let slot = arr.get_mut(i).ok_or(AcpiError::Capacity)?;
    *slot = item;
    *count = count.checked_add(1).ok_or(AcpiError::Capacity)?;
    Ok(())
}

/// Decode one interrupt-controller structure (`entry` is exactly its declared
/// bytes, `entry.len() >= 2`) into `info`.
fn decode_entry(entry: &[u8], info: &mut MadtInfo) -> Result<(), AcpiError> {
    let need = |min: usize| {
        if entry.len() < min {
            Err(AcpiError::Malformed)
        } else {
            Ok(())
        }
    };
    let flags_of = |off: usize| -> Result<(Polarity, Trigger), AcpiError> {
        let raw = read_u16(entry, off).ok_or(AcpiError::Malformed)?;
        decode_inti_flags(raw).ok_or(AcpiError::Malformed)
    };
    match entry[0] {
        // Processor Local APIC: [0, 8, uid, apic_id, flags:u32].
        0 => {
            need(8)?;
            let cpu = CpuEntry {
                apic_id: u32::from(entry[3]),
                enabled: read_u32(entry, 4).ok_or(AcpiError::Malformed)? & 1 != 0,
            };
            record_cpu(info, cpu);
        }
        // I/O APIC: [1, 12, id, reserved, address:u32, gsi_base:u32].
        1 => {
            need(12)?;
            let io = IoApicEntry {
                id: entry[2],
                address: read_u32(entry, 4).ok_or(AcpiError::Malformed)?,
                gsi_base: read_u32(entry, 8).ok_or(AcpiError::Malformed)?,
            };
            push(&mut info.ioapics, &mut info.ioapic_count, io)?;
        }
        // Interrupt Source Override: [2, 10, bus, source, gsi:u32, flags:u16].
        2 => {
            need(10)?;
            let (polarity, trigger) = flags_of(8)?;
            let iso = IsoEntry {
                bus: entry[2],
                source: entry[3],
                gsi: read_u32(entry, 4).ok_or(AcpiError::Malformed)?,
                polarity,
                trigger,
            };
            if info
                .overrides()
                .iter()
                .any(|o| o.bus == iso.bus && o.source == iso.source)
            {
                return Err(AcpiError::Malformed);
            }
            push(&mut info.overrides, &mut info.override_count, iso)?;
        }
        // NMI Source: [3, 8, flags:u16, gsi:u32].
        3 => {
            need(8)?;
            let (polarity, trigger) = flags_of(2)?;
            let src = NmiSource {
                gsi: read_u32(entry, 4).ok_or(AcpiError::Malformed)?,
                polarity,
                trigger,
            };
            push(&mut info.nmi_sources, &mut info.nmi_source_count, src)?;
        }
        // Local APIC NMI: [4, 6, uid, flags:u16, lint].
        4 => {
            need(6)?;
            let (polarity, trigger) = flags_of(3)?;
            let uid = if entry[2] == 0xFF {
                u32::MAX
            } else {
                u32::from(entry[2])
            };
            let nmi = LapicNmi {
                uid,
                polarity,
                trigger,
                lint: entry[5],
            };
            push(&mut info.lapic_nmis, &mut info.lapic_nmi_count, nmi)?;
        }
        // Processor Local x2APIC: [9, 16, reserved:2, x2apic_id:u32, flags:u32, uid:u32].
        9 => {
            need(16)?;
            let cpu = CpuEntry {
                apic_id: read_u32(entry, 4).ok_or(AcpiError::Malformed)?,
                enabled: read_u32(entry, 8).ok_or(AcpiError::Malformed)? & 1 != 0,
            };
            record_cpu(info, cpu);
        }
        // Local x2APIC NMI: [0xA, 12, flags:u16, uid:u32, lint, reserved:3].
        0xA => {
            need(12)?;
            let (polarity, trigger) = flags_of(2)?;
            let nmi = LapicNmi {
                uid: read_u32(entry, 4).ok_or(AcpiError::Malformed)?,
                polarity,
                trigger,
                lint: entry[8],
            };
            push(&mut info.lapic_nmis, &mut info.lapic_nmi_count, nmi)?;
        }
        // Everything else (LAPIC address override, GIC structures, …): skipped.
        _ => {}
    }
    Ok(())
}

fn record_cpu(info: &mut MadtInfo, cpu: CpuEntry) {
    if let Some(slot) = info.cpus.get_mut(info.cpus_seen as usize) {
        *slot = cpu;
    }
    info.cpus_seen = info.cpus_seen.saturating_add(1);
}

/// Decode the interrupt-controller structures of an already-sized MADT body.
///
/// `table` is the MADT's bytes (its declared length, header included). The walk
/// is the bounds proof: each iteration requires `offset + 2 <= len`, consumes
/// `entry_len >= 2` bytes, and slices `entry` through `get` — so it terminates
/// within `len / 2` iterations and never indexes out of bounds.
///
/// # Errors
///
/// [`AcpiError::Truncated`] if the fixed MADT prefix or a structure runs past the
/// table, [`AcpiError::Malformed`] / [`AcpiError::Capacity`] from the structure
/// rules in the module docs.
pub fn parse_madt_body(table: &[u8]) -> Result<MadtInfo, AcpiError> {
    let mut info = MadtInfo::EMPTY;
    info.lapic_addr = read_u32(table, SDT_HEADER_LEN).ok_or(AcpiError::Truncated)?;
    info.flags = read_u32(table, SDT_HEADER_LEN + 4).ok_or(AcpiError::Truncated)?;
    for_each_entry(table, |entry| decode_entry(entry, &mut info))?;
    Ok(info)
}

/// Walk the interrupt-controller structures of a sized MADT, handing each one
/// (exactly its declared bytes, ≥ 2 long) to `f` in table order. On `Ok` the
/// structures exactly tile `[MADT_ENTRIES_OFFSET, table.len())`; a structure
/// shorter than 2 bytes is [`AcpiError::Malformed`], one running past the
/// table (or a lone trailing byte) [`AcpiError::Truncated`], and `f`'s first
/// error stops the walk. Terminates within `len / 2` iterations: each consumes
/// ≥ 2 bytes. Kani: `madt_walk_is_total_and_tiles`.
///
/// # Errors
///
/// As above.
pub fn for_each_entry(
    table: &[u8],
    mut f: impl FnMut(&[u8]) -> Result<(), AcpiError>,
) -> Result<(), AcpiError> {
    let mut offset = MADT_ENTRIES_OFFSET;
    while offset < table.len() {
        let header = table.get(offset..offset + 2).ok_or(AcpiError::Truncated)?;
        let entry_len = usize::from(header[1]);
        if entry_len < 2 {
            return Err(AcpiError::Malformed);
        }
        let end = offset.checked_add(entry_len).ok_or(AcpiError::Truncated)?;
        let entry = table.get(offset..end).ok_or(AcpiError::Truncated)?;
        f(entry)?;
        offset = end;
    }
    Ok(())
}

/// Parse a complete MADT: validate the SDT (signature, length, checksum) and
/// decode its structures.
///
/// # Errors
///
/// Any [`validate_sdt`] or [`parse_madt_body`] error.
pub fn parse_madt(bytes: &[u8]) -> Result<MadtInfo, AcpiError> {
    let table = validate_sdt(bytes, &MADT_SIGNATURE)?;
    parse_madt_body(table)
}

/// Walk `RSDP → RSDT|XSDT → MADT` and parse the first valid MADT.
///
/// `read(phys, buf)` must fill all of `buf` with the bytes at physical `phys`,
/// returning `false` if it cannot. `root_buf` and `madt_buf` are caller-owned
/// fixed-size scratch: a table longer than its buffer is
/// [`AcpiError::TooLarge`] (nothing is ever sized from a firmware length).
/// Root-table entries that are unreadable or not a valid MADT are skipped.
///
/// # Errors
///
/// [`AcpiError::Unreadable`] for the RSDP / root table, any RSDP or root-table
/// validation error, [`AcpiError::TooLarge`], or [`AcpiError::NoMadt`] — or the
/// parse error of an `"APIC"`-signed table that failed to decode (a malformed
/// MADT is reported, not silently replaced by a later one).
pub fn discover_madt(
    rsdp_phys: u64,
    mut read: impl FnMut(u64, &mut [u8]) -> bool,
    root_buf: &mut [u8],
    madt_buf: &mut [u8],
) -> Result<MadtInfo, AcpiError> {
    let mut rsdp = [0u8; RSDP_V2_LEN];
    if !read(rsdp_phys, &mut rsdp) {
        // A v1 RSDP at the very end of a readable range: retry its 20 bytes.
        if !read(rsdp_phys, &mut rsdp[..RSDP_V1_LEN]) {
            return Err(AcpiError::Unreadable);
        }
        rsdp[RSDP_V1_LEN..].fill(0);
    }
    let root = parse_rsdp(&rsdp)?;

    let root_table = fetch_sdt(root.addr(), root.signature(), &mut read, root_buf)?;
    let count = root_entry_count(root_table, root);
    for i in 0..count {
        let Some(ptr) = root_entry(root_table, root, i) else {
            break;
        };
        let mut header = [0u8; SDT_HEADER_LEN];
        if !read(ptr, &mut header) || sdt_length(&header, &MADT_SIGNATURE).is_err() {
            continue;
        }
        let madt = fetch_sdt(ptr, &MADT_SIGNATURE, &mut read, madt_buf)?;
        return parse_madt_body(madt);
    }
    Err(AcpiError::NoMadt)
}

/// Read an SDT's header, then its whole declared length into `buf`, validated.
fn fetch_sdt<'b>(
    phys: u64,
    sig: &[u8; 4],
    read: &mut impl FnMut(u64, &mut [u8]) -> bool,
    buf: &'b mut [u8],
) -> Result<&'b [u8], AcpiError> {
    let mut header = [0u8; SDT_HEADER_LEN];
    if !read(phys, &mut header) {
        return Err(AcpiError::Unreadable);
    }
    let len = sdt_length(&header, sig)?;
    let dst = buf.get_mut(..len).ok_or(AcpiError::TooLarge)?;
    if !read(phys, dst) {
        return Err(AcpiError::Unreadable);
    }
    validate_sdt(dst, sig)
}

// ── Host unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// QEMU 8.2 `-M q35 -smp 4` MADT, captured from this kernel's own boot
    /// (`hal::acpi::read_phys`, serial hex dump, 2026-10-04). 4 × Processor
    /// Local APIC, 1 × IOAPIC (id 0, 0xFEC0_0000, GSI base 0), 5 × ISO
    /// (IRQ0→GSI2; IRQ5/9/10/11 level active-high), 1 × Local APIC NMI (all
    /// processors, LINT1).
    pub(crate) const QEMU_Q35_MADT: &[u8] = &[
        0x41, 0x50, 0x49, 0x43, 0x90, 0x00, 0x00, 0x00, 0x03, 0x49, 0x42, 0x4f, 0x43, 0x48, 0x53,
        0x20, 0x42, 0x58, 0x50, 0x43, 0x20, 0x20, 0x20, 0x20, 0x01, 0x00, 0x00, 0x00, 0x42, 0x58,
        0x50, 0x43, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x08, 0x02, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0x03, 0x03, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a,
        0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x0a, 0x00, 0x05, 0x05, 0x00, 0x00,
        0x00, 0x0d, 0x00, 0x02, 0x0a, 0x00, 0x09, 0x09, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x02, 0x0a,
        0x00, 0x0a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x02, 0x0a, 0x00, 0x0b, 0x0b, 0x00, 0x00,
        0x00, 0x0d, 0x00, 0x04, 0x06, 0xff, 0x00, 0x00, 0x01,
    ];

    /// The same boot's RSDT (QEMU 8.2 q35, SeaBIOS: a revision-0 RSDP, so the
    /// RSDT — not an XSDT — is the root): five 32-bit table pointers.
    const QEMU_Q35_RSDT: &[u8] = &[
        0x52, 0x53, 0x44, 0x54, 0x38, 0x00, 0x00, 0x00, 0x01, 0xec, 0x42, 0x4f, 0x43, 0x48, 0x53,
        0x20, 0x42, 0x58, 0x50, 0x43, 0x20, 0x20, 0x20, 0x20, 0x01, 0x00, 0x00, 0x00, 0x42, 0x58,
        0x50, 0x43, 0x01, 0x00, 0x00, 0x00, 0x05, 0x22, 0xfe, 0x0f, 0xf9, 0x22, 0xfe, 0x0f, 0x89,
        0x23, 0xfe, 0x0f, 0xc1, 0x23, 0xfe, 0x0f, 0xfd, 0x23, 0xfe, 0x0f,
    ];

    /// Fix up byte 9 so the table sums to zero.
    pub(crate) fn fix_checksum(t: &mut [u8]) {
        t[9] = 0;
        let sum = t.iter().fold(0u8, |a, &b| a.wrapping_add(b));
        t[9] = 0u8.wrapping_sub(sum);
    }

    fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
        let mut t = alloc::vec![0u8; SDT_HEADER_LEN];
        t[0..4].copy_from_slice(sig);
        t[4..8].copy_from_slice(&((SDT_HEADER_LEN + body.len()) as u32).to_le_bytes());
        t.extend_from_slice(body);
        fix_checksum(&mut t);
        t
    }

    fn madt(entries: &[u8]) -> Vec<u8> {
        let mut body = alloc::vec![0u8; 8];
        body[0..4].copy_from_slice(&0xFEE0_0000u32.to_le_bytes());
        body[4] = 1;
        body.extend_from_slice(entries);
        sdt(&MADT_SIGNATURE, &body)
    }

    fn rsdp_v1(rsdt: u32) -> Vec<u8> {
        let mut b = alloc::vec![0u8; RSDP_V1_LEN];
        b[0..8].copy_from_slice(&RSDP_SIGNATURE);
        b[16..20].copy_from_slice(&rsdt.to_le_bytes());
        let s = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(s);
        b
    }

    fn rsdp_v2(xsdt: u64) -> Vec<u8> {
        let mut b = alloc::vec![0u8; RSDP_V2_LEN];
        b[0..8].copy_from_slice(&RSDP_SIGNATURE);
        b[15] = 2;
        b[20..24].copy_from_slice(&(RSDP_V2_LEN as u32).to_le_bytes());
        b[24..32].copy_from_slice(&xsdt.to_le_bytes());
        let s = b[..RSDP_V1_LEN].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(s);
        let s = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[32] = 0u8.wrapping_sub(s);
        b
    }

    #[test]
    fn qemu_madt_parses_exactly() {
        assert!(checksum_ok(QEMU_Q35_MADT));
        let m = parse_madt(QEMU_Q35_MADT).expect("QEMU's MADT parses");
        assert_eq!(m.lapic_addr, 0xFEE0_0000);
        assert_eq!(m.flags & 1, 1, "PCAT_COMPAT: dual 8259s present");
        assert_eq!(m.cpus_seen, 4);
        for (i, c) in m.cpus().iter().enumerate() {
            assert_eq!(
                *c,
                CpuEntry {
                    apic_id: i as u32,
                    enabled: true
                }
            );
        }
        assert_eq!(
            m.ioapics(),
            &[IoApicEntry {
                id: 0,
                address: 0xFEC0_0000,
                gsi_base: 0
            }]
        );
        assert_eq!(m.override_count, 5);
        let irq0 = m.override_for_isa(0).expect("IRQ0 override");
        assert_eq!(irq0.gsi, 2);
        assert_eq!(
            (irq0.polarity, irq0.trigger),
            (Polarity::Conforms, Trigger::Conforms)
        );
        for irq in [5u8, 9, 10, 11] {
            let o = m.override_for_isa(irq).expect("PCI IRQ override");
            assert_eq!(o.gsi, u32::from(irq));
            assert_eq!(
                (o.polarity, o.trigger),
                (Polarity::ActiveHigh, Trigger::Level)
            );
        }
        assert!(m.override_for_isa(1).is_none());
        assert!(m.override_for_isa(12).is_none());
        assert_eq!(m.lapic_nmi_count, 1);
        assert_eq!(m.lapic_nmis[0].uid, u32::MAX);
        assert_eq!(m.lapic_nmis[0].lint, 1);
    }

    #[test]
    fn every_truncation_of_qemu_madt_is_err_or_ok_never_panics() {
        // Shrink the declared length too, so the walk itself meets the cut.
        for len in 0..QEMU_Q35_MADT.len() {
            assert!(parse_madt(&QEMU_Q35_MADT[..len]).is_err());
            let mut t = QEMU_Q35_MADT[..len].to_vec();
            if t.len() >= 8 {
                t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            }
            if t.len() > 9 {
                fix_checksum(&mut t);
            }
            let r = parse_madt(&t);
            // Cutting at a structure boundary is a valid (shorter) table.
            let boundary = [44usize, 52, 60, 68, 76, 88, 98, 108, 118, 128, 138, 144];
            assert_eq!(r.is_ok(), boundary.contains(&len), "len={len} r={r:?}");
        }
    }

    #[test]
    fn qemu_rsdt_lists_five_tables() {
        let t = validate_sdt(QEMU_Q35_RSDT, &RSDT_SIGNATURE).expect("valid RSDT");
        let k = RootTable::Rsdt(0);
        assert_eq!(root_entry_count(t, k), 5);
        assert_eq!(root_entry(t, k, 0), Some(0x0FFE_2205));
        assert_eq!(root_entry(t, k, 4), Some(0x0FFE_23FD));
    }

    #[test]
    fn rsdp_v1_selects_rsdt_and_v2_selects_xsdt() {
        assert_eq!(parse_rsdp(&rsdp_v1(0x1234)), Ok(RootTable::Rsdt(0x1234)));
        assert_eq!(
            parse_rsdp(&rsdp_v2(0xABCD_0000)),
            Ok(RootTable::Xsdt(0xABCD_0000))
        );
    }

    #[test]
    fn rsdp_rejects_bad_signature_checksum_and_short() {
        let mut b = rsdp_v1(0x1000);
        b[0] = b'X';
        assert_eq!(parse_rsdp(&b), Err(AcpiError::BadRsdpSignature));
        let mut b = rsdp_v1(0x1000);
        b[17] ^= 1;
        assert_eq!(parse_rsdp(&b), Err(AcpiError::BadChecksum));
        assert_eq!(parse_rsdp(&[0u8; 10]), Err(AcpiError::Truncated));
        assert_eq!(parse_rsdp(&rsdp_v1(0)), Err(AcpiError::Malformed));
    }

    #[test]
    fn rsdp_v2_with_bad_extended_checksum_falls_back_to_rsdt() {
        let mut b = rsdp_v2(0x5000);
        b[16..20].copy_from_slice(&0x7000u32.to_le_bytes());
        // Re-fix only the v1 checksum: the extended one is now wrong.
        b[8] = 0;
        let s = b[..RSDP_V1_LEN].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(s);
        b[33] ^= 1; // reserved byte, covered only by the extended checksum
        assert_eq!(parse_rsdp(&b), Ok(RootTable::Rsdt(0x7000)));
    }

    #[test]
    fn sdt_rules() {
        let t = sdt(b"FACP", &[1, 2, 3]);
        assert_eq!(sdt_length(&t, b"APIC"), Err(AcpiError::BadSignature));
        assert_eq!(validate_sdt(&t, b"FACP").map(<[u8]>::len), Ok(39));
        let mut bad = t.clone();
        bad[37] ^= 0x40;
        assert_eq!(validate_sdt(&bad, b"FACP"), Err(AcpiError::BadChecksum));
        let mut short = t.clone();
        short[4..8].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(sdt_length(&short, b"FACP"), Err(AcpiError::Malformed));
        assert_eq!(validate_sdt(&t[..38], b"FACP"), Err(AcpiError::Truncated));
    }

    #[test]
    fn root_entries_rsdt_and_xsdt() {
        let r = sdt(&RSDT_SIGNATURE, &[0x00, 0x10, 0, 0, 0x00, 0x20, 0, 0, 0xAA]);
        let k = RootTable::Rsdt(0);
        assert_eq!(root_entry_count(&r, k), 2);
        assert_eq!(root_entry(&r, k, 0), Some(0x1000));
        assert_eq!(root_entry(&r, k, 1), Some(0x2000));
        assert_eq!(root_entry(&r, k, 2), None);
        let mut body = Vec::new();
        body.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
        let x = sdt(&XSDT_SIGNATURE, &body);
        let k = RootTable::Xsdt(0);
        assert_eq!(root_entry_count(&x, k), 1);
        assert_eq!(root_entry(&x, k, 0), Some(0x1_0000_0000));
        assert_eq!(root_entry(&x, k, usize::MAX), None);
    }

    #[test]
    fn madt_structure_rules() {
        // Zero-length structure: Err, never an infinite loop.
        assert_eq!(parse_madt(&madt(&[3, 0, 0, 0])), Err(AcpiError::Malformed));
        assert_eq!(parse_madt(&madt(&[7, 1])), Err(AcpiError::Malformed));
        // Running past the end.
        assert_eq!(parse_madt(&madt(&[0, 8, 0])), Err(AcpiError::Truncated));
        // Lone trailing byte.
        assert_eq!(parse_madt(&madt(&[0])), Err(AcpiError::Truncated));
        // Known type, too short for itself.
        assert_eq!(
            parse_madt(&madt(&[1, 8, 0, 0, 0, 0, 0, 0])),
            Err(AcpiError::Malformed)
        );
        // Unknown type skipped by its own length.
        let m = parse_madt(&madt(&[0x7F, 3, 9, 0, 8, 1, 7, 1, 0, 0, 0])).expect("skips");
        assert_eq!(
            m.cpus(),
            &[CpuEntry {
                apic_id: 7,
                enabled: true
            }]
        );
        // Longer-than-minimum known structures are fine.
        let m = parse_madt(&madt(&[0, 9, 0, 2, 0, 0, 0, 0, 0xEE])).expect("ok");
        assert_eq!(
            m.cpus(),
            &[CpuEntry {
                apic_id: 2,
                enabled: false
            }]
        );
    }

    #[test]
    fn madt_decodes_x2apic_and_nmi_types() {
        let mut e = Vec::new();
        e.extend_from_slice(&[9, 16, 0, 0]);
        e.extend_from_slice(&300u32.to_le_bytes());
        e.extend_from_slice(&1u32.to_le_bytes());
        e.extend_from_slice(&5u32.to_le_bytes());
        e.extend_from_slice(&[0xA, 12, 0x0F, 0x00]);
        e.extend_from_slice(&5u32.to_le_bytes());
        e.extend_from_slice(&[1, 0, 0, 0]);
        e.extend_from_slice(&[3, 8, 0x0D, 0x00]);
        e.extend_from_slice(&23u32.to_le_bytes());
        let m = parse_madt(&madt(&e)).expect("parses");
        assert_eq!(
            m.cpus(),
            &[CpuEntry {
                apic_id: 300,
                enabled: true
            }]
        );
        assert_eq!(
            m.lapic_nmis[0],
            LapicNmi {
                uid: 5,
                polarity: Polarity::ActiveLow,
                trigger: Trigger::Level,
                lint: 1
            }
        );
        assert_eq!(
            m.nmi_sources[0],
            NmiSource {
                gsi: 23,
                polarity: Polarity::ActiveHigh,
                trigger: Trigger::Level
            }
        );
    }

    #[test]
    fn inti_flags_reserved_encodings_rejected() {
        assert_eq!(decode_inti_flags(0b10), None);
        assert_eq!(decode_inti_flags(0b1000), None);
        assert_eq!(
            decode_inti_flags(0),
            Some((Polarity::Conforms, Trigger::Conforms))
        );
        assert_eq!(
            decode_inti_flags(0xF),
            Some((Polarity::ActiveLow, Trigger::Level))
        );
        // An ISO carrying a reserved encoding makes the table malformed.
        assert_eq!(
            parse_madt(&madt(&[2, 10, 0, 0, 2, 0, 0, 0, 0b10, 0])),
            Err(AcpiError::Malformed)
        );
    }

    #[test]
    fn duplicate_override_and_capacity_are_errors() {
        let iso = [2u8, 10, 0, 0, 2, 0, 0, 0, 0, 0];
        let mut e = Vec::new();
        e.extend_from_slice(&iso);
        e.extend_from_slice(&iso);
        assert_eq!(parse_madt(&madt(&e)), Err(AcpiError::Malformed));

        let mut e = Vec::new();
        for i in 0..=MAX_IOAPICS as u8 {
            e.extend_from_slice(&[1, 12, i, 0, 0, 0, 0xC0, 0xFE, 0, 0, 0, 0]);
        }
        assert_eq!(parse_madt(&madt(&e)), Err(AcpiError::Capacity));
    }

    #[test]
    fn cpus_beyond_capacity_are_counted_not_stored() {
        let mut e = Vec::new();
        for i in 0..70u8 {
            e.extend_from_slice(&[0, 8, i, i, 1, 0, 0, 0]);
        }
        let m = parse_madt(&madt(&e)).expect("parses");
        assert_eq!(m.cpus_seen, 70);
        assert_eq!(m.cpus().len(), MAX_CPUS);
        assert_eq!(m.cpus()[63].apic_id, 63);
    }

    /// Deterministic mutation fuzz: random byte flips, length-field rewrites and
    /// truncations of QEMU's MADT, each re-checksummed half the time so the
    /// mutations reach the structure walk. Every outcome must be `Ok`/`Err` with
    /// counts within capacity — a panic fails the test.
    #[test]
    fn mutation_fuzz_never_panics() {
        let iters = if cfg!(miri) { 300 } else { 200_000 };
        let mut s: u64 = 0x5EED_1234_ABCD_0001;
        let mut next = move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        let mut oks = 0u32;
        for _ in 0..iters {
            let mut t = QEMU_Q35_MADT.to_vec();
            let flips = (next() % 6) + 1;
            for _ in 0..flips {
                let r = next();
                let i = (r as usize) % t.len();
                match (r >> 32) % 4 {
                    0 => t[i] = (r >> 40) as u8,
                    1 => t[i] ^= 1 << ((r >> 40) % 8),
                    2 if i >= MADT_ENTRIES_OFFSET => t[i] = ((r >> 40) % 20) as u8,
                    _ => t[i] = t[i].wrapping_add(1),
                }
            }
            if next() % 4 == 0 {
                let cut = (next() as usize) % (t.len() + 1);
                t.truncate(cut);
            }
            if next() % 2 == 0 && t.len() >= 10 {
                fix_checksum(&mut t);
            }
            if let Ok(m) = parse_madt(&t) {
                oks += 1;
                assert!(m.ioapics().len() <= MAX_IOAPICS);
                assert!(m.overrides().len() <= MAX_OVERRIDES);
                assert!(usize::from(m.lapic_nmi_count) <= MAX_LAPIC_NMIS);
                assert!(usize::from(m.nmi_source_count) <= MAX_NMI_SOURCES);
            }
        }
        if !cfg!(miri) {
            // The fuzz must actually reach the decoder, not stop at the checksum.
            assert!(oks > 20_000, "only {oks} mutants parsed");
        }
    }

    /// End-to-end `discover_madt` over a synthetic arena (index == phys).
    mod discover {
        use super::*;

        fn place(arena: &mut [u8], at: usize, bytes: &[u8]) {
            arena[at..at + bytes.len()].copy_from_slice(bytes);
        }

        fn reader(arena: &[u8]) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
            move |phys, buf| {
                let Ok(start) = usize::try_from(phys) else {
                    return false;
                };
                let Some(src) = start
                    .checked_add(buf.len())
                    .and_then(|e| arena.get(start..e))
                else {
                    return false;
                };
                buf.copy_from_slice(src);
                true
            }
        }

        #[test]
        fn rsdt_chain_finds_qemu_madt_after_another_table() {
            let mut arena = alloc::vec![0u8; 4096];
            place(&mut arena, 0, &rsdp_v1(64));
            let mut body = Vec::new();
            body.extend_from_slice(&512u32.to_le_bytes());
            body.extend_from_slice(&1024u32.to_le_bytes());
            body.extend_from_slice(&0xFFFF_0000u32.to_le_bytes()); // unreadable: skipped
            place(&mut arena, 64, &sdt(&RSDT_SIGNATURE, &body));
            place(&mut arena, 512, &sdt(b"FACP", &[0; 8]));
            place(&mut arena, 1024, QEMU_Q35_MADT);
            let (mut rb, mut mb) = ([0u8; 256], [0u8; 512]);
            let m = discover_madt(0, reader(&arena), &mut rb, &mut mb).expect("walks");
            assert_eq!(m.ioapic_count, 1);
            assert_eq!(m.override_count, 5);
        }

        #[test]
        fn xsdt_chain() {
            let mut arena = alloc::vec![0u8; 4096];
            place(&mut arena, 16, &rsdp_v2(128));
            place(
                &mut arena,
                128,
                &sdt(&XSDT_SIGNATURE, &2048u64.to_le_bytes()),
            );
            place(&mut arena, 2048, QEMU_Q35_MADT);
            let (mut rb, mut mb) = ([0u8; 256], [0u8; 512]);
            assert!(discover_madt(16, reader(&arena), &mut rb, &mut mb).is_ok());
        }

        #[test]
        fn errors_are_reported() {
            let arena = alloc::vec![0u8; 64];
            let (mut rb, mut mb) = ([0u8; 256], [0u8; 512]);
            assert_eq!(
                discover_madt(4096, reader(&arena), &mut rb, &mut mb),
                Err(AcpiError::Unreadable)
            );
            assert_eq!(
                discover_madt(0, reader(&arena), &mut rb, &mut mb),
                Err(AcpiError::BadRsdpSignature)
            );

            let mut arena = alloc::vec![0u8; 4096];
            place(&mut arena, 0, &rsdp_v1(64));
            place(&mut arena, 64, &sdt(&RSDT_SIGNATURE, &512u32.to_le_bytes()));
            place(&mut arena, 512, QEMU_Q35_MADT);
            let mut tiny = [0u8; 100];
            assert_eq!(
                discover_madt(0, reader(&arena), &mut rb, &mut tiny),
                Err(AcpiError::TooLarge)
            );
            arena[600] ^= 0xFF; // corrupt the MADT: reported, not skipped
            assert_eq!(
                discover_madt(0, reader(&arena), &mut rb, &mut mb),
                Err(AcpiError::BadChecksum)
            );

            let mut arena = alloc::vec![0u8; 4096];
            place(&mut arena, 0, &rsdp_v1(64));
            place(&mut arena, 64, &sdt(&RSDT_SIGNATURE, &512u32.to_le_bytes()));
            place(&mut arena, 512, &sdt(b"HPET", &[0; 4]));
            assert_eq!(
                discover_madt(0, reader(&arena), &mut rb, &mut mb),
                Err(AcpiError::NoMadt)
            );
        }
    }
}

/// Kani harnesses: decode totality and bounds over shrunken symbolic tables.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// The structure walk is total over every 56-byte buffer and every length
    /// ≤ 56, never hands out a structure shorter than 2 bytes, and on `Ok` the
    /// structures handed out exactly tile `[44, len)` — contiguous, in order,
    /// nothing skipped, nothing past the end. With [`one_entry_decode_is_total_and_exact`]
    /// (each structure decodes totally) and [`push_respects_capacity`] (no
    /// array overflows) this composes into "`parse_madt_body` is total and
    /// bounded" without model-checking the decoder inside the loop.
    #[kani::proof]
    #[kani::unwind(8)]
    fn madt_walk_is_total_and_tiles() {
        let buf: [u8; 56] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let table = &buf[..len];
        let mut next = MADT_ENTRIES_OFFSET;
        let mut ok_shape = true;
        let r = for_each_entry(table, |e| {
            assert!(e.len() >= 2);
            // Each entry starts where the previous one ended.
            let start = e.as_ptr() as usize - table.as_ptr() as usize;
            ok_shape &= start == next;
            next = start + e.len();
            Ok(())
        });
        if r.is_ok() {
            assert!(ok_shape);
            assert!(next == len.max(MADT_ENTRIES_OFFSET));
        }
    }

    /// `push` never writes past a fixed array and fails exactly at capacity.
    #[kani::proof]
    fn push_respects_capacity() {
        let mut arr = [0u8; 4];
        let mut count: u8 = kani::any();
        kani::assume(count <= 5);
        let before = count;
        let r = push(&mut arr, &mut count, 7);
        if before < 4 {
            assert!(r.is_ok());
            assert_eq!(count, before + 1);
            assert_eq!(arr[usize::from(before)], 7);
        } else {
            assert_eq!(r, Err(AcpiError::Capacity));
            assert_eq!(count, before);
        }
    }

    /// Composed smoke check: the real `parse_madt_body` — header reads, walk
    /// and decoder together — on any 46-byte buffer (one structure slot)
    /// returns without panicking. 48 bytes measured 68 s, over the 60 s rule;
    /// the walk and decode properties are carried by the harnesses above.
    #[kani::proof]
    #[kani::unwind(3)]
    fn madt_body_smoke_46() {
        let buf: [u8; 46] = kani::any();
        if let Ok(m) = parse_madt_body(&buf) {
            assert!(m.ioapic_count == 0 && m.cpus_seen == 0);
        }
    }

    /// A single structure of any type, length and content decodes totally, and
    /// an `Ok` IOAPIC/ISO entry carries exactly the bytes at its fixed offsets.
    #[kani::proof]
    #[kani::unwind(18)]
    fn one_entry_decode_is_total_and_exact() {
        let entry: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume((2..=16).contains(&len));
        let mut info = MadtInfo::EMPTY;
        let r = decode_entry(&entry[..len], &mut info);
        if r.is_ok() && entry[0] == 1 {
            assert!(len >= 12);
            assert_eq!(info.ioapic_count, 1);
            assert_eq!(info.ioapics[0].id, entry[2]);
            assert_eq!(
                info.ioapics[0].gsi_base,
                u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]])
            );
        }
        if r.is_ok() && entry[0] == 2 {
            assert!(len >= 10);
            assert_eq!(info.overrides[0].source, entry[3]);
        }
    }

    /// `parse_rsdp` is total over every 36-byte input and returns a non-zero
    /// root pointer whenever it returns `Ok`.
    #[kani::proof]
    #[kani::unwind(38)]
    fn rsdp_decode_is_total() {
        let buf: [u8; RSDP_V2_LEN] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        if let Ok(root) = parse_rsdp(&buf[..len]) {
            assert!(len >= RSDP_V1_LEN);
            assert!(root.addr() != 0);
        }
    }

    /// `root_entry` never reads out of bounds for any index on any table, and
    /// is `Some` exactly for indices below `root_entry_count`.
    #[kani::proof]
    #[kani::unwind(2)]
    fn root_entry_is_total() {
        let buf: [u8; 52] = kani::any();
        let len: usize = kani::any();
        kani::assume((SDT_HEADER_LEN..=buf.len()).contains(&len));
        let xsdt: bool = kani::any();
        let kind = if xsdt {
            RootTable::Xsdt(1)
        } else {
            RootTable::Rsdt(1)
        };
        let i: usize = kani::any();
        let t = &buf[..len];
        assert_eq!(
            root_entry(t, kind, i).is_some(),
            i < root_entry_count(t, kind)
        );
    }
}
