//! Kernel-service capabilities on the bus — the FS-1c wiring
//! (`docs/specs/2026-09-18-sentinelfs-design.md` §9; component-model spec §8;
//! threat entries T-STO-* in `docs/security/threat-model.md` §6).
//!
//! A kernel service (today only storage, `ServiceId::Storage`) is the
//! authority over its own capabilities: the kernel grants them, it holds no
//! capability to do so. Once granted, a service capability is an ordinary
//! table entry — delegated by `Ctx::delegate` (the child is checked `⊑` the
//! parent by the one predicate, so a storage delegate never amplifies),
//! revoked and released by the same calls, freed at `terminate`, and checked
//! by `CapSpace::check` with an `Access::Storage`. Presenting one to a storage
//! service, and quota accounting, are FS-4.
//!
//! **Kernel-only, by design, until FS-4.** PR-2b's manifest requests name
//! *component* services and are routed to instances; no route form reaches a
//! kernel service, and `CapRequest::is_meaningful` refuses any request
//! carrying storage ops or a storage attenuation. So `Target::Service`
//! capabilities are reachable only through this `pub(crate)` function, never
//! from a component manifest — and must stay so until FS-4 adds a route form
//! for kernel services (with its own review). Until then the only caller of
//! [`Host::grant_service`] is the boot proof (`super::storage_proof`).

use crate::cap::deny::Action;
use crate::cap::{CapError, CapIndex, Capability, DenyReason, Target, Tick};
use crate::host::codec::Sender;
use crate::host::{ComponentId, ComponentRuntime, Host, InstanceId, UNBOUND_BUCKET};

impl<R: ComponentRuntime> Host<R> {
    /// The kernel, as the service's authority, grants instance `inst` the
    /// service capability `cap` at tick `now` (read under the host lock).
    /// Deny by default: refused — and logged in the kernel's bucket, as the
    /// recipient's, like a refused manifest grant — unless `inst` is live,
    /// `cap` designates a kernel service, is well formed, and is not dead on
    /// arrival; `TableFull` when the recipient has no usable slot.
    ///
    /// # Errors
    ///
    /// `CapError::Deny` with `NoSuchSender`, `WrongTarget`, `Malformed` or
    /// `TableFull`, each logged; `CapError::NoSuchTable` (internal, unlogged)
    /// if the instance's slot has no table.
    pub(crate) fn grant_service(
        &mut self,
        inst: InstanceId,
        cap: &Capability,
        now: Tick,
    ) -> Result<CapIndex, CapError> {
        let found = self
            .slot_of(inst)
            .and_then(|slot| Some((slot, self.sender_at(slot)?)));
        let Some((slot, who)) = found else {
            let nobody = Sender {
                instance: inst,
                component: ComponentId::KERNEL,
            };
            return Err(self.refuse_grant(now, nobody, DenyReason::NoSuchSender));
        };
        let reason = if !matches!(cap.target, Target::Service(_)) {
            Some(DenyReason::WrongTarget)
        } else if !cap.is_well_formed() || !cap.is_live(now) {
            Some(DenyReason::Malformed)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(self.refuse_grant(now, who, reason));
        }
        match self.caps.grant(slot, cap, cap) {
            Ok(idx) => Ok(idx),
            Err(CapError::Deny(reason)) => Err(self.refuse_grant(now, who, reason)),
            Err(CapError::TableFull) => Err(self.refuse_grant(now, who, DenyReason::TableFull)),
            // Unreachable (`slot` came from `slot_of`); an internal error, not
            // a full table, and not a denial to log as one.
            Err(CapError::NoSuchTable) => Err(CapError::NoSuchTable),
        }
    }

    fn refuse_grant(&mut self, now: Tick, who: Sender, reason: DenyReason) -> CapError {
        self.deny.record(
            now,
            UNBOUND_BUCKET,
            who,
            CapIndex::KERNEL,
            Action::Grant,
            reason,
        );
        CapError::Deny(reason)
    }
}
