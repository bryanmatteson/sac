//! Disposable bounded-memory closure metadata. Values have fixed width;
//! a fixed resident prefix handles small closures and overflow stays on disk.
use super::temporary::{FixedRecordStack, GraphTable};
use super::*;

pub(super) fn encode_ref(r: ObjectRef) -> [u8; 44] {
    let mut bytes = [0; 44];
    bytes[..32].copy_from_slice(&r.hash.0);
    bytes[32..40].copy_from_slice(&r.address.offset.to_le_bytes());
    bytes[40..].copy_from_slice(&r.address.length.to_le_bytes());
    bytes
}
pub(super) fn decode_ref(bytes: &[u8]) -> Result<ObjectRef> {
    if bytes.len() != 44 {
        return Err(corrupt("temporary object reference"));
    }
    Ok(ObjectRef {
        hash: ObjectHash(bytes[..32].try_into().unwrap()),
        address: ChunkAddress {
            offset: u64::from_le_bytes(bytes[32..40].try_into().unwrap()),
            length: u32::from_le_bytes(bytes[40..44].try_into().unwrap()),
        },
    })
}
pub(super) struct DiskRefs(pub(super) GraphTable);
impl DiskRefs {
    pub(super) fn new() -> Result<Self> {
        Ok(Self(GraphTable::new()?))
    }
    pub(super) fn get(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
        self.0
            .get(&hash.0)?
            .map(|bytes| decode_ref(&bytes))
            .transpose()
    }
    pub(super) fn insert_cancellable(
        &mut self,
        r: ObjectRef,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        self.0
            .insert_cancellable(&r.hash.0, &encode_ref(r), cancelled)?;
        Ok(())
    }
}
// Kept in the same bounded/spilled table as append IDs. A full 44-byte
// parent occurrence key cannot alias the ordinary 32-byte canonical-ID keys.
// This is writer-local append provenance, never verified-layout cache status.
pub(super) fn rewrite_layout(children: &[ObjectRef]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"SAC1/writer-rewrite-layout\0");
    hash.update(&(children.len() as u32).to_le_bytes());
    for child in children {
        hash.update(&encode_ref(*child));
    }
    *hash.finalize().as_bytes()
}
impl DiskRefs {
    pub(super) fn record_rewrite_layout(
        &mut self,
        parent: ObjectRef,
        children: &[ObjectRef],
    ) -> Result<()> {
        // Forty bytes fit the existing 44-byte GraphTable value. Preserve the
        // original physical-byte estimate without another key or resident map.
        let mut value = [0; 40];
        value[..32].copy_from_slice(&rewrite_layout(children));
        let child_bytes: u64 = children.iter().map(|r| u64::from(r.address.length)).sum();
        value[32..].copy_from_slice(&child_bytes.to_le_bytes());
        self.0
            .insert_cancellable(&encode_ref(parent), &value, &|| false)
    }
    pub(super) fn rewrite_layout(&self, parent: ObjectRef) -> Result<Option<([u8; 32], u64)>> {
        self.0
            .get(&encode_ref(parent))?
            .map(|value| {
                if value.len() != 40 {
                    return Err(corrupt("writer rewrite layout"));
                }
                Ok((
                    value[..32].try_into().unwrap(),
                    u64::from_le_bytes(value[32..].try_into().unwrap()),
                ))
            })
            .transpose()
    }
}
pub(super) struct DiskStack {
    entries: Option<FixedRecordStack<45>>,
    resident: Vec<[u8; 45]>,
    resident_limit: u64,
    len: u64,
    budget: temporary::Budget,
    #[cfg(test)]
    spill_batches: u64,
    #[cfg(test)]
    refill_batches: u64,
}
const RESIDENT_STACK_FRAMES: u64 = 256;
impl DiskStack {
    pub(super) fn with_budget(resident_limit: u64, budget: temporary::Budget) -> Result<Self> {
        if resident_limit > RESIDENT_STACK_FRAMES
            || (resident_limit != 0 && (resident_limit < 4 || !resident_limit.is_power_of_two()))
        {
            return Err(Error::Limit("closure resident traversal frames"));
        }
        Ok(Self {
            entries: None,
            resident: Vec::new(),
            resident_limit,
            len: 0,
            budget,
            #[cfg(test)]
            spill_batches: 0,
            #[cfg(test)]
            refill_batches: 0,
        })
    }
    pub(super) fn push(&mut self, r: ObjectRef, expanded: bool) -> Result<()> {
        let next = self
            .len
            .checked_add(1)
            .ok_or(Error::Limit("closure traversal depth"))?;
        let mut bytes = [0; 45];
        bytes[..44].copy_from_slice(&encode_ref(r));
        bytes[44] = expanded as u8;
        if self.resident_limit != 0 {
            // Keep a hot top with room on both sides of the spill boundary.
            // Moving the entire window makes a push/pop pair repeatedly
            // spill and refill it even when traversal depth never advances.
            if self.resident.len() as u64 == self.resident_limit {
                if self.entries.is_none() {
                    self.entries = Some(FixedRecordStack::with_budget(self.budget.clone())?);
                }
                let count = (self.resident_limit / 2).max(1) as usize;
                self.entries
                    .as_mut()
                    .unwrap()
                    .push_many(&self.resident[..count])?;
                let retained = self.resident.len() - count;
                self.resident.copy_within(count.., 0);
                self.resident.truncate(retained);
                #[cfg(test)]
                {
                    self.spill_batches += 1;
                }
            }
            self.resident.push(bytes);
        } else {
            if self.entries.is_none() {
                self.entries = Some(FixedRecordStack::with_budget(self.budget.clone())?);
            }
            self.entries.as_mut().unwrap().push(&bytes)?;
        }
        self.len = next;
        Ok(())
    }
    pub(super) fn pop(&mut self) -> Result<Option<(ObjectRef, bool)>> {
        if self.len == 0 {
            return Ok(None);
        }
        let next = self.len - 1;
        let bytes = if self.resident_limit != 0 {
            if self.resident.is_empty() {
                let count = self.len.min((self.resident_limit / 2).max(1)) as usize;
                let entries = self
                    .entries
                    .as_mut()
                    .ok_or_else(|| corrupt("temporary spilled traversal stack"))?;
                self.resident.resize(count, [0; 45]);
                let result = entries.pop_many(&mut self.resident);
                if let Err(error) = result {
                    self.resident.clear();
                    return Err(error);
                }
                #[cfg(test)]
                {
                    self.refill_batches += 1;
                }
            }
            *self
                .resident
                .last()
                .ok_or_else(|| corrupt("temporary resident traversal stack"))?
        } else {
            self.entries
                .as_mut()
                .ok_or_else(|| corrupt("temporary spilled traversal stack"))?
                .pop()?
                .ok_or_else(|| corrupt("temporary traversal stack"))?
        };
        let expanded = match bytes[44] {
            0 => false,
            1 => true,
            _ => return Err(corrupt("temporary traversal record flag")),
        };
        let reference = decode_ref(&bytes[..44])?;
        if self.resident_limit != 0 {
            self.resident.pop();
        }
        self.len = next;
        Ok(Some((reference, expanded)))
    }
    fn disk_bytes(&self) -> Result<u64> {
        Ok(self
            .entries
            .as_ref()
            .map(FixedRecordStack::disk_bytes)
            .unwrap_or(0))
    }
}

/// Reusable closure copier for exports containing several selected roots.
/// Hash remapping, physical validation and traversal state have fixed resident
/// prefixes and spill larger graphs to disposable local files.
/// One decoded object and one frame's child table are live at a time, with at
/// most 1 MiB of the parents that the traversal is inside. A copier with
/// disk-only metadata keeps no parents.
pub struct ClosureCopy {
    pub(super) copied: DiskRefs,
    pending: DiskStack,
    validated: GraphTable,
    retained: GraphTable,
    retained_roots: Vec<ObjectRef>,
    spilled: bool,
    budget: temporary::Budget,
}
impl ClosureCopy {
    pub fn new() -> Result<Self> {
        Self::new_with_stack_limit(RESIDENT_STACK_FRAMES, false)
    }
    /// Keep all traversal and remapping metadata on disk. A caller retaining
    /// another copier can use this for interleaved repairs without allocating
    /// a second resident graph prefix or resident traversal stack.
    pub fn new_spilled() -> Result<Self> {
        Self::new_with_stack_limit(0, true)
    }
    /// Partition a caller's aggregate traversal allowance between copiers.
    /// Each copier may retain this many pending frames and use this many
    /// validation frames concurrently. Disk-only metadata does not allocate
    /// resident remapping or validation-table prefixes. Limits are fixed at
    /// construction: zero or a power of two from 4 through 256 frames, so Vec
    /// growth also stays inside the requested per-stack allocation bound.
    pub fn new_with_stack_limit(resident_frames: u64, disk_only_metadata: bool) -> Result<Self> {
        Self::with_budget(
            resident_frames,
            disk_only_metadata,
            temporary::Budget::new(temporary::MAX_DISK),
        )
    }
    pub fn new_with_disk_budget(max_bytes: u64) -> Result<Self> {
        Self::with_budget(0, true, temporary::Budget::new(max_bytes))
    }
    fn with_budget(
        resident_frames: u64,
        disk_only_metadata: bool,
        budget: temporary::Budget,
    ) -> Result<Self> {
        let resident = if disk_only_metadata {
            0
        } else {
            GraphTable::RESIDENT_ENTRIES
        };
        Ok(Self {
            copied: DiskRefs(GraphTable::with_budget(resident, budget.clone())),
            pending: DiskStack::with_budget(resident_frames, budget.clone())?,
            validated: GraphTable::with_budget(resident, budget.clone()),
            retained: GraphTable::with_budget(0, budget.clone()),
            retained_roots: Vec::new(),
            spilled: disk_only_metadata,
            budget,
        })
    }
    pub(super) fn mark_validated(
        &mut self,
        reference: ObjectRef,
        cancelled: &impl Fn() -> bool,
    ) -> Result<()> {
        self.validated
            .insert_cancellable(&encode_ref(reference), &[], cancelled)?;
        Ok(())
    }
    pub(super) fn rehint(&self, reference: ObjectRef) -> Result<Option<ObjectRef>> {
        if self.validated.get(&encode_ref(reference))?.is_none() {
            return Ok(None);
        }
        self.copied.get(reference.hash)
    }
    pub(super) fn has_no_children(&self, hash: ObjectHash) -> Result<bool> {
        // Hash keys (32 bytes) are disjoint from physical-validation keys
        // (44 bytes). The existing bounded table also retains this immutable
        // canonical property without keeping decoded payloads resident.
        Ok(self.validated.get(&hash.0)?.as_deref() == Some(&[0]))
    }
    pub fn disk_bytes(&self) -> Result<u64> {
        Ok(self.copied.0.disk_bytes()?
            + self.pending.disk_bytes()?
            + self.validated.disk_bytes()?
            + self.retained.disk_bytes()?)
    }
    pub(super) fn temporary_budget(&self) -> temporary::Budget {
        self.budget.clone()
    }
    pub(super) fn attach_aggregate_budget(&self, budget: temporary::Budget) -> Result<()> {
        self.budget.attach_aggregate(budget)
    }
    pub fn temporary_statistics(&self) -> super::TemporaryIoStatistics {
        self.budget.statistics()
    }
    /// Track at most eight selected target component roots across projections.
    /// Adds precede releases, so unchanged DAG subtrees are not revisited. Returns
    /// at most 512 objects whose final root-reachability count became zero;
    /// callers can account their obsolete public representations as tail garbage.
    /// The first call seeds the roots and returns no removals. Refcounts and the
    /// traversal stack spill under this copier's existing aggregate scratch quota.
    /// Roots must already be authenticated by this copier or candidate validation.
    /// Any failure (including cancellation/large removal) invalidates this tracker:
    /// abandon the candidate rather than retrying with its partially changed counts.
    pub fn update_retained_roots<S: ObjectStore + ?Sized>(
        &mut self,
        target: &S,
        roots: &[ObjectRef],
        cancelled: &impl Fn() -> bool,
    ) -> Result<Vec<ObjectRef>> {
        if roots.len() > 8 {
            return Err(Error::Limit("selected component roots"));
        }
        let mut removed = Vec::new();
        let mut stack = DiskStack::with_budget(self.pending.resident_limit, self.budget.clone())?;
        for (add, root) in roots
            .iter()
            .map(|r| (true, *r))
            .chain(self.retained_roots.iter().map(|r| (false, *r)))
        {
            stack.push(root, false)?;
            while let Some((reference, _)) = stack.pop()? {
                if cancelled() {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
                }
                let previous = self.retained.get(&reference.hash.0)?;
                let count = previous.as_ref().map_or(0, |value| {
                    u64::from_le_bytes(value[..8].try_into().unwrap())
                });
                let next = if add {
                    count.checked_add(1)
                } else {
                    count.checked_sub(1)
                }
                .ok_or_else(|| corrupt("selected component reference count"))?;
                self.retained.insert_cancellable(
                    &reference.hash.0,
                    &next.to_le_bytes(),
                    cancelled,
                )?;
                if add && count > 0 || !add && next > 0 {
                    continue;
                }
                if !add {
                    if removed.len() == 512 {
                        return Err(Error::Limit("selected component removals"));
                    }
                    removed.push(reference);
                }
                // Copying already authenticated this immutable canonical leaf.
                // It has no outgoing counts to update. Avoid reading and
                // hashing large byte payloads again merely to discover that.
                if self.has_no_children(reference.hash)? {
                    continue;
                }
                let object = target.get_verified_shared(reference)?;
                for child in object.children.iter().rev() {
                    stack.push(*child, false)?;
                }
            }
        }
        self.retained_roots = roots.to_vec();
        Ok(removed)
    }
    pub fn copy_root<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
        &mut self,
        source: &S,
        destination: &mut D,
        root: ObjectRef,
    ) -> Result<ObjectRef> {
        self.copy_root_reusing(source, destination, root, |_, _| Ok(None))
    }
    /// Copy staged parents while reusing authenticated durable boundaries.
    /// The resolver must attest the entire source subtree through a retained
    /// generation capability (NativeStore::rehint), not a hash-only lookup.
    /// It is called for each distinct physical reference before content dedup.
    pub fn copy_root_reusing<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
        &mut self,
        source: &S,
        destination: &mut D,
        root: ObjectRef,
        resolve: impl FnMut(&D, ObjectRef) -> Result<Option<ObjectRef>>,
    ) -> Result<ObjectRef> {
        self.copy_root_reusing_cancellable(source, destination, root, resolve, &|| false)
    }
    pub fn copy_root_cancellable<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
        &mut self,
        source: &S,
        destination: &mut D,
        root: ObjectRef,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ObjectRef> {
        self.copy_root_reusing_cancellable(source, destination, root, |_, _| Ok(None), cancelled)
    }
    /// [`Self::copy_root_reusing`] with cooperative cancellation. The same
    /// attestation rule applies to `resolve`.
    pub fn copy_root_reusing_cancellable<S: ObjectStore + ?Sized, D: ObjectStore + ?Sized>(
        &mut self,
        source: &S,
        destination: &mut D,
        root: ObjectRef,
        mut resolve: impl FnMut(&D, ObjectRef) -> Result<Option<ObjectRef>>,
        cancelled: &impl Fn() -> bool,
    ) -> Result<ObjectRef> {
        // Validate each physical occurrence and copy in the same postorder
        // traversal. A canonical-ID hit never skips a new occurrence's edges.
        // In particular, large childless byte frames are read only once.
        let mut active = GraphTable::with_budget(
            if self.spilled {
                0
            } else {
                GraphTable::RESIDENT_ENTRIES
            },
            self.budget.clone(),
        );
        // The parents that the traversal is inside, newest last. A parent
        // returns after all its children; keeping it here avoids a second
        // read and authentication when the source cache has released it.
        // The retained canonical bytes have a fixed limit, and a copier with
        // disk-only metadata retains none.
        const RETAINED_PARENT_BYTES: usize = 1024 * 1024;
        let retain = if self.spilled {
            0
        } else {
            RETAINED_PARENT_BYTES
        };
        let mut parents = std::collections::VecDeque::<(ObjectRef, VerifiedObject)>::new();
        let mut parent_bytes = 0usize;
        let result = (|| {
            self.pending.push(root, false)?;
            while let Some((reference, expanded)) = self.pending.pop()? {
                if cancelled() {
                    return Err(std::io::Error::from(std::io::ErrorKind::Interrupted).into());
                }
                let key = encode_ref(reference);
                if !expanded {
                    if self.validated.get(&key)?.is_some()
                        && self.copied.get(reference.hash)?.is_some()
                    {
                        continue;
                    }
                    if active.get(&key)?.is_some() {
                        return Err(corrupt("physical child cycle"));
                    }
                    if let Some(rewritten) = resolve(destination, reference)? {
                        if rewritten.hash != reference.hash {
                            return Err(corrupt("reused closure identity"));
                        }
                        destination.validate_reference(rewritten)?;
                        self.copied.insert_cancellable(rewritten, cancelled)?;
                        self.validated.insert_cancellable(&key, &[], cancelled)?;
                        continue;
                    }
                }
                let retained = if expanded
                    && parents
                        .back()
                        .is_some_and(|(parent, _)| *parent == reference)
                {
                    let (_, verified) = parents.pop_back().unwrap();
                    parent_bytes -= verified.object().canonical_len();
                    Some(verified)
                } else {
                    None
                };
                let verified = match retained {
                    Some(verified) => verified,
                    None => source.verified_object(reference)?,
                };
                let object = verified.object();
                if !expanded {
                    validate_core_edges(object, |child| {
                        if cancelled() {
                            return Err(
                                std::io::Error::from(std::io::ErrorKind::Interrupted).into()
                            );
                        }
                        source.get_verified_shared(child)
                    })?;
                    if !object.children.is_empty() {
                        active.insert_cancellable(&key, &[1], cancelled)?;
                        self.pending.push(reference, true)?;
                        for child in object.children.iter().rev() {
                            self.pending.push(*child, false)?;
                        }
                        let size = object.canonical_len();
                        if size <= retain {
                            parent_bytes += size;
                            parents.push_back((reference, verified));
                            while parent_bytes > retain {
                                let Some((_, oldest)) = parents.pop_front() else {
                                    break;
                                };
                                parent_bytes -= oldest.object().canonical_len();
                            }
                        }
                        continue;
                    }
                }
                // All strong child occurrences passed their own admission before
                // this canonical deduplication. Only completed subtrees enter the
                // reusable physical-validation table.
                if self.copied.get(reference.hash)?.is_none() {
                    let children = object
                        .children
                        .iter()
                        .map(|child| {
                            self.copied
                                .get(child.hash)?
                                .ok_or_else(|| corrupt("closure child missing"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    let rewritten = destination.put_verified(&verified, &children)?;
                    if rewritten.hash != reference.hash {
                        return Err(corrupt("copy identity"));
                    }
                    if children.is_empty() {
                        self.validated
                            .insert_cancellable(&reference.hash.0, &[0], cancelled)?;
                    }
                    self.copied.insert_cancellable(rewritten, cancelled)?;
                }
                self.validated.insert_cancellable(&key, &[], cancelled)?;
            }
            self.copied
                .get(root.hash)?
                .ok_or_else(|| corrupt("copied root missing"))
        })();
        if result.is_err() {
            // A failed source or cancellation must not leave ancestor frames to
            // be consumed by the next selected root. Completed mappings remain
            // reusable; the failed subtree never received validation authority.
            self.pending =
                DiskStack::with_budget(self.pending.resident_limit, self.budget.clone())?;
        }
        result
    }
}
