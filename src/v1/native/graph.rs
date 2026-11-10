//! Resource closure scratch state. Physical admission and content remapping
//! have different keys; both tables and the frontier share one disk quota.
use super::spill::{DiskStack, decode_ref, encode_ref};
use super::temporary::{Budget as TemporaryBudget, GraphTable};
use crate::v1::resources::Budget;
use crate::v1::{ObjectHash, ObjectRef, Result};

// Two fixed prefixes (256 records each), their B-tree/key/value allocation
// overhead, the 256-frame stack window, and rehash/I/O scratch. Disk growth
// streams fixed records and never loads an index or an ancestor payload.
const RESIDENT_BYTES: usize = 384 * 1024;
const PREFIX_ENTRIES: usize = 256;

pub(crate) struct Workspace {
    // A 32-byte hash is active/inactive (1/0); a 44-byte physical reference
    // is completed (2). Key length separates the two namespaces exactly.
    states: GraphTable,
    copied: GraphTable,
    pending: DiskStack,
    #[cfg(test)]
    disk: TemporaryBudget,
}
impl Workspace {
    pub(crate) fn new(budget: &mut Budget) -> Result<Self> {
        budget.reserve_memory(RESIDENT_BYTES)?;
        let disk = TemporaryBudget::new(budget.limits.max_temp_bytes);
        Ok(Self {
            states: GraphTable::with_budget(PREFIX_ENTRIES, disk.clone()),
            copied: GraphTable::with_budget(PREFIX_ENTRIES, disk.clone()),
            pending: DiskStack::with_budget(256, disk.clone())?,
            #[cfg(test)]
            disk,
        })
    }
    pub(crate) fn push(&mut self, r: ObjectRef, expanded: bool, budget: &Budget) -> Result<()> {
        budget.time()?;
        self.pending.push(r, expanded)
    }
    pub(crate) fn pop(&mut self) -> Result<Option<(ObjectRef, bool)>> {
        self.pending.pop()
    }
    pub(crate) fn completed(&self, r: ObjectRef) -> Result<bool> {
        Ok(self.states.get(&encode_ref(r))?.is_some())
    }
    pub(crate) fn enter(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        if self.states.get(&r.hash.0)?.as_deref() == Some(&[1]) {
            return Err(super::corrupt("object graph cycle"));
        }
        let result = self
            .states
            .insert_cancellable(&r.hash.0, &[1], &|| budget.time().is_err());
        budget.time()?;
        result
    }
    pub(crate) fn complete(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        let cancelled = || budget.time().is_err();
        let result = self
            .states
            .insert_cancellable(&r.hash.0, &[0], &cancelled)
            .and_then(|()| {
                self.states
                    .insert_cancellable(&encode_ref(r), &[2], &cancelled)
            });
        budget.time()?;
        result
    }
    pub(crate) fn mapped(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
        self.copied
            .get(&hash.0)?
            .map(|bytes| decode_ref(&bytes))
            .transpose()
    }
    pub(crate) fn map(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        let result = self
            .copied
            .insert_cancellable(&r.hash.0, &encode_ref(r), &|| budget.time().is_err());
        budget.time()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::{ChunkAddress, Error, resources::Limits};
    fn reference(i: u64) -> ObjectRef {
        let mut hash = [0; 32];
        hash[..8].copy_from_slice(&i.to_le_bytes());
        ObjectRef {
            hash: ObjectHash(hash),
            address: ChunkAddress {
                offset: 128 + i * 128,
                length: 128,
            },
        }
    }
    #[test]
    fn shared_spill_quota_and_exact_physical_states() {
        let mut budget = Budget::new(Limits {
            max_memory_bytes: 8 << 20,
            max_temp_bytes: 16 << 20,
            ..Limits::default()
        });
        let mut graph = Workspace::new(&mut budget).unwrap();
        for i in 0..20_000 {
            let r = reference(i);
            graph.enter(r, &budget).unwrap();
            graph.push(r, true, &budget).unwrap();
        }
        for i in (0..20_000).rev() {
            let r = reference(i);
            assert_eq!(graph.pop().unwrap(), Some((r, true)));
            graph.complete(r, &budget).unwrap();
            graph.map(r, &budget).unwrap();
            assert!(graph.completed(r).unwrap());
            let mut other = r;
            other.address.offset += 1;
            assert!(!graph.completed(other).unwrap());
            assert_eq!(graph.mapped(r.hash).unwrap(), Some(r));
        }
        let statistics = graph.disk.statistics();
        assert!(statistics.peak_reserved_bytes > 1 << 20);
        assert!(statistics.peak_reserved_bytes <= budget.limits.max_temp_bytes);
        assert!(statistics.read_bytes > 0 && statistics.write_bytes > 0);
        let disk = graph.disk.clone();
        drop(graph);
        assert_eq!(disk.used(), 0);

        let mut budget = Budget::new(Limits {
            max_temp_bytes: 0,
            ..Limits::default()
        });
        let mut graph = Workspace::new(&mut budget).unwrap();
        for i in 0..PREFIX_ENTRIES as u64 {
            graph.enter(reference(i), &budget).unwrap();
        }
        assert!(matches!(
            graph.enter(reference(1_000), &budget),
            Err(Error::Limit("temporary disk bytes"))
        ));
        assert_eq!(graph.disk.statistics().peak_reserved_bytes, 0);
    }
}
