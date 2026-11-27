//! Resource closure scratch state. Physical admission and content remapping
//! have different keys; both tables and the frontier share one disk quota.
use super::spill::{DiskStack, decode_ref, encode_ref};
use super::temporary::{Budget as TemporaryBudget, ValueGraphTable};
use crate::v1::resources::Budget;
use crate::v1::{ChunkAddress, ObjectHash, ObjectRef, ObjectView, Result};

// Two fixed prefixes (256 records each), their B-tree/key/value allocation
// overhead, the 256-frame stack window, and rehash/I/O scratch. Disk growth
// streams fixed records and never loads an index or an ancestor payload.
const RESIDENT_BYTES: usize = 384 * 1024;
const PREFIX_ENTRIES: usize = 256;
// Valid frame spans fit below this bit. Keep the transient active marker in
// the mapped span rather than widening every disposable content-map record.
const ACTIVE: u32 = 1 << 31;
const _: () = {
    assert!(crate::v1::MAX_CHUNK_SIZE <= 1 << 24);
};

fn byte_fact(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

pub(crate) struct Workspace {
    // One logical record holds the relocated address and active flag together.
    // Reentering another occurrence preserves an already copied address.
    states: ValueGraphTable<12, 32>,
    // Exact physical completion remains separate from content deduplication.
    // A nonzero fact is an authenticated schema-1 byte leaf's length plus one.
    // The maximum byte body and its length-plus-one fact fit in three bytes.
    completed: ValueGraphTable<3>,
    pending: DiskStack<48>,
    #[cfg(test)]
    disk: TemporaryBudget,
}
impl Workspace {
    pub(crate) fn new(budget: &mut Budget) -> Result<Self> {
        budget.reserve_memory(RESIDENT_BYTES)?;
        let disk = TemporaryBudget::new(budget.limits.max_temp_bytes);
        Ok(Self {
            states: ValueGraphTable::with_budget(PREFIX_ENTRIES, disk.clone()),
            completed: ValueGraphTable::with_budget(PREFIX_ENTRIES, disk.clone()),
            pending: DiskStack::with_budget(256, disk.clone())?,
            #[cfg(test)]
            disk,
        })
    }
    pub(crate) fn push(&mut self, r: ObjectRef, expanded: bool, budget: &Budget) -> Result<()> {
        self.push_pending(r, expanded, 0, budget)
    }
    pub(crate) fn push_for_copy(
        &mut self,
        r: ObjectRef,
        byte_length: u32,
        budget: &Budget,
    ) -> Result<()> {
        self.push_pending(r, false, byte_length, budget)
    }
    fn push_pending(
        &mut self,
        r: ObjectRef,
        expanded: bool,
        byte_length: u32,
        budget: &Budget,
    ) -> Result<()> {
        budget.time()?;
        if byte_length as usize > crate::v1::MAX_CHUNK_SIZE - 8 || (expanded && byte_length != 0) {
            return Err(super::corrupt("temporary byte role"));
        }
        let mut bytes = [0; 48];
        bytes[..44].copy_from_slice(&encode_ref(r));
        bytes[44] = expanded as u8;
        bytes[45..].copy_from_slice(&byte_length.to_le_bytes()[..3]);
        self.pending.push_record(bytes)
    }
    #[cfg(test)]
    pub(crate) fn pop(&mut self) -> Result<Option<(ObjectRef, bool)>> {
        Ok(self.pop_for_copy()?.map(|(r, expanded, _)| (r, expanded)))
    }
    pub(crate) fn pop_for_copy(&mut self) -> Result<Option<(ObjectRef, bool, u32)>> {
        self.pending
            .pop_record()?
            .map(|bytes| {
                let expanded = match bytes[44] {
                    0 => false,
                    1 => true,
                    _ => return Err(super::corrupt("temporary traversal record flag")),
                };
                let length = byte_fact(&bytes[45..]);
                if length as usize > crate::v1::MAX_CHUNK_SIZE - 8 || (expanded && length != 0) {
                    return Err(super::corrupt("temporary byte role"));
                }
                Ok((decode_ref(&bytes[..44])?, expanded, length))
            })
            .transpose()
    }
    #[cfg(test)]
    pub(crate) fn completed(&self, r: ObjectRef) -> Result<bool> {
        Ok(self.completed.get(&encode_ref(r))?.is_some())
    }
    pub(crate) fn completed_for_copy(&self, r: ObjectRef, byte_length: u32) -> Result<bool> {
        let Some(fact) = self.completed.get(&encode_ref(r))? else {
            return Ok(false);
        };
        if byte_length != 0 {
            let fact = byte_fact(&fact);
            if fact == 0 {
                return Err(super::corrupt("core child role kind or schema"));
            }
            if fact != byte_length + 1 {
                return Err(super::corrupt("extent byte length"));
            }
        }
        Ok(true)
    }
    pub(crate) fn enter(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        let mut state = self.state(r.hash)?;
        let length = u32::from_le_bytes(state[8..].try_into().unwrap());
        if length & ACTIVE != 0 {
            return Err(super::corrupt("object graph cycle"));
        }
        state[8..].copy_from_slice(&(length | ACTIVE).to_le_bytes());
        let result = self
            .states
            .insert_cancellable(&r.hash.0, &state, &|| budget.time().is_err());
        budget.time()?;
        result
    }
    pub(crate) fn complete(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        let fact = self
            .completed
            .get(&encode_ref(r))?
            .map_or([0; 3], |fact| (&*fact).try_into().unwrap());
        self.complete_fact(r, fact, budget)
    }
    pub(crate) fn complete_for_copy(
        &mut self,
        r: ObjectRef,
        object: ObjectView<'_>,
        budget: &Budget,
    ) -> Result<()> {
        let length = if object.kind == 7 && object.version == 1 && object.children.is_empty() {
            object.bytes.len() as u32 + 1
        } else {
            0
        };
        self.complete_fact(r, length.to_le_bytes()[..3].try_into().unwrap(), budget)
    }
    fn complete_fact(&mut self, r: ObjectRef, fact: [u8; 3], budget: &Budget) -> Result<()> {
        let mut state = self.state(r.hash)?;
        let length = u32::from_le_bytes(state[8..].try_into().unwrap()) & !ACTIVE;
        state[8..].copy_from_slice(&length.to_le_bytes());
        let cancelled = || budget.time().is_err();
        let result = self
            .states
            .insert_cancellable(&r.hash.0, &state, &cancelled)
            .and_then(|()| {
                self.completed
                    .insert_cancellable(&encode_ref(r), &fact, &cancelled)
            });
        budget.time()?;
        result
    }
    pub(crate) fn mapped(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
        let state = self.state(hash)?;
        let length = u32::from_le_bytes(state[8..].try_into().unwrap()) & !ACTIVE;
        Ok((length != 0).then(|| ObjectRef {
            hash,
            address: ChunkAddress {
                offset: u64::from_le_bytes(state[..8].try_into().unwrap()),
                length,
            },
        }))
    }
    pub(crate) fn map(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
        if r.address.length & ACTIVE != 0 {
            return Err(super::corrupt("temporary mapped frame span"));
        }
        let mut state = self.state(r.hash)?;
        state[..8].copy_from_slice(&r.address.offset.to_le_bytes());
        let active = u32::from_le_bytes(state[8..].try_into().unwrap()) & ACTIVE;
        state[8..].copy_from_slice(&(r.address.length | active).to_le_bytes());
        let result = self
            .states
            .insert_cancellable(&r.hash.0, &state, &|| budget.time().is_err());
        budget.time()?;
        result
    }
    fn state(&self, hash: ObjectHash) -> Result<[u8; 12]> {
        let mut state = [0; 12];
        if let Some(value) = self.states.get(&hash.0)? {
            state.copy_from_slice(&value);
        }
        Ok(state)
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
    fn logical_mapping_survives_distinct_occurrences_and_cycle_checks() {
        let mut budget = Budget::new(Limits::default());
        let mut graph = Workspace::new(&mut budget).unwrap();
        let original = reference(1);
        let relocated = ObjectRef {
            address: reference(2).address,
            ..original
        };
        graph.enter(original, &budget).unwrap();
        assert!(graph.mapped(original.hash).unwrap().is_none());
        graph.complete(original, &budget).unwrap();
        graph.map(relocated, &budget).unwrap();
        let other = ObjectRef {
            address: reference(3).address,
            ..original
        };
        assert!(!graph.completed(other).unwrap());
        graph.enter(other, &budget).unwrap();
        assert_eq!(graph.mapped(original.hash).unwrap(), Some(relocated));
        assert!(matches!(
            graph.enter(other, &budget),
            Err(Error::Corrupt(_))
        ));
        graph.complete(other, &budget).unwrap();
        assert!(graph.completed(original).unwrap());
        assert!(graph.completed(other).unwrap());
        assert_eq!(graph.mapped(original.hash).unwrap(), Some(relocated));
    }
    #[test]
    fn packed_states_preserve_active_mappings_and_maximum_byte_lengths() {
        let mut budget = Budget::new(Limits::default());
        let mut graph = Workspace::new(&mut budget).unwrap();
        let length = (crate::v1::MAX_CHUNK_SIZE - 8) as u32;
        let bytes = vec![7; length as usize];
        for index in 0..1025 {
            graph
                .push_for_copy(reference(index), length, &budget)
                .unwrap();
        }
        assert!(
            graph
                .push_for_copy(reference(1025), length + 1, &budget)
                .is_err()
        );
        for index in (0..1025).rev() {
            let r = reference(index);
            assert_eq!(graph.pop_for_copy().unwrap(), Some((r, false, length)));
            graph.enter(r, &budget).unwrap();
            let moved = ObjectRef {
                address: ChunkAddress {
                    offset: 128,
                    length: length + 64,
                },
                ..r
            };
            graph.map(moved, &budget).unwrap();
            assert_eq!(graph.mapped(r.hash).unwrap(), Some(moved));
            assert!(graph.enter(r, &budget).is_err());
            graph
                .complete_for_copy(
                    r,
                    ObjectView {
                        kind: 7,
                        version: 1,
                        bytes: &bytes,
                        children: &[],
                    },
                    &budget,
                )
                .unwrap();
            graph.enter(r, &budget).unwrap();
            graph.complete(r, &budget).unwrap();
        }
        for index in 0..1025 {
            let r = reference(index);
            assert!(graph.completed_for_copy(r, length).unwrap());
            assert!(graph.completed_for_copy(r, length - 1).is_err());
        }
        let r = reference(0);
        let before = graph.mapped(r.hash).unwrap();
        assert!(
            graph
                .map(
                    ObjectRef {
                        address: ChunkAddress {
                            length: ACTIVE,
                            ..r.address
                        },
                        ..r
                    },
                    &budget
                )
                .is_err()
        );
        assert_eq!(graph.mapped(r.hash).unwrap(), before);
        assert!(graph.pop_for_copy().unwrap().is_none());
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

    #[test]
    fn byte_roles_and_exact_completion_facts_survive_spill() {
        let mut budget = Budget::new(Limits::default());
        let mut graph = Workspace::new(&mut budget).unwrap();
        for index in 0..20_000 {
            graph
                .push_for_copy(reference(index), (index % 32 + 1) as u32, &budget)
                .unwrap();
        }
        let bytes = [7; 32];
        for index in (0..20_000).rev() {
            let r = reference(index);
            let length = (index % 32 + 1) as u32;
            assert_eq!(graph.pop_for_copy().unwrap(), Some((r, false, length)));
            assert!(!graph.completed_for_copy(r, length).unwrap());
            graph.enter(r, &budget).unwrap();
            graph
                .complete_for_copy(
                    r,
                    ObjectView {
                        kind: 7,
                        version: 1,
                        bytes: &bytes[..length as usize],
                        children: &[],
                    },
                    &budget,
                )
                .unwrap();
        }
        assert!(graph.disk.statistics().peak_reserved_bytes > 1 << 20);
        for index in 0..20_000 {
            let r = reference(index);
            let length = (index % 32 + 1) as u32;
            graph.complete(r, &budget).unwrap();
            assert!(graph.completed_for_copy(r, length).unwrap());
            assert!(graph.completed_for_copy(r, length + 1).is_err());
            let other = ObjectRef {
                address: reference(index + 20_000).address,
                ..r
            };
            assert!(!graph.completed_for_copy(other, length).unwrap());
        }
        assert!(graph.pop_for_copy().unwrap().is_none());
    }
}
