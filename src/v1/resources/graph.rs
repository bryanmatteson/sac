//! Minimal builds use a finite resident index; native builds spill exact state.
#[cfg(feature = "native")]
pub(super) use crate::v1::native::graph::Workspace;

#[cfg(not(feature = "native"))]
mod resident {
    use super::super::*;
    use std::collections::{BTreeMap, BTreeSet};
    pub(crate) struct Workspace {
        active: BTreeSet<ObjectHash>,
        completed: BTreeMap<ObjectRef, u32>,
        copied: BTreeMap<ObjectHash, ObjectRef>,
        pending: Vec<(ObjectRef, bool, u32)>,
    }
    impl Workspace {
        pub(crate) fn new(budget: &mut Budget) -> Result<Self> {
            let graph = Self {
                active: BTreeSet::new(),
                completed: BTreeMap::new(),
                copied: BTreeMap::new(),
                pending: vec![],
            };
            graph.room(budget, 1)?;
            Ok(graph)
        }
        fn room(&self, budget: &Budget, additional: usize) -> Result<()> {
            budget.memory(
                (self.active.len()
                    + self.completed.len()
                    + self.copied.len()
                    + self.pending.len()
                    + additional)
                    .saturating_mul(128)
                    .saturating_add(3 * crate::v1::MAX_CHUNK_SIZE),
            )
        }
        pub(crate) fn push(&mut self, r: ObjectRef, expanded: bool, budget: &Budget) -> Result<()> {
            self.room(budget, 1)?;
            self.pending.push((r, expanded, 0));
            Ok(())
        }
        pub(crate) fn push_for_copy(
            &mut self,
            r: ObjectRef,
            byte_length: u32,
            budget: &Budget,
        ) -> Result<()> {
            self.room(budget, 1)?;
            self.pending.push((r, false, byte_length));
            Ok(())
        }
        pub(crate) fn pop(&mut self) -> Result<Option<(ObjectRef, bool)>> {
            Ok(self.pending.pop().map(|(r, expanded, _)| (r, expanded)))
        }
        pub(crate) fn pop_for_copy(&mut self) -> Result<Option<(ObjectRef, bool, u32)>> {
            Ok(self.pending.pop())
        }
        pub(crate) fn completed(&self, r: ObjectRef) -> Result<bool> {
            Ok(self.completed.contains_key(&r))
        }
        pub(crate) fn completed_for_copy(&self, r: ObjectRef, byte_length: u32) -> Result<bool> {
            let Some(fact) = self.completed.get(&r) else {
                return Ok(false);
            };
            if byte_length != 0 {
                if *fact == 0 {
                    return Err(corrupt("core child role kind or schema"));
                }
                if *fact != byte_length + 1 {
                    return Err(corrupt("extent byte length"));
                }
            }
            Ok(true)
        }
        pub(crate) fn enter(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
            self.room(budget, 1)?;
            if !self.active.insert(r.hash) {
                return Err(corrupt("object graph cycle"));
            }
            Ok(())
        }
        pub(crate) fn complete(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
            self.room(budget, 1)?;
            self.active.remove(&r.hash);
            self.completed.entry(r).or_insert(0);
            Ok(())
        }
        pub(crate) fn complete_for_copy(
            &mut self,
            r: ObjectRef,
            object: ObjectView<'_>,
            budget: &Budget,
        ) -> Result<()> {
            self.room(budget, 1)?;
            self.active.remove(&r.hash);
            let fact = if object.kind == 7 && object.version == 1 && object.children.is_empty() {
                object.bytes.len() as u32 + 1
            } else {
                0
            };
            self.completed.insert(r, fact);
            Ok(())
        }
        pub(crate) fn mapped(&self, hash: ObjectHash) -> Result<Option<ObjectRef>> {
            Ok(self.copied.get(&hash).copied())
        }
        pub(crate) fn map(&mut self, r: ObjectRef, budget: &Budget) -> Result<()> {
            self.room(budget, 1)?;
            self.copied.insert(r.hash, r);
            Ok(())
        }
    }
}
#[cfg(not(feature = "native"))]
pub(super) use resident::Workspace;
