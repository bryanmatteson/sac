//! Minimal builds use a finite resident index; native builds spill exact state.
#[cfg(feature = "native")]
pub(super) use crate::v1::native::graph::Workspace;

#[cfg(not(feature = "native"))]
mod resident {
    use super::super::*;
    use std::collections::{BTreeMap, BTreeSet};
    pub(crate) struct Workspace {
        active: BTreeSet<ObjectHash>,
        completed: BTreeSet<ObjectRef>,
        copied: BTreeMap<ObjectHash, ObjectRef>,
        pending: Vec<(ObjectRef, bool)>,
    }
    impl Workspace {
        pub(crate) fn new(budget: &mut Budget) -> Result<Self> {
            let graph = Self {
                active: BTreeSet::new(),
                completed: BTreeSet::new(),
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
            self.pending.push((r, expanded));
            Ok(())
        }
        pub(crate) fn pop(&mut self) -> Result<Option<(ObjectRef, bool)>> {
            Ok(self.pending.pop())
        }
        pub(crate) fn completed(&self, r: ObjectRef) -> Result<bool> {
            Ok(self.completed.contains(&r))
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
            self.completed.insert(r);
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
