use super::tree::{self, DirectoryNode, Entry, EntryData, FileData};
use super::*;
use std::io::Write;

#[derive(Clone, Debug)]
pub struct DirectoryValidated {
    root: ObjectRef,
    source: usize,
}
#[derive(Clone, Debug)]
pub enum Lookup {
    Found {
        entry: ResourceEntry,
        directory_validated: bool,
    },
    NoMatchUnverified,
    NotFound,
}
#[derive(Clone, Debug, Default)]
pub struct VerificationReport {
    pub snapshot_id: [u8; 32],
    pub root_admitted: bool,
    pub content_verified: bool,
    pub physical_checked: bool,
    pub core_checked: bool,
    pub profile_checked: bool,
    pub trusted: bool,
    pub entries: u64,
    pub files: u64,
    pub logical_bytes: u64,
}

pub struct ArchiveReader<'a, S: ObjectStore + ?Sized> {
    pub(crate) store: &'a S,
    pub(crate) snapshot: ObjectRef,
    pub(crate) directory: ObjectRef,
    pub(crate) limits: Limits,
    pub(crate) has_profiles: bool,
    // Row positions of the directory pages that lookups have examined.
    pub(crate) rows: std::sync::Mutex<super::pages::RowIndexes>,
}
impl<'a, S: ObjectStore + ?Sized> ArchiveReader<'a, S> {
    pub fn open(store: &'a S, snapshot: ObjectRef, limits: Limits) -> Result<Self> {
        let mut budget = Budget::new(limits.clone());
        let object = budget.get(store, snapshot)?;
        if object.kind != 2 || object.version != 1 {
            return Err(corrupt("expected snapshot schema 1"));
        }
        let body = cbor::decode(&object.bytes)?;
        let fields = values(&body)?;
        if fields.len() != 3 {
            return Err(corrupt("snapshot arity"));
        }
        let directory = child(&object, &fields[0])?;
        budget.check_reference(snapshot, directory)?;
        for feature in values(&fields[2])? {
            let f = values(feature)?;
            if f.len() != 4 {
                return Err(corrupt("capability arity"));
            }
            if f[0] == Value::Null && f[3] == Value::Bool(true) {
                return Err(Error::Unsupported(format!(
                    "required core capability {:?}",
                    f[1]
                )));
            }
        }
        Ok(Self {
            store,
            snapshot,
            directory,
            limits,
            has_profiles: !values(&fields[1])?.is_empty(),
            rows: Default::default(),
        })
    }
    pub fn snapshot(&self) -> ObjectRef {
        self.snapshot
    }
    pub fn directory_root(&self) -> ObjectRef {
        self.directory
    }
    pub fn limits(&self) -> &Limits {
        &self.limits
    }
    pub fn lookup(&self, path: &[Vec<u8>]) -> Result<Lookup> {
        let mut budget = Budget::new(self.limits.clone());
        match self.find(path, &mut budget)? {
            Some(entry) => Ok(Lookup::Found {
                entry: entry.public(path.to_vec()),
                directory_validated: false,
            }),
            None => Ok(Lookup::NoMatchUnverified),
        }
    }
    /// Resolve a route without copying names, metadata or inline contents.
    /// The result pins one authenticated page. A missing route does not certify
    /// absence from an otherwise unvalidated directory index.
    pub fn lookup_shared(&self, path: &[Vec<u8>]) -> Result<Option<ResourceView>> {
        let mut budget = Budget::new(self.limits.clone());
        Ok(self
            .find_shared(path, &mut budget)?
            .map(|entry| ResourceView { entry }))
    }
    pub fn validate_directory(&self, path: &[Vec<u8>]) -> Result<DirectoryValidated> {
        let mut budget = Budget::new(self.limits.clone());
        let root = if path.is_empty() {
            self.directory
        } else {
            let entry = self
                .find(path, &mut budget)?
                .ok_or_else(|| corrupt("directory route has no match"))?;
            match entry.data {
                EntryData::Directory(r) => r,
                _ => return Err(corrupt("expected directory")),
            }
        };
        self.walk_directory(root, None, None, None, &mut budget, 0, &mut |_, _| Ok(()))?;
        Ok(DirectoryValidated {
            root,
            source: self.source_id(),
        })
    }
    pub fn lookup_validated(&self, directory: &DirectoryValidated, name: &[u8]) -> Result<Lookup> {
        check_key(name)?;
        if directory.source != self.source_id() {
            return Err(corrupt("directory token belongs to another source"));
        }
        let mut budget = Budget::new(self.limits.clone());
        match tree::lookup_entry(self.store, directory.root, name, &mut budget)? {
            Some(entry) => Ok(Lookup::Found {
                entry: entry.public(vec![name.to_vec()]),
                directory_validated: true,
            }),
            None => Ok(Lookup::NotFound),
        }
    }
    fn source_id(&self) -> usize {
        self.store as *const S as *const () as usize
    }
    pub(crate) fn find(&self, path: &[Vec<u8>], budget: &mut Budget) -> Result<Option<Entry>> {
        self.find_shared(path, budget)?
            .map(|entry| entry.owned())
            .transpose()
    }
    fn find_shared(
        &self,
        path: &[Vec<u8>],
        budget: &mut Budget,
    ) -> Result<Option<super::pages::SharedEntry>> {
        validate_path(path, &self.limits)?;
        let mut root = self.directory;
        for (i, name) in path.iter().enumerate() {
            budget.depth(i)?;
            let Some(entry) =
                super::pages::lookup(self.store, root, name, budget, Some(&self.rows))?
            else {
                return Ok(None);
            };
            if i + 1 == path.len() {
                return Ok(Some(entry));
            }
            let [_, kind, _, value] = entry.fields()?;
            if kind.uint()? != 1 {
                return Err(corrupt("path component is not a directory"));
            }
            root = entry.child(value)?;
        }
        unreachable!()
    }
    /// Resolve a file once. The handle pins its authenticated directory page.
    pub fn open_file(&self, path: &[Vec<u8>]) -> Result<Option<OpenedFile<'_, 'a, S>>> {
        let mut budget = Budget::new(self.limits.clone());
        let Some(entry) = self.find_shared(path, &mut budget)? else {
            return Ok(None);
        };
        if entry.fields()?[1].uint()? != 0 {
            return Err(corrupt("expected regular file"));
        }
        Ok(Some(OpenedFile {
            archive: self,
            entry,
        }))
    }
    /// Read into existing caller storage, without allocating an output buffer.
    pub fn read_range_into(&self, path: &[Vec<u8>], offset: u64, output: &mut [u8]) -> Result<()> {
        let mut budget = Budget::new(self.limits.clone());
        let entry = self
            .find_shared(path, &mut budget)?
            .ok_or_else(|| corrupt("resource route has no match"))?;
        self.read_shared(
            &entry,
            offset,
            output.len() as u64,
            &mut &mut *output,
            &mut budget,
        )
    }
    fn read_shared<W: Write>(
        &self,
        entry: &super::pages::SharedEntry,
        offset: u64,
        length: u64,
        output: &mut W,
        budget: &mut Budget,
    ) -> Result<()> {
        let [_, kind, _, value] = entry.fields()?;
        if kind.uint()? != 0 {
            return Err(corrupt("expected regular file"));
        }
        let [file_length, storage, data] = value.fields()?;
        let file_length = file_length.uint()?;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| corrupt("requested range overflow"))?;
        if end > file_length {
            return Err(corrupt("requested range beyond file"));
        }
        if storage.uint()? == 0 {
            output.write_all(&data.bytes()?[offset as usize..end as usize])?;
        } else {
            self.extents(
                entry.child(data)?,
                file_length,
                None,
                offset,
                end,
                output,
                budget,
                0,
            )?;
        }
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<ResourceEntry>> {
        let mut result = Vec::new();
        let mut resident = 0usize;
        self.visit_entries(&mut |entry| {
            resident = resident
                .checked_add(
                    192 + entry.path.iter().map(Vec::len).sum::<usize>()
                        + cbor::encoded_len(&entry.metadata),
                )
                .ok_or(Error::Limit("listing memory"))?;
            if resident > self.limits.max_memory_bytes {
                return Err(Error::Limit("listing memory; use visit_entries"));
            }
            result.push(entry);
            Ok(())
        })?;
        Ok(result)
    }
    /// Enumerate in bytewise path order while holding only the active tree path.
    pub fn visit_entries<F: FnMut(ResourceEntry) -> Result<()>>(
        &self,
        visitor: &mut F,
    ) -> Result<()> {
        let mut budget = Budget::new(self.limits.clone());
        self.visit_internal(&mut budget, true, &mut |entry, _| visitor(entry))
    }
    pub(crate) fn visit_internal<F: FnMut(ResourceEntry, &mut Budget) -> Result<()>>(
        &self,
        budget: &mut Budget,
        reserve: bool,
        visitor: &mut F,
    ) -> Result<()> {
        self.visit_raw_with_budget(budget, reserve, &mut |path, entry, budget| {
            visitor(entry.public(path.to_vec()), budget)
        })
    }
    /// Internal consumers retain the storage tuple already authenticated by the
    /// directory walk instead of reparsing a directory route for every file.
    pub(crate) fn visit_raw_with_budget<
        F: FnMut(&ResourcePath, Entry, &mut Budget) -> Result<()>,
    >(
        &self,
        budget: &mut Budget,
        reserve: bool,
        visitor: &mut F,
    ) -> Result<()> {
        self.visit_tree(self.directory, &mut Vec::new(), budget, reserve, visitor)
    }
    fn visit_tree<F: FnMut(&ResourcePath, Entry, &mut Budget) -> Result<()>>(
        &self,
        root: ObjectRef,
        path: &mut ResourcePath,
        budget: &mut Budget,
        reserve: bool,
        visitor: &mut F,
    ) -> Result<()> {
        budget.depth(path.len())?;
        budget.memory((path.len() + 1).saturating_mul(DIRECTORY_LEAF_LIMIT * 4))?;
        self.walk_directory(root, None, None, None, budget, 0, &mut |entry, budget| {
            path.push(entry.name.clone());
            let logical = match &entry.data {
                EntryData::File { length, .. } => *length,
                _ => 0,
            };
            if reserve {
                budget.entry(logical)?;
            }
            let child = match &entry.data {
                EntryData::Directory(child) => Some(*child),
                _ => None,
            };
            visitor(path, entry, budget)?;
            if let Some(child) = child {
                self.visit_tree(child, path, budget, reserve, visitor)?;
            }
            path.pop();
            Ok(())
        })
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "tree traversal carries explicit inherited geometry and one operation budget"
    )]
    fn walk_directory<F>(
        &self,
        root: ObjectRef,
        expected_height: Option<u64>,
        lower: Option<&[u8]>,
        upper: Option<&[u8]>,
        budget: &mut Budget,
        depth: usize,
        visitor: &mut F,
    ) -> Result<()>
    where
        F: FnMut(Entry, &mut Budget) -> Result<()>,
    {
        budget.depth(depth)?;
        budget.edge()?;
        let node = tree::directory(budget.get(self.store, root)?.as_ref())?;
        match node {
            DirectoryNode::Leaf(entries) => {
                if expected_height.is_some_and(|h| h != 0) {
                    return Err(corrupt("directory height mismatch"));
                }
                tree::check_interval(&entries, lower, upper)?;
                for entry in entries {
                    visitor(entry, budget)?;
                }
            }
            DirectoryNode::Branch { height, fences } => {
                if expected_height.is_some_and(|h| h != height) {
                    return Err(corrupt("directory branch height mismatch"));
                }
                if upper.is_some_and(|u| fences.last().unwrap().0.as_slice() != u)
                    || lower.is_some_and(|l| fences[0].0.as_slice() <= l)
                {
                    return Err(corrupt("directory branch interval mismatch"));
                }
                let mut previous = lower;
                for (key, reference) in &fences {
                    budget.check_reference(root, *reference)?;
                    self.walk_directory(
                        *reference,
                        Some(height - 1),
                        previous,
                        Some(key),
                        budget,
                        depth + 1,
                        visitor,
                    )?;
                    previous = Some(key);
                }
            }
        }
        Ok(())
    }
    pub fn read_range(&self, path: &[Vec<u8>], offset: u64, length: usize) -> Result<Vec<u8>> {
        if length > self.limits.max_memory_bytes / 2 {
            return Err(Error::Limit("range output memory"));
        }
        let mut budget = Budget::new(self.limits.clone());
        let entry = self
            .find(path, &mut budget)?
            .ok_or_else(|| corrupt("resource route has no match"))?;
        let mut output = Vec::with_capacity(length);
        self.read_entry(&entry, offset, length as u64, &mut output, &mut budget)?;
        Ok(output)
    }
    /// Resolve one route and read that authenticated descriptor without a
    /// second directory lookup. A miss is unverified absence, as in `lookup`.
    pub fn read_file_bounded(
        &self,
        path: &[Vec<u8>],
        max_length: usize,
    ) -> Result<Option<(ResourceEntry, Vec<u8>)>> {
        let mut budget = Budget::new(self.limits.clone());
        let Some(entry) = self.find(path, &mut budget)? else {
            return Ok(None);
        };
        let EntryData::File { length, .. } = &entry.data else {
            return Err(corrupt("expected regular file"));
        };
        if *length > max_length as u64 || *length > (self.limits.max_memory_bytes / 2) as u64 {
            return Err(Error::Limit("bounded file output memory"));
        }
        let mut output = Vec::with_capacity(
            usize::try_from(*length).map_err(|_| Error::Limit("file output address space"))?,
        );
        budget.entry(*length)?;
        self.read_entry(&entry, 0, *length, &mut output, &mut budget)?;
        Ok(Some((entry.public(path.to_vec()), output)))
    }
    pub fn read_to<W: Write>(&self, path: &[Vec<u8>], output: &mut W) -> Result<()> {
        let mut budget = Budget::new(self.limits.clone());
        let entry = self
            .find_shared(path, &mut budget)?
            .ok_or_else(|| corrupt("resource route has no match"))?;
        let [_, kind, _, value] = entry.fields()?;
        if kind.uint()? != 0 {
            return Err(corrupt("expected regular file"));
        }
        let length = value.fields::<3>()?[0].uint()?;
        budget.entry(length)?;
        self.read_shared(&entry, 0, length, output, &mut budget)
    }

    pub(crate) fn read_entry<W: Write>(
        &self,
        entry: &Entry,
        offset: u64,
        length: u64,
        output: &mut W,
        budget: &mut Budget,
    ) -> Result<()> {
        let EntryData::File {
            length: file_length,
            data,
        } = &entry.data
        else {
            return Err(corrupt("expected regular file"));
        };
        let end = offset
            .checked_add(length)
            .ok_or_else(|| corrupt("requested range overflow"))?;
        if end > *file_length {
            return Err(corrupt("requested range beyond file"));
        }
        match data {
            FileData::Inline(b) => output.write_all(&b[offset as usize..end as usize])?,
            FileData::Extents(root) => {
                self.extents(*root, *file_length, None, offset, end, output, budget, 0)?
            }
        }
        Ok(())
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "tree traversal carries explicit inherited geometry and one operation budget"
    )]
    fn extents<W: Write>(
        &self,
        root: ObjectRef,
        expected_length: u64,
        expected_height: Option<u64>,
        start: u64,
        end: u64,
        output: &mut W,
        budget: &mut Budget,
        depth: usize,
    ) -> Result<()> {
        budget.depth(depth)?;
        budget.edge()?;
        let object = budget.get(self.store, root)?;
        if object.version != 1 || object.canonical_len() > PAGE_LIMIT {
            return Err(corrupt("extent schema or page size"));
        }
        let body = crate::v1::cbor_view::admitted(&object.bytes)?;
        match object.kind {
            5 => {
                if expected_height.is_some_and(|h| h != 0) {
                    return Err(corrupt("extent leaf height"));
                }
                let rows = body.array()?;
                if rows.len() == 0 {
                    return Err(corrupt("empty extent leaf"));
                }
                let mut prior = 0u64;
                for value in rows {
                    let row = value?.fields::<2>()?;
                    let length = row[0].uint()?;
                    if length == 0 {
                        return Err(corrupt("zero extent"));
                    }
                    let next = prior
                        .checked_add(length)
                        .ok_or_else(|| corrupt("extent sum overflow"))?;
                    if start < next && end > prior {
                        let a = start.saturating_sub(prior);
                        let b = end.min(next) - prior;
                        if row[1].is_null() {
                            write_zeros(output, b - a, budget)?;
                        } else {
                            let r = *object
                                .children
                                .get(row[1].uint()? as usize)
                                .ok_or_else(|| corrupt("child index"))?;
                            budget.check_reference(root, r)?;
                            budget.edge()?;
                            let data = budget.get(self.store, r)?;
                            if data.kind != 7
                                || data.version != 1
                                || !data.children.is_empty()
                                || data.bytes.len() as u64 != length
                            {
                                return Err(corrupt("extent byte object length or type"));
                            }
                            output.write_all(&data.bytes[a as usize..b as usize])?;
                        }
                    }
                    prior = next;
                }
                if prior != expected_length {
                    return Err(corrupt("extent root length mismatch"));
                }
            }
            6 => {
                let fields = body.fields::<2>()?;
                let height = fields[0].uint()?;
                if !(1..=16).contains(&height) || expected_height.is_some_and(|h| h != height) {
                    return Err(corrupt("extent branch height"));
                }
                let rows = fields[1].array()?;
                if rows.len() < 2 {
                    return Err(corrupt("unary extent branch"));
                }
                let mut prior = 0u64;
                for value in rows {
                    let row = value?.fields::<2>()?;
                    let next = row[0].uint()?;
                    if next <= prior {
                        return Err(corrupt("unordered extent ends"));
                    }
                    if start < next && end > prior {
                        let r = *object
                            .children
                            .get(row[1].uint()? as usize)
                            .ok_or_else(|| corrupt("child index"))?;
                        budget.check_reference(root, r)?;
                        self.extents(
                            r,
                            next - prior,
                            Some(height - 1),
                            start.saturating_sub(prior),
                            end.min(next) - prior,
                            output,
                            budget,
                            depth + 1,
                        )?;
                    }
                    prior = next;
                }
                if prior != expected_length {
                    return Err(corrupt("extent branch coverage mismatch"));
                }
            }
            _ => return Err(corrupt("expected extent node")),
        }
        Ok(())
    }
    /// Verify the selected snapshot closure. Commit attachments are verified
    /// only when the caller supplies its selected Commit to `verify_commit`.
    pub fn verify(&self) -> Result<VerificationReport> {
        self.verify_from(self.snapshot, Budget::new(self.limits.clone()))
    }
    pub fn verify_commit(&self, commit: ObjectRef) -> Result<VerificationReport> {
        let mut budget = Budget::new(self.limits.clone());
        let object = budget.get(self.store, commit)?;
        if object.kind != 1 || object.version != 1 {
            return Err(corrupt("expected Commit schema 1"));
        }
        let body = cbor::decode(&object.bytes)?;
        let fields = values(&body)?;
        if fields.len() != 3 || child(&object, &fields[0])?.hash != self.snapshot.hash {
            return Err(corrupt("Commit does not select this snapshot"));
        }
        self.verify_from(commit, budget)
    }
    fn verify_from(&self, root: ObjectRef, mut budget: Budget) -> Result<VerificationReport> {
        let mut report = VerificationReport {
            snapshot_id: self.snapshot.hash.0,
            root_admitted: true,
            ..Default::default()
        };
        self.visit_raw_with_budget(&mut budget, true, &mut |_, entry, budget| {
            report.entries += 1;
            if let EntryData::File { length, .. } = &entry.data {
                report.files += 1;
                report.logical_bytes = report
                    .logical_bytes
                    .checked_add(*length)
                    .ok_or(Error::Limit("logical bytes"))?;
                self.read_entry(&entry, 0, *length, &mut std::io::sink(), budget)?;
            }
            Ok(())
        })?;
        let snapshot = budget.get(self.store, self.snapshot)?;
        let snapshot_body = cbor::decode(&snapshot.bytes)?;
        for declaration in values(&values(&snapshot_body)?[1])? {
            let fields = values(declaration)?;
            let root = child(&snapshot, &fields[2])?;
            budget.check_reference(self.snapshot, root)?;
            let profile = budget.get(self.store, root)?;
            if profile.kind != 8 || profile.version != 1 {
                return Err(corrupt("profile declaration must retain kind 8"));
            }
            let envelope = cbor::decode(&profile.bytes)?;
            let envelope = values(&envelope)?;
            if envelope[0] != fields[0]
                || envelope[1] != Value::Text("root".into())
                || envelope[2] != fields[1]
            {
                return Err(corrupt("profile declaration root binding mismatch"));
            }
        }
        // Every distinct physical occurrence is checked. Repeated immutable
        // occurrences share that validation; namespace expansion is charged above.
        self.verify_graph(root, &mut budget)?;
        report.content_verified = true;
        report.core_checked = true;
        report.profile_checked = !self.has_profiles;
        Ok(report)
    }
    fn verify_graph(&self, root: ObjectRef, budget: &mut Budget) -> Result<()> {
        let mut graph = super::graph::Workspace::new(budget)?;
        graph.push(root, false, budget)?;
        while let Some((reference, expanded)) = graph.pop()? {
            budget.time()?;
            if expanded {
                graph.complete(reference, budget)?;
                continue;
            }
            if graph.completed(reference)? {
                continue;
            }
            graph.enter(reference, budget)?;
            let object = budget.get(self.store, reference)?;
            crate::v1::validate_core_edges(&object, |child| budget.get(self.store, child))?;
            for child in &object.children {
                budget.edge()?;
                budget.check_reference(reference, *child)?;
            }
            graph.push(reference, true, budget)?;
            for child in object.children.iter().rev() {
                graph.push(*child, false, budget)?;
            }
        }
        Ok(())
    }
}
pub(crate) fn write_zeros<W: Write>(output: &mut W, mut count: u64, budget: &Budget) -> Result<()> {
    let zeros = [0u8; 64 * 1024];
    while count > 0 {
        budget.time()?;
        let n = count.min(zeros.len() as u64) as usize;
        output.write_all(&zeros[..n])?;
        count -= n as u64;
    }
    Ok(())
}

/// Immutable file descriptor with retained authenticated backing. Repeated ranges
/// avoid both path resolution and owned metadata decoding.
pub struct OpenedFile<'r, 'a, S: ObjectStore + ?Sized> {
    archive: &'r ArchiveReader<'a, S>,
    entry: super::pages::SharedEntry,
}

/// Shared authenticated entry. Borrowed fields remain valid while this view is
/// retained; its page is caller-held memory, separately from the store cache.
pub struct ResourceView {
    entry: super::pages::SharedEntry,
}
impl ResourceView {
    pub fn name(&self) -> &[u8] {
        self.entry.fields().expect("admitted entry")[0]
            .bytes()
            .expect("admitted name")
    }
    pub fn kind(&self) -> EntryKind {
        match self.entry.fields().expect("admitted entry")[1]
            .uint()
            .expect("admitted kind")
        {
            0 => EntryKind::File,
            1 => EntryKind::Directory,
            2 => EntryKind::Symlink,
            _ => unreachable!("admitted kind"),
        }
    }
    pub fn metadata(&self) -> crate::v1::cbor_view::Item<'_> {
        self.entry.fields().expect("admitted entry")[2]
    }
    pub fn file_length(&self) -> Option<u64> {
        (self.kind() == EntryKind::File).then(|| {
            self.entry.fields().expect("admitted entry")[3]
                .fields::<3>()
                .expect("admitted file")[0]
                .uint()
                .expect("admitted length")
        })
    }
    pub fn link_target(&self) -> Option<&[u8]> {
        (self.kind() == EntryKind::Symlink).then(|| {
            self.entry.fields().expect("admitted entry")[3]
                .bytes()
                .expect("admitted link")
        })
    }
}
impl<S: ObjectStore + ?Sized> OpenedFile<'_, '_, S> {
    pub fn len(&self) -> u64 {
        self.entry
            .fields()
            .and_then(|f| f[3].fields::<3>()?[0].uint())
            .expect("admitted file")
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn read_into(&self, offset: u64, output: &mut [u8]) -> Result<()> {
        let mut budget = Budget::new(self.archive.limits.clone());
        self.archive.read_shared(
            &self.entry,
            offset,
            output.len() as u64,
            &mut &mut *output,
            &mut budget,
        )
    }
    pub fn read_to<W: Write>(&self, output: &mut W) -> Result<()> {
        let mut budget = Budget::new(self.archive.limits.clone());
        budget.entry(self.len())?;
        self.archive
            .read_shared(&self.entry, 0, self.len(), output, &mut budget)
    }
}
