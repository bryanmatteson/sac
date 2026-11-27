use super::tree::{self, Entry, EntryData, FileData};
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
        let parts = crate::profiles::SnapshotProfiles::discover(store, snapshot, &limits)?;
        parts.require_core_support()?;
        Ok(Self {
            store,
            snapshot,
            directory: parts.directory(),
            has_profiles: !parts.profiles().is_empty(),
            limits,
            rows: Default::default(),
        })
    }
    pub fn snapshot(&self) -> ObjectRef {
        self.snapshot
    }
    /// The store this reader resolves its snapshot from.
    pub fn store(&self) -> &'a S {
        self.store
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
                Some(output),
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
    /// Visit entries and optionally read their authenticated file bodies without
    /// repeating a path lookup. File handles borrow the current traversal row.
    pub fn visit_entries_with_files<F>(&self, mut visitor: F) -> Result<()>
    where
        F: FnMut(ResourceEntry, Option<VisitedFile<'_, 'a, S>>) -> Result<()>,
    {
        let mut budget = Budget::new(self.limits.clone());
        self.visit_raw_with_budget(&mut budget, true, &mut |path, entry, _| {
            let file = match &entry.data {
                EntryData::File { length, data } => Some(VisitedFile {
                    reader: self,
                    entry: &entry,
                    length: *length,
                    data,
                }),
                _ => None,
            };
            visitor(entry.public(path.clone()), file)
        })
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
        self.walk_directory_view(
            root,
            expected_height,
            lower,
            upper,
            budget,
            depth,
            &mut |entry, budget| visitor(entry.owned()?, budget),
        )
    }
    #[allow(
        clippy::too_many_arguments,
        reason = "tree traversal carries explicit inherited geometry and one operation budget"
    )]
    fn walk_directory_view<F>(
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
        F: FnMut(super::pages::EntryView<'_>, &mut Budget) -> Result<()>,
    {
        budget.depth(depth)?;
        budget.edge()?;
        budget.visit_for_copy(self.store, root, None, &mut |object, budget, _| {
            if object.version != 1 {
                return Err(Error::Unsupported("directory schema".into()));
            }
            if object.canonical_len()
                > if object.kind == 3 {
                    DIRECTORY_LEAF_LIMIT
                } else {
                    PAGE_LIMIT
                }
            {
                return Err(Error::Limit("directory page bytes"));
            }
            let body = crate::v1::cbor_view::admitted(object.bytes)?;
            match object.kind {
                3 => {
                    if expected_height.is_some_and(|height| height != 0) {
                        return Err(corrupt("directory height mismatch"));
                    }
                    if lower.is_some() || upper.is_some() {
                        let mut rows = body.array()?;
                        let first = rows.next().ok_or_else(|| corrupt("empty branch child"))??;
                        let last = rows.last().transpose()?.unwrap_or(first);
                        let first_key = first.first_field(4)?.bytes()?;
                        let last_key = last.first_field(4)?.bytes()?;
                        if lower.is_some_and(|bound| first_key <= bound)
                            || upper.is_some_and(|bound| last_key != bound)
                        {
                            return Err(corrupt("directory leaf interval mismatch"));
                        }
                    }
                    for row in body.array()? {
                        visitor(super::pages::EntryView { object, row: row? }, budget)?;
                    }
                }
                4 => {
                    let [height, rows] = body.fields()?;
                    let height = height.uint()?;
                    if expected_height.is_some_and(|expected| expected != height) {
                        return Err(corrupt("directory branch height mismatch"));
                    }
                    let mut bounds = rows.array()?;
                    let first = bounds
                        .next()
                        .ok_or_else(|| corrupt("empty branch child"))??;
                    let last = bounds.last().transpose()?.unwrap_or(first);
                    let first_key = first.first_field(2)?.bytes()?;
                    let last_key = last.first_field(2)?.bytes()?;
                    if upper.is_some_and(|bound| last_key != bound)
                        || lower.is_some_and(|bound| first_key <= bound)
                    {
                        return Err(corrupt("directory branch interval mismatch"));
                    }
                    let mut previous = lower;
                    for row in rows.array()? {
                        let [key, child] = row?.fields()?;
                        let key = key.bytes()?;
                        let child = *object
                            .children
                            .get(
                                usize::try_from(child.uint()?)
                                    .map_err(|_| corrupt("child index"))?,
                            )
                            .ok_or_else(|| corrupt("child index"))?;
                        budget.check_reference(root, child)?;
                        self.walk_directory_view(
                            child,
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
                _ => return Err(corrupt("expected directory node")),
            }
            Ok(())
        })
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
            FileData::Extents(root) => self.extents(
                *root,
                *file_length,
                None,
                offset,
                end,
                Some(output),
                budget,
                0,
            )?,
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
        mut output: Option<&mut W>,
        budget: &mut Budget,
        depth: usize,
    ) -> Result<()> {
        budget.depth(depth)?;
        budget.edge()?;
        budget.visit_for_copy(self.store, root, None, &mut |object, budget, _| {
            if object.version != 1 || object.canonical_len() > PAGE_LIMIT {
                return Err(corrupt("extent schema or page size"));
            }
            let body = crate::v1::cbor_view::admitted(object.bytes)?;
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
                            if !row[1].is_null() {
                                let r = *object
                                    .children
                                    .get(row[1].uint()? as usize)
                                    .ok_or_else(|| corrupt("child index"))?;
                                budget.check_reference(root, r)?;
                                budget.edge()?;
                                if let Some(output) = output.as_deref_mut() {
                                    budget.visit_for_copy(
                                        self.store,
                                        r,
                                        None,
                                        &mut |data, _, _| {
                                            if data.kind != 7
                                                || data.version != 1
                                                || !data.children.is_empty()
                                                || data.bytes.len() as u64 != length
                                            {
                                                return Err(corrupt(
                                                    "extent byte object length or type",
                                                ));
                                            }
                                            output
                                                .write_all(&data.bytes[a as usize..b as usize])
                                                .map_err(Error::from)
                                        },
                                    )?;
                                } else {
                                    // A successful graph copy checks this exact edge's
                                    // kind and length. Charge the namespace visit now.
                                    let decoded = length
                                        .checked_add(8)
                                        .and_then(|len| usize::try_from(len).ok())
                                        .filter(|len| *len <= super::super::MAX_CHUNK_SIZE)
                                        .ok_or_else(|| {
                                            corrupt("extent byte object length or type")
                                        })?;
                                    budget.charge_reference(r)?;
                                    budget.charge_decoded(decoded)?;
                                }
                            } else if let Some(output) = output.as_deref_mut() {
                                write_zeros(output, b - a, budget)?;
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
                                output.as_deref_mut(),
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
        })
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
        let mut report = self.verify_namespace(&mut budget)?;
        // Repeated immutable occurrences share graph validation. Namespace
        // expansion and file lengths are charged by verify_namespace.
        self.verify_graph(root, &mut budget)?;
        report.content_verified = true;
        report.core_checked = true;
        report.profile_checked = !self.has_profiles;
        Ok(report)
    }
    fn verify_namespace(&self, budget: &mut Budget) -> Result<VerificationReport> {
        let mut report = VerificationReport {
            snapshot_id: self.snapshot.hash.0,
            root_admitted: true,
            ..Default::default()
        };
        self.verify_directory(self.directory, 0, budget, &mut report)?;
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
        Ok(report)
    }
    fn verify_directory(
        &self,
        root: ObjectRef,
        depth: usize,
        budget: &mut Budget,
        report: &mut VerificationReport,
    ) -> Result<()> {
        budget.depth(depth)?;
        budget.memory((depth + 1).saturating_mul(DIRECTORY_LEAF_LIMIT * 4))?;
        self.walk_directory_view(root, None, None, None, budget, 0, &mut |entry, budget| {
            let [_, kind, _, value] = entry.fields()?;
            let kind = kind.uint()?;
            let logical = if kind == 0 {
                value.fields::<3>()?[0].uint()?
            } else {
                0
            };
            budget.entry(logical)?;
            report.entries += 1;
            match kind {
                0 => {
                    report.files += 1;
                    report.logical_bytes = report
                        .logical_bytes
                        .checked_add(logical)
                        .ok_or(Error::Limit("logical bytes"))?;
                    let [_, storage, data] = value.fields::<3>()?;
                    if storage.uint()? == 1 {
                        let extent = entry.child(data)?;
                        self.extents(
                            extent,
                            logical,
                            None,
                            0,
                            logical,
                            // The graph walk authenticates every physical
                            // byte occurrence and its declared extent length.
                            None::<&mut std::io::Sink>,
                            budget,
                            0,
                        )?;
                    }
                    // Inline byte lengths and contents were authenticated by
                    // the intrinsic directory admission; no owned copy is needed.
                }
                1 => self.verify_directory(entry.child(value)?, depth + 1, budget, report)?,
                _ => {}
            }
            Ok(())
        })
    }
    /// Verify the portable snapshot and export its commit in one graph walk.
    /// The caller is responsible for physical file validation and for staging
    /// the output. An error can leave an incomplete prefix in the writer.
    #[cfg(feature = "native")]
    pub fn pack_verified_commit<W: Write>(
        &self,
        commit: ObjectRef,
        output: W,
        max_copy_temp_bytes: u64,
    ) -> Result<W> {
        self.pack_verified_commit_with_options(
            commit,
            output,
            max_copy_temp_bytes,
            super::super::SealingOptions::default(),
        )
    }
    /// Verify and seal with an explicit source-encoding policy. Authentication,
    /// namespace geometry and operation charges match `pack_verified_commit`.
    #[cfg(feature = "native")]
    pub fn pack_verified_commit_with_options<W: Write>(
        &self,
        commit: ObjectRef,
        output: W,
        max_copy_temp_bytes: u64,
        options: super::super::SealingOptions,
    ) -> Result<W> {
        let mut verification = Budget::new(self.limits.clone());
        // The copy's direct role checks authenticate every extent byte leaf
        // before it is exported, including its declared length.
        self.verify_namespace(&mut verification)?;
        let mut copy_limits = self.limits.clone();
        copy_limits.max_temp_bytes = copy_limits.max_temp_bytes.min(max_copy_temp_bytes);
        super::super::pack_commit_impl(
            self.store,
            commit,
            output,
            copy_limits,
            options,
            Some((self.snapshot, verification)),
        )
    }
    fn verify_graph(&self, root: ObjectRef, budget: &mut Budget) -> Result<()> {
        let mut graph = super::graph::Workspace::new(budget)?;
        graph.push(root, false, budget)?;
        let mut byte_lengths = [0; super::super::MAX_CHILDREN];
        while let Some((reference, expanded, byte_length)) = graph.pop_for_copy()? {
            budget.time()?;
            if expanded {
                graph.complete(reference, budget)?;
                continue;
            }
            if graph.completed_for_copy(reference, byte_length)? {
                continue;
            }
            graph.enter(reference, budget)?;
            budget.visit_for_copy(self.store, reference, None, &mut |object, budget, _| {
                if byte_length != 0 {
                    super::super::schema::CoreRole::Bytes(u64::from(byte_length)).check::<false>(
                        super::super::schema::CoreShape {
                            kind: object.kind,
                            version: object.version,
                            bytes: object.bytes,
                            child_count: object.children.len(),
                        },
                    )?;
                }
                budget.check_graph_children(
                    self.store,
                    reference,
                    object,
                    &mut byte_lengths,
                    None,
                )?;
                if object.children.is_empty() {
                    return graph.complete_for_copy(reference, object, budget);
                }
                graph.push(reference, true, budget)?;
                for (index, child) in object.children.iter().enumerate().rev() {
                    graph.push_for_copy(*child, byte_lengths[index], budget)?;
                }
                Ok(())
            })?;
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

/// File descriptor borrowed from an authenticated entry during traversal.
pub struct VisitedFile<'r, 'a, S: ObjectStore + ?Sized> {
    reader: &'r ArchiveReader<'a, S>,
    entry: &'r Entry,
    length: u64,
    data: &'r FileData,
}
impl<S: ObjectStore + ?Sized> VisitedFile<'_, '_, S> {
    pub fn contents(&self) -> FileContents<'_> {
        match self.data {
            FileData::Inline(bytes) => FileContents::Inline(bytes),
            FileData::Extents(root) => FileContents::Extents {
                length: self.length,
                root: *root,
            },
        }
    }
    pub fn read_bounded(&self, max_bytes: usize) -> Result<Vec<u8>> {
        let length = usize::try_from(self.length).map_err(|_| Error::Limit("file length"))?;
        if length > max_bytes.min(self.reader.limits.max_memory_bytes / 2) {
            return Err(Error::Limit("bounded file output memory"));
        }
        let mut budget = Budget::new(self.reader.limits.clone());
        budget.entry(self.length)?;
        let mut output = Vec::with_capacity(length);
        self.reader
            .read_entry(self.entry, 0, self.length, &mut output, &mut budget)?;
        Ok(output)
    }
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
    /// Borrow a file's authenticated storage descriptor without reading or
    /// copying its payload. An extent descriptor retains its exact child
    /// reference; validate the complete extent graph before sharing it into a
    /// new snapshot, as required by `ArchiveBuilder::set_files_batch`.
    pub fn file_contents(&self) -> Result<Option<FileContents<'_>>> {
        if self.kind() != EntryKind::File {
            return Ok(None);
        }
        let [length, storage, data] = self.entry.fields()?[3].fields()?;
        Ok(Some(match storage.uint()? {
            0 => FileContents::Inline(data.bytes()?),
            1 => FileContents::Extents {
                length: length.uint()?,
                root: self.entry.child(data)?,
            },
            _ => return Err(corrupt("unknown file storage")),
        }))
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
