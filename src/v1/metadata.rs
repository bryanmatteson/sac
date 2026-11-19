//! Optional, application-independent `sac.metadata.v1` container metadata.
//!
//! Each namespaced key is one ordinary resource containing deterministic CBOR.
//! Directory paths and unchanged values are shared between snapshots. Unknown
//! keys, nested fields, profiles and feature declarations are never normalized.
use super::cbor::{self, Value};
use super::profiles::{ProfileRoot, ProfileValidator, SnapshotProfiles};
use super::resources::{
    self, ArchiveBuilder, ArchiveReader, Budget, DirectoryValidated, EntryKind, Limits, Profile,
};
use super::{Error, ObjectRef, ObjectStore, Result, cbor_view, corrupt, schema};
use std::sync::OnceLock;

pub const PROFILE_ID: &str = "sac.metadata.v1";
pub const VERSION: u32 = 1;
/// Per-value encoded bound. Total collection size is governed by resource limits.
pub const MAX_VALUE_BYTES: usize = 8 * 1024 * 1024;

fn key_path(key: &str) -> Result<Vec<Vec<u8>>> {
    if !schema::valid_id(key) {
        return Err(corrupt("metadata key must be a namespaced ID"));
    }
    Ok(vec![key.as_bytes().to_vec()])
}
fn check_value(bytes: &[u8], limits: &Limits) -> Result<()> {
    if bytes.len() > MAX_VALUE_BYTES
        || bytes.len() as u64 > limits.max_file_bytes
        || bytes.len() > limits.max_memory_bytes / 4
    {
        return Err(Error::Limit("metadata value"));
    }
    cbor_view::view(bytes)?;
    Ok(())
}
fn profile_directory<S: ObjectStore + ?Sized>(
    store: &S,
    root: &ProfileRoot,
    limits: &Limits,
) -> Result<ObjectRef> {
    let [directory] = root.children() else {
        return Err(corrupt("metadata root shape"));
    };
    if root.payload() != [0x81, 0x00] {
        return Err(corrupt("metadata root shape"));
    }
    let target = Budget::new(limits.clone()).get(store, *directory)?;
    if !matches!(target.kind, 3 | 4) || target.version != 1 {
        return Err(corrupt("metadata directory kind"));
    }
    Ok(*directory)
}

/// Validates the metadata directory and every value for profile-aware tools.
pub struct MetadataValidator;
impl<S: ObjectStore + ?Sized> ProfileValidator<S> for MetadataValidator {
    fn id(&self) -> &str {
        PROFILE_ID
    }
    fn version(&self) -> u32 {
        VERSION
    }
    fn validate(
        &self,
        store: &S,
        snapshot: &SnapshotProfiles,
        root: &ProfileRoot,
        limits: &Limits,
    ) -> Result<()> {
        let directory = profile_directory(store, root, limits)?;
        MetadataReader::from_directory(store, snapshot.snapshot(), directory, limits.clone())
            .verify()
    }
}

fn directory_reader<S: ObjectStore + ?Sized>(
    store: &S,
    snapshot: ObjectRef,
    directory: ObjectRef,
    limits: Limits,
) -> ArchiveReader<'_, S> {
    ArchiveReader {
        store,
        snapshot,
        directory,
        limits,
        has_profiles: true,
        rows: Default::default(),
    }
}

/// A routed miss is not certified absence until the directory has been checked.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup {
    Found(Vec<u8>),
    NoMatchUnverified,
    NotFound,
}

pub struct MetadataReader<'a, S: ObjectStore + ?Sized> {
    reader: ArchiveReader<'a, S>,
    validated: OnceLock<DirectoryValidated>,
}
impl<'a, S: ObjectStore + ?Sized> MetadataReader<'a, S> {
    /// Open only the profile root and directory header, without hydrating values.
    pub fn open(store: &'a S, snapshot: ObjectRef, limits: Limits) -> Result<Option<Self>> {
        let parts = SnapshotProfiles::discover(store, snapshot, &limits)?;
        let Some(root) = parts.open_root(store, PROFILE_ID, VERSION, &limits, |_| false)? else {
            return Ok(None);
        };
        let directory = profile_directory(store, &root, &limits)?;
        Ok(Some(Self::from_directory(
            store, snapshot, directory, limits,
        )))
    }
    fn from_directory(
        store: &'a S,
        snapshot: ObjectRef,
        directory: ObjectRef,
        limits: Limits,
    ) -> Self {
        Self {
            reader: directory_reader(store, snapshot, directory, limits),
            validated: OnceLock::new(),
        }
    }
    pub fn directory_root(&self) -> ObjectRef {
        self.reader.directory_root()
    }
    /// Point read; does not decode any other metadata value.
    pub fn lookup_encoded(&self, key: &str) -> Result<Lookup> {
        let path = key_path(key)?;
        match self.reader.read_file_bounded(&path, MAX_VALUE_BYTES)? {
            Some((_, bytes)) => {
                check_value(&bytes, self.reader.limits())?;
                Ok(Lookup::Found(bytes))
            }
            None if self.validated.get().is_some() => Ok(Lookup::NotFound),
            None => Ok(Lookup::NoMatchUnverified),
        }
    }
    /// Get canonical CBOR, checking directory completeness once on an initial miss.
    pub fn get_encoded(&self, key: &str) -> Result<Option<Vec<u8>>> {
        match self.lookup_encoded(key)? {
            Lookup::Found(bytes) => Ok(Some(bytes)),
            Lookup::NotFound => Ok(None),
            Lookup::NoMatchUnverified => {
                self.validate_directory()?;
                Ok(None)
            }
        }
    }
    pub fn get(&self, key: &str) -> Result<Option<Value>> {
        self.get_encoded(key)?
            .map(|bytes| cbor::decode(&bytes))
            .transpose()
    }
    /// Visit keys and encoded lengths, without reading extent-backed values.
    pub fn visit_keys(&self, visitor: &mut impl FnMut(&str, u64) -> Result<()>) -> Result<()> {
        self.reader.visit_entries(&mut |entry| {
            if entry.path.len() != 1
                || entry.kind != EntryKind::File
                || entry.length > MAX_VALUE_BYTES as u64
            {
                return Err(corrupt(
                    "metadata entries must be bounded, flat regular files",
                ));
            }
            let key =
                std::str::from_utf8(&entry.path[0]).map_err(|_| corrupt("metadata key UTF-8"))?;
            key_path(key)?;
            visitor(key, entry.length)
        })
    }
    pub fn validate_directory(&self) -> Result<()> {
        if self.validated.get().is_none() {
            self.visit_keys(&mut |_, _| Ok(()))?;
            let token = self.reader.validate_directory(&[])?;
            let _ = self.validated.set(token);
        }
        Ok(())
    }
    /// Validate all values using the allocation-free deterministic CBOR scanner.
    pub fn verify(&self) -> Result<()> {
        self.validate_directory()?;
        self.visit_keys(&mut |key, _| self.get_encoded(key).map(|_| ()))
    }
    /// Atomically export canonical value files plus the standard extraction report.
    pub fn export(&self, destination: &std::path::Path) -> Result<resources::ExtractionReport> {
        self.verify()?;
        self.reader.extract(destination)
    }
}

/// Persistent edits. `finish` returns a snapshot; publication remains the caller's
/// transaction. Every unrelated profile, feature, key and value stays intact.
pub struct MetadataEditor<'a, S: ObjectStore> {
    store: &'a mut S,
    original: ObjectRef,
    parts: SnapshotProfiles,
    directory: Option<ObjectRef>,
    limits: Limits,
    changed: bool,
    directory_validated: bool,
}
impl<'a, S: ObjectStore> MetadataEditor<'a, S> {
    pub fn open(store: &'a mut S, snapshot: ObjectRef, limits: Limits) -> Result<Self> {
        let parts = SnapshotProfiles::discover(store, snapshot, &limits)?;
        let directory = parts
            .open_root(store, PROFILE_ID, VERSION, &limits, |_| false)?
            .map(|root| profile_directory(store, &root, &limits))
            .transpose()?;
        Ok(Self {
            store,
            original: snapshot,
            parts,
            directory,
            limits,
            changed: false,
            directory_validated: directory.is_none(),
        })
    }
    pub fn set(&mut self, key: &str, value: &Value) -> Result<bool> {
        // Check the owned model before encoding, including canonical map order.
        if cbor::encoded_len(value) > MAX_VALUE_BYTES {
            return Err(Error::Limit("metadata value"));
        }
        self.set_encoded(key, &cbor::encode(value))
    }
    pub fn set_encoded(&mut self, key: &str, bytes: &[u8]) -> Result<bool> {
        let path = key_path(key)?;
        check_value(bytes, &self.limits)?;
        let mut attributes = Value::Map(Vec::new());
        if let Some(directory) = self.directory {
            let reader = MetadataReader::from_directory(
                &*self.store,
                self.original,
                directory,
                self.limits.clone(),
            );
            match reader.reader.read_file_bounded(&path, MAX_VALUE_BYTES)? {
                Some((entry, previous)) => {
                    attributes = entry.metadata;
                    if previous == bytes {
                        return Ok(false);
                    }
                    // A declared byte digest describes the new bytes, not the old value.
                    if let Value::Map(entries) = &mut attributes {
                        for entry in entries {
                            if entry.key == Value::text("byte_digest") {
                                entry.value = Value::bytes(blake3::hash(bytes).as_bytes().to_vec());
                            }
                        }
                    }
                }
                None if !self.directory_validated => {
                    reader.validate_directory()?;
                    self.directory_validated = true;
                }
                None => {}
            }
        }
        let mut builder = match self.directory {
            Some(root) => ArchiveBuilder::from_directory(self.store, root, self.limits.clone()),
            None => ArchiveBuilder::with_limits(self.store, self.limits.clone()),
        };
        builder.set_page_limit(4096)?;
        builder.set_chunk_size(64 * 1024)?;
        builder.set_file(&path, bytes, attributes)?;
        self.directory = Some(builder.finish_directory()?);
        self.changed = true;
        Ok(true)
    }
    pub fn remove(&mut self, key: &str) -> Result<bool> {
        let path = key_path(key)?;
        let Some(directory) = self.directory else {
            return Ok(false);
        };
        let reader = MetadataReader::from_directory(
            &*self.store,
            self.original,
            directory,
            self.limits.clone(),
        );
        // Verify absence without reading a potentially large value being removed.
        let present = match reader.reader.lookup(&path)? {
            resources::Lookup::Found { .. } => true,
            _ => {
                reader.validate_directory()?;
                false
            }
        };
        if !present {
            return Ok(false);
        }
        let mut builder =
            ArchiveBuilder::from_directory(self.store, directory, self.limits.clone());
        builder.set_page_limit(4096)?;
        builder.remove_file(&path)?;
        self.directory = Some(builder.finish_directory()?);
        self.changed = true;
        Ok(true)
    }
    pub fn finish(mut self) -> Result<ObjectRef> {
        if !self.changed {
            return Ok(self.original);
        }
        let directory = self.directory.ok_or(Error::Missing)?;
        let root = self.store.put(
            8,
            1,
            &cbor::encode(&Value::Array(vec![
                Value::text(PROFILE_ID),
                Value::text("root"),
                Value::Uint(1),
                Value::bytes([0x81, 0x00]),
            ])),
            &[directory],
        )?;
        self.parts.profiles.retain(|p| p.id != PROFILE_ID);
        self.parts.profiles.push(Profile {
            id: PROFILE_ID.into(),
            version: VERSION,
            root,
        });
        resources::snapshot(
            self.store,
            self.parts.directory,
            self.parts.profiles,
            self.parts.features,
        )
    }
}
