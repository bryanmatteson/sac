//! The SAC Registry separates immutable releases and exact file encodings from
//! a shared store of SAC objects. Application profile semantics stay with their owners.
pub mod http;
pub mod oci;
mod store;
mod transfer;

pub use store::{ArchiveReader, Registry, Registry as FilesystemRegistry};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fmt, str::FromStr};

pub const DEFAULT_MAX_BYTES: u64 = 8 << 30;
const MAX_LAYOUT_BYTES: u64 = 32 << 20;
const MAX_RECORD_BYTES: u64 = 256 << 10;
const MAX_LIST_BYTES: u64 = 16 << 20;
const MAX_RELEASES: usize = 10_000;
const MAX_BLOB_BYTES: u64 = 8 << 20;
const MAX_FRAMES: usize = 100_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid registry input: {0}")]
    Invalid(String),
    #[error("registry entry not found: {0}")]
    NotFound(String),
    #[error("immutable registry entry already exists: {0}")]
    Conflict(String),
    #[error("registry limit exceeded: {0}")]
    Limit(&'static str),
    #[error("registry integrity check failed: {0}")]
    Integrity(&'static str),
    #[error("registry transport: {0}")]
    Transport(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sac(#[from] sac::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Reference {
    pub namespace: String,
    pub name: String,
    pub version: String,
}

impl FromStr for Reference {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        let (name, version) = value.split_once('@').ok_or_else(reference_error)?;
        let (namespace, name) = name.split_once('/').ok_or_else(reference_error)?;
        Self::new(namespace, name, version)
    }
}

impl Reference {
    pub fn new(namespace: &str, name: &str, version: &str) -> Result<Self> {
        for part in [namespace, name, version] {
            if part.is_empty()
                || part.len() > 128
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            {
                return Err(reference_error());
            }
        }
        Ok(Self {
            namespace: namespace.into(),
            name: name.into(),
            version: version.into(),
        })
    }

    fn key(&self) -> Result<String> {
        Self::new(&self.namespace, &self.name, &self.version)?;
        let mut hash = Sha256::new();
        hash.update(b"SAC registry release v1\0");
        hash.update(self.to_string().as_bytes());
        Ok(hex::encode(hash.finalize()))
    }
}

fn reference_error() -> Error {
    Error::Invalid("expected namespace/name@version with lowercase ASCII letters, digits, dots, underscores, or hyphens".into())
}

impl fmt::Display for Reference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}/{}@{}",
            self.namespace, self.name, self.version
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub version: u32,
    pub root_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Annotation {
    Text(String),
    List(Vec<String>),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub sha256: String,
    pub bytes: u64,
    pub snapshot_id: String,
    pub commit_id: String,
    pub profiles: Vec<Profile>,
    pub annotations: BTreeMap<String, Annotation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Release {
    pub reference: String,
    pub artifact: Artifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl Release {
    fn validate(&self) -> Result<Reference> {
        let reference = self.reference.parse()?;
        self.artifact.validate()?;
        if let Some(profile) = &self.profile
            && !self.artifact.profiles.iter().any(|row| row.id == *profile)
        {
            return Err(Error::Invalid(format!("snapshot has no profile {profile}")));
        }
        Ok(reference)
    }

    pub fn matches(&self, profile: Option<&str>, version: Option<u32>, tag: Option<&str>) -> bool {
        profile.is_none_or(|id| {
            self.artifact
                .profiles
                .iter()
                .any(|row| row.id == id && version.is_none_or(|version| row.version == version))
        }) && tag.is_none_or(|tag| {
            matches!(self.artifact.annotations.get("sac.registry.tags"),
                Some(Annotation::List(tags)) if tags.iter().any(|value| value == tag))
        })
    }
}

impl Artifact {
    fn validate(&self) -> Result<()> {
        check_digest(&self.sha256)?;
        check_digest(&self.snapshot_id)?;
        check_digest(&self.commit_id)?;
        if !self.profiles.windows(2).all(|rows| rows[0].id < rows[1].id) {
            return Err(Error::Integrity("profile declaration order"));
        }
        for profile in &self.profiles {
            check_digest(&profile.root_id)?;
        }
        Ok(())
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn check_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Error::Invalid("expected a lowercase 256-bit digest".into()))
    }
}
