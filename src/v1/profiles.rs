//! Typed discovery and owner-supplied validation of SAC1 application profiles.
use super::cbor_view::{self, Item};
use super::resources::{Budget, Limits};
use super::{CanonicalObject, Error, ObjectRef, ObjectStore, Result, corrupt, schema};
use std::sync::Arc;

pub use super::resources::{Feature, Profile};

/// Declarations authenticated by one snapshot. Discovery reads only that snapshot.
#[derive(Debug)]
pub struct SnapshotProfiles {
    snapshot: ObjectRef,
    object: Arc<CanonicalObject>,
    pub(crate) directory: ObjectRef,
    pub(crate) profiles: Vec<Profile>,
    pub(crate) features: Vec<Feature>,
}

impl SnapshotProfiles {
    pub fn discover<S: ObjectStore + ?Sized>(
        store: &S,
        snapshot: ObjectRef,
        limits: &Limits,
    ) -> Result<Self> {
        let mut budget = Budget::new(limits.clone());
        let object = budget.get(store, snapshot)?;
        if (object.kind, object.version) != (2, 1) {
            return Err(corrupt("expected snapshot schema 1"));
        }
        let [directory, declarations, capabilities] =
            cbor_view::admitted(&object.bytes)?.fields()?;
        let declarations = declarations.array()?;
        let capabilities = capabilities.array()?;
        // The intrinsic 16 KiB snapshot cap bounds both counts and all owned strings.
        budget.memory(
            object.canonical_len()
                + object.bytes.len()
                + declarations.len() * size_of::<Profile>()
                + capabilities.len() * size_of::<Feature>()
                + object.children.len() * size_of::<ObjectRef>(),
        )?;
        let child = |index: Item<'_>| -> Result<ObjectRef> {
            let i = usize::try_from(index.uint()?).map_err(|_| corrupt("snapshot child index"))?;
            let reference = *object
                .children
                .get(i)
                .ok_or_else(|| corrupt("snapshot child index"))?;
            budget.check_reference(snapshot, reference)?;
            Ok(reference)
        };
        let directory = child(directory)?;
        let mut profiles = Vec::with_capacity(declarations.len());
        for row in declarations {
            let [id, version, root] = row?.fields()?;
            profiles.push(Profile {
                id: id.text()?.to_owned(),
                version: version.uint()? as u32, // checked by the intrinsic snapshot schema
                root: child(root)?,
            });
        }
        let mut features = Vec::with_capacity(capabilities.len());
        for row in capabilities {
            let [scope, id, version, required] = row?.fields()?;
            features.push(Feature {
                scope: if scope.is_null() {
                    None
                } else {
                    Some(scope.text()?.to_owned())
                },
                id: id.text()?.to_owned(),
                version: version.uint()? as u32,
                required: required.boolean()?,
            });
        }
        budget.time()?;
        Ok(Self {
            snapshot,
            object,
            directory,
            profiles,
            features,
        })
    }

    pub fn snapshot(&self) -> ObjectRef {
        self.snapshot
    }
    pub fn directory(&self) -> ObjectRef {
        self.directory
    }
    /// Child table in wire order for consumers with a canonical packing recipe.
    pub fn children(&self) -> &[ObjectRef] {
        &self.object.children
    }
    pub fn profiles(&self) -> &[Profile] {
        &self.profiles
    }
    pub fn features(&self) -> &[Feature] {
        &self.features
    }
    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles
            .binary_search_by(|p| p.id.as_str().cmp(id))
            .ok()
            .map(|i| &self.profiles[i])
    }
    /// Unknown required core capabilities allow discovery but block content operations.
    pub fn require_core_support(&self) -> Result<()> {
        if let Some(f) = self
            .features
            .iter()
            .find(|f| f.scope.is_none() && f.required)
        {
            return Err(Error::Unsupported(format!(
                "required core capability {}",
                f.id
            )));
        }
        Ok(())
    }

    /// Open the owner's exact version, admitting the selected root and its binding.
    /// Absent profiles return `None`. Descendant roles and semantics belong to the caller.
    pub fn open_root<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
        id: &str,
        version: u32,
        limits: &Limits,
        supports_feature: impl Fn(&Feature) -> bool,
    ) -> Result<Option<ProfileRoot>> {
        self.require_core_support()?;
        let Some(profile) = self.profile(id) else {
            return Ok(None);
        };
        if profile.version != version {
            return Err(Error::Unsupported(unsupported_version(profile)));
        }
        self.bound_root(
            store,
            profile,
            &mut Budget::new(limits.clone()),
            supports_feature,
        )
        .map(Some)
    }

    fn bound_root<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
        profile: &Profile,
        budget: &mut Budget,
        supports_feature: impl Fn(&Feature) -> bool,
    ) -> Result<ProfileRoot> {
        for feature in self
            .features
            .iter()
            .filter(|f| f.required && f.scope.as_deref() == Some(&profile.id))
        {
            if !supports_feature(feature) {
                return Err(Error::Unsupported(format!(
                    "required {} capability {} version {}",
                    profile.id, feature.id, feature.version
                )));
            }
        }
        budget.edge()?;
        let object = budget.get(store, profile.root)?;
        if (object.kind, object.version) != (8, 1) {
            return Err(corrupt("expected profile root kind 8 schema 1"));
        }
        let payload =
            schema::profile_root_payload(&object.bytes, &profile.id, u64::from(profile.version))?;
        let payload_offset = object.bytes.len() - payload.len();
        for child in &object.children {
            budget.check_reference(profile.root, *child)?;
        }
        Ok(ProfileRoot {
            object,
            payload_offset,
        })
    }

    /// Dispatch each declaration to the first supplied validator for its ID and version.
    /// Unclaimed profiles stay unchecked. Limits, missing data and I/O failures
    /// return an operation error rather than a semantic verdict.
    pub fn validate<S: ObjectStore + ?Sized>(
        &self,
        store: &S,
        validators: &[&dyn ProfileValidator<S>],
        limits: &Limits,
    ) -> Result<Vec<ProfileReport<'_>>> {
        self.require_core_support()?;
        let mut budget = Budget::new(limits.clone());
        budget.memory(self.profiles.len() * size_of::<ProfileReport<'_>>())?;
        let mut reports = Vec::with_capacity(self.profiles.len());
        for profile in &self.profiles {
            let mut matching = validators
                .iter()
                .copied()
                .filter(|v| v.id() == profile.id)
                .peekable();
            let validation = if matching.peek().is_none() {
                ProfileValidation::Unchecked
            } else if let Some(owner) = matching.find(|v| v.version() == profile.version) {
                let result = self
                    .bound_root(store, profile, &mut budget, |f| owner.supports_feature(f))
                    .and_then(|root| owner.validate(store, self, &root, limits));
                match result {
                    Ok(()) => ProfileValidation::Valid,
                    Err(Error::Unsupported(reason)) => ProfileValidation::Unsupported(reason),
                    Err(Error::Corrupt(reason)) => ProfileValidation::Invalid(reason),
                    Err(error) => return Err(error),
                }
            } else {
                ProfileValidation::Unsupported(unsupported_version(profile))
            };
            budget.time()?;
            reports.push(ProfileReport {
                profile,
                validation,
            });
        }
        Ok(reports)
    }
}

fn unsupported_version(profile: &Profile) -> String {
    format!("{} profile version {}", profile.id, profile.version)
}

/// An authenticated kind-8 root bound to its snapshot declaration.
pub struct ProfileRoot {
    object: Arc<CanonicalObject>,
    // The byte string is the last field of the canonical root body.
    payload_offset: usize,
}
impl ProfileRoot {
    pub fn payload(&self) -> &[u8] {
        &self.object.bytes[self.payload_offset..]
    }
    pub fn children(&self) -> &[ObjectRef] {
        &self.object.children
    }
}

/// Caller-selected semantic validation for one exact application profile version.
pub trait ProfileValidator<S: ObjectStore + ?Sized> {
    fn id(&self) -> &str;
    fn version(&self) -> u32;
    /// Called for required capabilities scoped to this profile.
    fn supports_feature(&self, _feature: &Feature) -> bool {
        false
    }
    /// Check the application payload and its required dependencies within the supplied limits.
    fn validate(
        &self,
        store: &S,
        snapshot: &SnapshotProfiles,
        root: &ProfileRoot,
        limits: &Limits,
    ) -> Result<()>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProfileValidation {
    Unchecked,
    Valid,
    Unsupported(String),
    Invalid(String),
}

#[derive(Debug)]
pub struct ProfileReport<'a> {
    pub profile: &'a Profile,
    pub validation: ProfileValidation,
}
