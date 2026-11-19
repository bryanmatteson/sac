use sac::cbor::{self, Value};
use sac::profiles::{
    Feature, Profile, ProfileRoot, ProfileValidation, ProfileValidator, SnapshotProfiles,
};
use sac::resources::{self, Limits};
use sac::{Error, MemoryStore, ObjectRef, ObjectStore, PositionalStore, Result};

const OWNED: &str = "example.owned";
const OTHER: &str = "example.other";

fn profile(
    store: &mut MemoryStore,
    id: &str,
    version: u32,
    payload: &[u8],
    dir: ObjectRef,
) -> Profile {
    let bytes = cbor::encode(&Value::Array(vec![
        Value::text(id),
        Value::text("root"),
        Value::Uint(u64::from(version)),
        Value::bytes(payload),
    ]));
    Profile {
        id: id.into(),
        version,
        root: store.put(8, 1, &bytes, &[dir]).unwrap(),
    }
}

struct Owner;
impl<S: ObjectStore + ?Sized> ProfileValidator<S> for Owner {
    fn id(&self) -> &str {
        OWNED
    }
    fn version(&self) -> u32 {
        2
    }
    fn supports_feature(&self, feature: &Feature) -> bool {
        feature.id == "example.cap" && feature.version == 1
    }
    fn validate(
        &self,
        _: &S,
        snapshot: &SnapshotProfiles,
        root: &ProfileRoot,
        _: &Limits,
    ) -> Result<()> {
        if root.payload() == b"accepted" && root.children() == [snapshot.directory()] {
            Ok(())
        } else {
            Err(Error::Corrupt("invalid example payload".into()))
        }
    }
}

fn required(scope: Option<&str>, version: u32) -> Feature {
    Feature {
        scope: scope.map(str::to_owned),
        id: "example.cap".into(),
        version,
        required: true,
    }
}

#[test]
fn authenticated_discovery_reads_one_snapshot_and_dispatches_only_claimed_roots() {
    let mut store = MemoryStore::sealed();
    let dir = store.put(3, 1, &[0x80], &[]).unwrap();
    let owned = profile(&mut store, OWNED, 2, b"accepted", dir);
    let other = profile(&mut store, OTHER, 7, b"opaque", dir);
    let root = owned.root;
    let snapshot = resources::snapshot(
        &mut store,
        dir,
        vec![owned, other],
        vec![required(Some(OTHER), 99), required(Some(OWNED), 1)],
    )
    .unwrap();
    store.publish(snapshot).unwrap();
    let source = PositionalStore::open(store.as_bytes()).unwrap();
    let selected = source.reader().snapshot().unwrap();
    let reads = source.reader().statistics().requests;
    let limits = Limits::default();
    let declarations = SnapshotProfiles::discover(&source, selected, &limits).unwrap();
    assert_eq!(source.reader().statistics().requests, reads + 1);
    assert_eq!(declarations.snapshot(), selected);
    assert_eq!(declarations.profile(OWNED).unwrap().root.hash, root.hash);
    assert!(declarations.profile("example.absent").is_none());
    assert_eq!(declarations.features().len(), 2);
    let reports = declarations.validate(&source, &[&Owner], &limits).unwrap();
    assert_eq!(reports[0].profile.id, OTHER);
    assert_eq!(reports[0].validation, ProfileValidation::Unchecked);
    assert_eq!(reports[1].validation, ProfileValidation::Valid);
    assert_eq!(source.reader().statistics().requests, reads + 2);
}

#[test]
fn owner_semantics_version_and_required_capabilities_have_independent_outcomes() {
    let mut store = MemoryStore::sealed();
    let dir = store.put(3, 1, &[0x80], &[]).unwrap();
    let limits = Limits::default();
    for (version, feature, payload, expected) in [
        (
            2,
            Feature {
                required: false,
                ..required(Some(OWNED), 99)
            },
            &b"accepted"[..],
            "valid",
        ),
        (
            2,
            required(Some(OWNED), 99),
            &b"accepted"[..],
            "unsupported",
        ),
        (3, required(Some(OWNED), 1), &b"accepted"[..], "unsupported"),
        (2, required(Some(OWNED), 1), &b"bad"[..], "invalid"),
    ] {
        let owned = profile(&mut store, OWNED, version, payload, dir);
        let snapshot = resources::snapshot(&mut store, dir, vec![owned], vec![feature]).unwrap();
        let parts = SnapshotProfiles::discover(&store, snapshot, &limits).unwrap();
        let reports = parts.validate(&store, &[&Owner], &limits).unwrap();
        let state = &reports[0].validation;
        assert!(
            matches!(
                (expected, state),
                ("valid", ProfileValidation::Valid)
                    | ("unsupported", ProfileValidation::Unsupported(_))
                    | ("invalid", ProfileValidation::Invalid(_))
            ),
            "{state:?}"
        );
    }
    let owned = profile(&mut store, OWNED, 2, b"accepted", dir);
    let snapshot =
        resources::snapshot(&mut store, dir, vec![owned], vec![required(None, 1)]).unwrap();
    let parts = SnapshotProfiles::discover(&store, snapshot, &limits).unwrap();
    assert!(parts.features()[0].scope.is_none());
    assert!(matches!(
        parts.validate(&store, &[&Owner], &limits),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        parts.open_root(&store, OWNED, 2, &limits, |_| true),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn a_declaration_alone_does_not_validate_its_binding_or_override_limits() {
    let mut store = MemoryStore::sealed();
    let dir = store.put(3, 1, &[0x80], &[]).unwrap();
    let mut wrong = profile(&mut store, OTHER, 2, b"accepted", dir);
    wrong.id = OWNED.into();
    let snapshot = resources::snapshot(&mut store, dir, vec![wrong], vec![]).unwrap();
    let limits = Limits::default();
    let declarations = SnapshotProfiles::discover(&store, snapshot, &limits).unwrap();
    assert!(matches!(
        declarations.open_root(&store, OWNED, 2, &limits, |_| false),
        Err(Error::Corrupt(_))
    ));
    assert!(matches!(
        declarations.validate(&store, &[&Owner], &limits).unwrap()[0].validation,
        ProfileValidation::Invalid(_)
    ));
    let zero = Limits {
        max_frames: 0,
        ..limits
    };
    assert!(matches!(
        SnapshotProfiles::discover(&store, snapshot, &zero),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        declarations.validate(&store, &[&Owner], &zero),
        Err(Error::Limit(_))
    ));
}
