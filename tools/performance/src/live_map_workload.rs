//! Route the live-map backend through the public library; keep prior controls intact.
use crate::dual_map::{DualMap as Prototype, DualReader as PrototypeReader};
use sac::{LiveMap, LiveMapReader, ObjectRef, ObjectStore, Result};
use std::collections::BTreeMap;
#[derive(Clone)]
pub enum DualMap {
    Prototype(Prototype),
    Production(LiveMap),
}
pub enum DualReader<'a, S: ObjectStore + ?Sized> {
    Prototype(PrototypeReader<'a, S>),
    Production(LiveMapReader<'a, S>),
}
impl<S: ObjectStore + ?Sized> DualReader<'_, S> {
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self {
            Self::Prototype(r) => r.get(key),
            Self::Production(r) => r.get(key),
        }
    }
}
impl DualMap {
    pub fn from_base<S: ObjectStore + ?Sized>(s: &S, r: ObjectRef) -> Result<Self> {
        Prototype::from_base(s, r).map(Self::Prototype)
    }
    pub fn from_base_bucket<S: ObjectStore + ?Sized>(s: &S, r: ObjectRef) -> Result<Self> {
        Prototype::from_base_bucket(s, r).map(Self::Prototype)
    }
    pub fn from_base_paged<S: ObjectStore + ?Sized>(s: &S, r: ObjectRef) -> Result<Self> {
        Prototype::from_base_paged(s, r).map(Self::Prototype)
    }
    pub fn from_base_live<S: ObjectStore + ?Sized>(s: &S, r: ObjectRef) -> Result<Self> {
        LiveMap::from_base(s, r).map(Self::Production)
    }
    pub fn open<S: ObjectStore + ?Sized>(s: &S, r: ObjectRef) -> Result<Self> {
        let object = s.get_verified_shared(r)?;
        let [_, profiles, _] = sac::v1::cbor_view::view(&object.bytes)?.fields()?;
        let [id, _, _] = profiles.array()?.next().unwrap()?.fields()?;
        if id.text()? == sac::resources::live_map::PROFILE {
            LiveMap::open(s, r).map(Self::Production)
        } else {
            Prototype::open(s, r).map(Self::Prototype)
        }
    }
    pub fn set<S: ObjectStore + ?Sized>(&mut self, s: &mut S, k: &[u8], v: &[u8]) -> Result<()> {
        match self {
            Self::Prototype(m) => m.set(s, k, v),
            Self::Production(m) => m.set(s, k, v),
        }
    }
    pub fn snapshot<S: ObjectStore + ?Sized>(&self, s: &mut S) -> Result<ObjectRef> {
        match self {
            Self::Prototype(m) => m.snapshot(s),
            Self::Production(m) => m.snapshot(s),
        }
    }
    pub fn checkpoint<S: ObjectStore + ?Sized>(&mut self, s: &mut S) -> Result<ObjectRef> {
        match self {
            Self::Prototype(m) => m.checkpoint(s),
            Self::Production(m) => m.checkpoint(s),
        }
    }
    pub fn checkpoint_rebuild<S: ObjectStore + ?Sized>(&mut self, s: &mut S) -> Result<ObjectRef> {
        match self {
            Self::Prototype(m) => m.checkpoint_rebuild(s),
            Self::Production(m) => m.checkpoint(s),
        }
    }
    pub fn verify<S: ObjectStore + ?Sized>(&self, s: &S) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
        match self {
            Self::Prototype(m) => m.verify(s),
            Self::Production(m) => m.verify(s),
        }
    }
    pub fn overlay_len(&self) -> u64 {
        match self {
            Self::Prototype(m) => m.overlay_len(),
            Self::Production(m) => m.overlay_len(),
        }
    }
    pub fn reader<'a, S: ObjectStore + ?Sized>(&self, s: &'a S) -> Result<DualReader<'a, S>> {
        match self {
            Self::Prototype(m) => m.reader(s).map(DualReader::Prototype),
            Self::Production(m) => m.reader(s).map(DualReader::Production),
        }
    }
}
