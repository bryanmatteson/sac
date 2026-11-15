//! Disposable facts for one physical validation. Every fact is keyed by the
//! complete authenticated occurrence; it says nothing about another locator.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Fact {
    kind: u16,
    version: u16,
    measure: u64,
}
impl Fact {
    pub fn from_frame(frame: &wire::FrameView<'_>) -> Result<Self> {
        let measure = if matches!(frame.kind, 4 | 6) {
            cbor_view::admitted(frame.body)?.first_field(2)?.uint()?
        } else {
            frame.body.len() as u64
        };
        Ok(Self {
            kind: frame.kind,
            version: frame.version,
            measure,
        })
    }
    pub fn encode(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..2].copy_from_slice(&self.kind.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.version.to_le_bytes());
        bytes[4..].copy_from_slice(&self.measure.to_le_bytes());
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            kind: u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            version: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            measure: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
        }
    }
}

/// A fixed-width direct role requirement. A zero mask has no role constraint;
/// all nonzero masks require schema 1. The optional measure is a branch height
/// or an extent byte length. Profile name/type/version bindings still borrow
/// their actual authenticated body for comparison.
#[derive(Clone, Copy, Default)]
pub(super) struct Role {
    kinds: u16,
    measure_kind: u8,
    measure: u64,
}
impl Role {
    pub const ANY: Self = Self {
        kinds: 0,
        measure_kind: 0,
        measure: 0,
    };
    pub fn from_core(role: schema::CoreRole<'_>) -> Option<Self> {
        use schema::CoreRole;
        Some(match role {
            CoreRole::Kinds(a, b) => Self {
                kinds: (1 << a) | (1 << b),
                ..Self::ANY
            },
            CoreRole::Branch { kind, height } => Self {
                kinds: 1 << kind,
                measure_kind: 1,
                measure: height,
            },
            CoreRole::Bytes(length) => Self {
                kinds: 1 << 7,
                measure_kind: 2,
                measure: length,
            },
            CoreRole::Profile { .. } => return None,
        })
    }
    pub fn merge(&mut self, other: Self) -> Result<()> {
        if other.kinds == 0 {
            return Ok(());
        }
        if self.kinds == 0 {
            *self = other;
            return Ok(());
        }
        self.kinds &= other.kinds;
        if self.kinds == 0 {
            return Err(corrupt("core child role kind or schema"));
        }
        if other.measure_kind != 0 {
            if self.measure_kind != 0
                && (self.measure_kind != other.measure_kind || self.measure != other.measure)
            {
                return Err(corrupt(if other.measure_kind == 1 {
                    "core branch child height"
                } else {
                    "extent byte length"
                }));
            }
            self.measure_kind = other.measure_kind;
            self.measure = other.measure;
        }
        Ok(())
    }
    pub fn check(self, fact: Fact) -> Result<()> {
        if self.kinds == 0 {
            return Ok(());
        }
        if fact.version != 1 || fact.kind >= 16 || self.kinds & (1 << fact.kind) == 0 {
            return Err(corrupt("core child role kind or schema"));
        }
        if self.measure_kind != 0 && self.measure != fact.measure {
            return Err(corrupt(if self.measure_kind == 1 {
                "core branch child height"
            } else {
                "extent byte length"
            }));
        }
        Ok(())
    }
    fn encode(self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[..2].copy_from_slice(&self.kinds.to_le_bytes());
        bytes[2] = self.measure_kind;
        bytes[4..].copy_from_slice(&self.measure.to_le_bytes());
        bytes
    }
    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes[2] > 2 || bytes[3] != 0 {
            return Err(corrupt("temporary traversal role"));
        }
        Ok(Self {
            kinds: u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            measure_kind: bytes[2],
            measure: u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
        })
    }
}

pub(super) struct Pending(super::spill::DiskStack<56>);
impl Pending {
    pub fn new(budget: temporary::Budget) -> Result<Self> {
        Ok(Self(super::spill::DiskStack::with_budget(256, budget)?))
    }
    pub fn push(&mut self, reference: ObjectRef, role: Role) -> Result<()> {
        let mut bytes = [0; 56];
        bytes[..44].copy_from_slice(&super::spill::encode_ref(reference));
        bytes[44..].copy_from_slice(&role.encode());
        self.0.push_record(bytes)
    }
    pub fn pop(&mut self) -> Result<Option<(ObjectRef, Role)>> {
        self.0
            .pop_record()?
            .map(|bytes| {
                Ok((
                    super::spill::decode_ref(&bytes[..44])?,
                    Role::decode(&bytes[44..])?,
                ))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_roles_survive_spill_and_refill_without_losing_large_lengths() {
        let budget = temporary::Budget::new(1 << 20);
        let mut pending = Pending::new(budget.clone()).unwrap();
        for index in 0..1025u64 {
            pending
                .push(
                    ObjectRef {
                        hash: ObjectHash::digest(&index.to_le_bytes()),
                        address: ChunkAddress {
                            offset: 128 + 64 * index,
                            length: 64,
                        },
                    },
                    Role::from_core(schema::CoreRole::Bytes(u64::MAX - index)).unwrap(),
                )
                .unwrap();
        }
        assert!(budget.used() > 0);
        for index in (0..1025u64).rev() {
            let (reference, role) = pending.pop().unwrap().unwrap();
            assert_eq!(reference.hash, ObjectHash::digest(&index.to_le_bytes()));
            assert_eq!(reference.address.offset, 128 + 64 * index);
            assert!(
                role.check(Fact {
                    kind: 7,
                    version: 1,
                    measure: u64::MAX - index
                })
                .is_ok()
            );
            assert!(
                role.check(Fact {
                    kind: 7,
                    version: 1,
                    measure: index
                })
                .is_err()
            );
        }
        assert!(pending.pop().unwrap().is_none());
        drop(pending);
        assert_eq!(budget.used(), 0);
    }
}
