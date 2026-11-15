//! Disposable facts for one physical validation. Every fact is keyed by the
//! complete authenticated occurrence; it says nothing about another locator.
use super::*;

const _: () = {
    assert!(MAX_CHUNK_SIZE + wire::FRAME + 12 * MAX_CHILDREN + 7 < 1 << 24);
};

fn measure(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0])
}

/// The header has already passed frame_span's stored/decoded/child bounds.
pub(super) fn record(span: u32, decoded: u32) -> [u8; 6] {
    let mut bytes = [0; 6];
    bytes[..3].copy_from_slice(&span.to_le_bytes()[..3]);
    bytes[3..].copy_from_slice(&decoded.to_le_bytes()[..3]);
    bytes
}

pub(super) fn record_decoded(bytes: &[u8], span: u32) -> Result<u64> {
    if measure(bytes) != span {
        return Err(corrupt("reachable locator span"));
    }
    Ok(u64::from(measure(&bytes[3..])))
}

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
    pub fn encode(self) -> [u8; 4] {
        // Direct roles require schema 1 and a kind below 16. Other types all
        // reject those roles; ANY needs only the authenticated occurrence key.
        // Body lengths and admitted branch heights fit in the low 24 bits.
        // Incoming role requirements still retain their complete u64 value.
        if self.version != 1 || self.kind >= 16 {
            return [0, 0, 0, 255];
        }
        let mut bytes = [0; 4];
        bytes[..3].copy_from_slice(&(self.measure as u32).to_le_bytes()[..3]);
        bytes[3] = self.kind as u8;
        bytes
    }
    pub fn decode(bytes: &[u8]) -> Self {
        Self {
            kind: u16::from(bytes[3]),
            version: u16::from(bytes[3] < 16),
            measure: u64::from(measure(bytes)),
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
    fn compact_facts_preserve_every_direct_role_decision() {
        let mut roles = vec![Role::ANY];
        for kind in 0..16 {
            roles.push(Role::from_core(schema::CoreRole::Kinds(kind, kind)).unwrap());
        }
        for length in [0, 4, 16, MAX_CHUNK_SIZE as u64 - 8, (1 << 32) + 4, u64::MAX] {
            roles.push(Role::from_core(schema::CoreRole::Bytes(length)).unwrap());
        }
        for kind in [4, 6] {
            for height in [0, 16, u64::MAX] {
                roles.push(Role::from_core(schema::CoreRole::Branch { kind, height }).unwrap());
            }
        }
        for kind in (0..=20).chain([255, u16::MAX]) {
            for version in [0, 1, 2, u16::MAX] {
                for measure in [0, 4, 16, MAX_CHUNK_SIZE as u64 - 8] {
                    let original = Fact {
                        kind,
                        version,
                        measure,
                    };
                    let bytes = original.encode();
                    assert_eq!(bytes.len(), 4);
                    let packed = Fact::decode(&bytes);
                    for role in &roles {
                        assert_eq!(
                            role.check(original).is_ok(),
                            role.check(packed).is_ok(),
                            "kind={kind} version={version} measure={measure}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn compact_inventory_retains_maximum_header_bounds_and_full_span_checks() {
        let maximum = ((wire::FRAME + MAX_CHUNK_SIZE + 12 * MAX_CHILDREN + 7) & !7) as u32;
        for (span, decoded) in [(64, 8), (maximum, MAX_CHUNK_SIZE as u32)] {
            let packed = record(span, decoded);
            assert_eq!(packed.len(), 6);
            assert_eq!(record_decoded(&packed, span).unwrap(), u64::from(decoded));
            assert!(record_decoded(&packed, span + 8).is_err());
            assert!(record_decoded(&packed, span + (1 << 24)).is_err());
        }
    }

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
