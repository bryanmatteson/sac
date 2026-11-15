use super::*;
#[derive(Clone)]
#[doc(hidden)]
pub enum Value {
    Inline(Vec<u8>),
    Blob { length: usize, reference: ObjectRef },
}
impl Value {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Inline(bytes) => bytes.len(),
            Self::Blob { length, .. } => *length,
        }
    }
    pub(crate) fn validate<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<()> {
        if let Self::Blob { length, reference } = self {
            let object = store.get_verified_shared(*reference)?;
            if object.kind != 7
                || object.version != 1
                || !object.children.is_empty()
                || object.bytes.len() != *length
            {
                return Err(bad("blob type/length"));
            }
        }
        Ok(())
    }
    pub(crate) fn read<S: ObjectStore + ?Sized>(&self, store: &S) -> Result<Vec<u8>> {
        match self {
            Self::Inline(bytes) => Ok(bytes.clone()),
            Self::Blob { length, reference } => {
                let object = store.get_verified_shared(*reference)?;
                if object.kind != 7
                    || object.version != 1
                    || !object.children.is_empty()
                    || object.bytes.len() != *length
                {
                    return Err(bad("blob type/length"));
                }
                Ok(object.bytes.clone())
            }
        }
    }
}
