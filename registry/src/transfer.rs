use std::io::Read;

/// Counting adapter enforcing a hard byte cap on a streamed body
/// Independent of any length the peer or the layout declared. Mandatory
/// On every streamed remote GET (7)
pub struct CappedReader<R> {
    inner: R,
    consumed: u64,
    cap: u64,
}

impl<R: Read> CappedReader<R> {
    #[must_use]
    pub fn new(inner: R, cap: u64) -> Self {
        Self {
            inner,
            consumed: 0,
            cap,
        }
    }
}

impl<R: Read> Read for CappedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.consumed = self.consumed.saturating_add(n as u64);
        if self.consumed > self.cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("streamed body exceeded the {}-byte cap", self.cap),
            ));
        }
        Ok(n)
    }
}
