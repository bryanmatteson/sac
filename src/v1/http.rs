//! Version-pinned, bounded HTTP byte ranges. Discovery is counted separately
//! from the two core admission reads. A changed representation invalidates the
//! source; an ignored Range never silently downloads the complete container.
use super::{Error, ReadAt, Result, corrupt};
use reqwest::{StatusCode, blocking::Client, header};
use std::{
    collections::VecDeque,
    io::Read,
    sync::Mutex,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug)]
pub struct HttpLimits {
    pub max_range_bytes: usize,
    pub request_timeout: Duration,
    /// Resident raw payload plus allocated LRU entry slots (not decoded objects).
    pub max_cache_bytes: usize,
    /// Maximum backward coalescing for small reads; zero issues exact ranges.
    pub read_ahead_bytes: usize,
    /// Aggregate requested response-body bytes, including the overflow probe.
    pub max_wire_bytes: u64,
}
impl Default for HttpLimits {
    fn default() -> Self {
        Self {
            max_range_bytes: 9 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            max_cache_bytes: 1024 * 1024,
            read_ahead_bytes: 0,
            max_wire_bytes: 256 * 1024 * 1024 * 1024,
        }
    }
}
impl HttpLimits {
    /// Coalesce the earlier bytes/frame adjacent to a small extent page. Large
    /// control reads remain exact so admission does not grow by a read-ahead.
    pub fn interactive() -> Self {
        Self {
            read_ahead_bytes: 32 * 1024,
            ..Self::default()
        }
    }
}
struct CacheEntry {
    offset: u64,
    bytes: Box<[u8]>,
}
struct RawCache {
    entries: VecDeque<CacheEntry>,
    payload_bytes: usize,
    metadata_bytes: usize,
    budget: usize,
}
impl RawCache {
    fn new(budget: usize) -> Self {
        // Fixed entry-count ceiling also bounds bookkeeping for one-byte reads.
        // Reserve slots up front and charge their actual allocated capacity.
        let slots = (budget / (std::mem::size_of::<CacheEntry>() + 128)).min(256);
        let entries = VecDeque::with_capacity(slots);
        let metadata_bytes = entries.capacity() * std::mem::size_of::<CacheEntry>();
        if metadata_bytes > budget {
            return Self {
                entries: VecDeque::new(),
                payload_bytes: 0,
                metadata_bytes: 0,
                budget,
            };
        }
        Self {
            entries,
            payload_bytes: 0,
            metadata_bytes,
            budget,
        }
    }
    fn capacity(&self) -> usize {
        self.budget.saturating_sub(self.metadata_bytes)
    }
    fn clear(&mut self) {
        self.entries.clear();
        self.payload_bytes = 0;
    }
    fn copy(&mut self, offset: u64, bytes: &mut [u8]) -> bool {
        let end = offset + bytes.len() as u64;
        if let Some(index) = self
            .entries
            .iter()
            .position(|e| offset >= e.offset && end <= e.offset + e.bytes.len() as u64)
        {
            let entry = self.entries.remove(index).unwrap();
            let start = (offset - entry.offset) as usize;
            bytes.copy_from_slice(&entry.bytes[start..start + bytes.len()]);
            self.entries.push_back(entry);
            true
        } else {
            false
        }
    }
    fn prepare(&mut self, length: usize) {
        while !self.entries.is_empty()
            && (self.entries.len() == self.entries.capacity()
                || self.payload_bytes + length > self.capacity())
        {
            if let Some(old) = self.entries.pop_front() {
                self.payload_bytes -= old.bytes.len();
            }
        }
    }
    fn insert(&mut self, offset: u64, bytes: Box<[u8]>) {
        if self.entries.capacity() == 0 || bytes.len() > self.capacity() {
            return;
        }
        self.prepare(bytes.len());
        self.payload_bytes += bytes.len();
        self.entries.push_back(CacheEntry { offset, bytes });
    }
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HttpStatistics {
    pub discovery_requests: u64,
    pub range_requests: u64,
    pub requested_bytes: u64,
    /// Actual response-body bytes consumed, excluding HTTP/TLS headers.
    pub response_bytes: u64,
    /// Caller-requested raw bytes, including cache hits, before read-ahead.
    pub logical_bytes: u64,
    pub cache_hits: u64,
    pub cache_payload_bytes: usize,
    pub cache_resident_bytes: usize,
}
/// One exact representation selected by a strong ETag and Content-Length.
/// The client disables redirects and automatic content decoding. HTTPS uses
/// the system's certificate trust through rustls-platform-verifier.
pub struct HttpSource {
    client: Client,
    url: reqwest::Url,
    etag: header::HeaderValue,
    length: u64,
    limits: HttpLimits,
    requests: AtomicU64,
    requested: AtomicU64,
    reserved: AtomicU64,
    returned: AtomicU64,
    invalidated: AtomicBool,
    logical: AtomicU64,
    hits: AtomicU64,
    cache: Mutex<RawCache>,
}
fn network(error: reqwest::Error) -> Error {
    // Do not include a URL that might carry credentials or a secret query.
    Error::Io(std::io::Error::other(error.without_url()))
}
fn identity(headers: &header::HeaderMap) -> Result<()> {
    if headers
        .get(header::CONTENT_ENCODING)
        .is_some_and(|h| h.as_bytes() != b"identity")
    {
        return Err(corrupt("HTTP response changes the byte representation"));
    }
    Ok(())
}
fn decimal(value: Option<&header::HeaderValue>) -> Result<u64> {
    let value = value
        .ok_or_else(|| corrupt("HTTP length is missing"))?
        .to_str()
        .map_err(|_| corrupt("HTTP length is not ASCII"))?;
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(corrupt("HTTP length is not an unsigned decimal"));
    }
    value.parse().map_err(|_| Error::Limit("HTTP length"))
}
impl HttpSource {
    pub fn open(url: &str, limits: HttpLimits) -> Result<Self> {
        if limits.max_range_bytes == 0 || limits.request_timeout.is_zero() {
            return Err(Error::Limit("HTTP source policy"));
        }
        let url = reqwest::Url::parse(url).map_err(|_| corrupt("invalid HTTP source URL"))?;
        if !matches!(url.scheme(), "http" | "https") || url.fragment().is_some() {
            return Err(Error::Unsupported("HTTP source scheme or fragment".into()));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(limits.request_timeout)
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()
            .map_err(network)?;
        let response = client
            .head(url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CACHE_CONTROL, "no-transform")
            .send()
            .map_err(network)?;
        if response.status() != StatusCode::OK {
            return Err(Error::Unsupported(format!(
                "HTTP version discovery status {}",
                response.status()
            )));
        }
        for name in [
            header::ETAG,
            header::CONTENT_LENGTH,
            header::CONTENT_ENCODING,
        ] {
            if response.headers().get_all(name).iter().count() > 1 {
                return Err(corrupt("ambiguous HTTP discovery headers"));
            }
        }
        identity(response.headers())?;
        let length = decimal(response.headers().get(header::CONTENT_LENGTH))?;
        let etag = response
            .headers()
            .get(header::ETAG)
            .cloned()
            .ok_or_else(|| Error::Unsupported("HTTP source requires a strong ETag".into()))?;
        let value = etag.as_bytes();
        if value.len() < 2
            || value.first() != Some(&b'"')
            || value.last() != Some(&b'"')
            || value[1..value.len() - 1]
                .iter()
                .any(|b| *b == b'"' || *b < 0x21 || *b == 0x7f)
        {
            return Err(Error::Unsupported(
                "HTTP source requires a strong ETag".into(),
            ));
        }
        Ok(Self {
            client,
            url,
            etag,
            length,
            limits,
            requests: AtomicU64::new(0),
            requested: AtomicU64::new(0),
            reserved: AtomicU64::new(0),
            returned: AtomicU64::new(0),
            invalidated: AtomicBool::new(false),
            logical: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            cache: Mutex::new(RawCache::new(limits.max_cache_bytes)),
        })
    }
    pub fn statistics(&self) -> HttpStatistics {
        let cache = self.cache.lock().unwrap_or_else(|error| error.into_inner());
        HttpStatistics {
            discovery_requests: 1,
            range_requests: self.requests.load(Ordering::Relaxed),
            requested_bytes: self.requested.load(Ordering::Relaxed),
            response_bytes: self.returned.load(Ordering::Relaxed),
            logical_bytes: self.logical.load(Ordering::Relaxed),
            cache_hits: self.hits.load(Ordering::Relaxed),
            cache_payload_bytes: cache.payload_bytes,
            cache_resident_bytes: cache.metadata_bytes + cache.payload_bytes,
        }
    }
    pub fn etag(&self) -> &[u8] {
        self.etag.as_bytes()
    }
    fn changed(&self, message: &str) -> Error {
        self.invalidated.store(true, Ordering::Release);
        corrupt(message)
    }
}
impl ReadAt for HttpSource {
    fn len(&self) -> Result<u64> {
        if self.invalidated.load(Ordering::Acquire) {
            return Err(corrupt("HTTP source view has been invalidated"));
        }
        Ok(self.length)
    }
    fn read_exact_at(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        self.len()?;
        let end = offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::Limit("HTTP range extent"))?;
        if bytes.len() > self.limits.max_range_bytes {
            return Err(Error::Limit("HTTP range bytes"));
        }
        if end > self.length {
            return Err(corrupt("HTTP range outside pinned representation"));
        }
        if bytes.is_empty() {
            return Ok(());
        }
        self.logical
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        // Serialize cache lookup/fetch so observed version invalidation prevents
        // a concurrent cache hit from returning a stale pinned representation.
        let mut cache = self.cache.lock().map_err(|_| Error::Poisoned)?;
        self.len()?;
        if cache.copy(offset, bytes) {
            self.hits.fetch_add(1, Ordering::Relaxed);
            self.len()?;
            return Ok(());
        }
        let extra = if bytes.len() <= self.limits.read_ahead_bytes && cache.entries.capacity() != 0
        {
            self.limits
                .read_ahead_bytes
                .min(self.limits.max_range_bytes.saturating_sub(bytes.len()))
                .min(cache.capacity().saturating_sub(bytes.len()))
        } else {
            0
        };
        let start = offset.saturating_sub(extra as u64);
        let span = usize::try_from(end - start).map_err(|_| Error::Limit("HTTP range extent"))?;
        // Include the single overflow probe before initiating the operation.
        let reservation = (span as u64)
            .checked_add(1)
            .ok_or(Error::Limit("HTTP wire bytes"))?;
        if reservation
            > self
                .limits
                .max_wire_bytes
                .saturating_sub(self.reserved.load(Ordering::Relaxed))
        {
            return Err(Error::Limit("HTTP wire bytes"));
        }
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.reserved.fetch_add(reservation, Ordering::Relaxed);
        self.requested.fetch_add(span as u64, Ordering::Relaxed);
        let result = if span <= cache.capacity() && cache.entries.capacity() != 0 {
            // Reserve the incoming payload before allocation so old entries
            // and the fetch buffer never exceed the same resident byte budget.
            cache.prepare(span);
            let mut fetched = vec![0; span];
            let result = self.fetch(start, &mut fetched);
            if result.is_ok() {
                bytes.copy_from_slice(&fetched[(offset - start) as usize..]);
                cache.insert(start, fetched.into_boxed_slice());
            }
            result
        } else {
            self.fetch(offset, bytes)
        };
        if self.invalidated.load(Ordering::Acquire) {
            cache.clear();
        }
        result
    }
}
impl HttpSource {
    fn fetch(&self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        let end = offset + bytes.len() as u64;
        let response = self
            .client
            .get(self.url.clone())
            .header(header::ACCEPT_ENCODING, "identity")
            .header(header::CACHE_CONTROL, "no-transform")
            .header(header::IF_MATCH, self.etag.clone())
            .header(header::RANGE, format!("bytes={offset}-{}", end - 1))
            .send()
            .map_err(network)?;
        if response.status() == StatusCode::OK {
            self.invalidated.store(true, Ordering::Release);
            return Err(Error::Unsupported(
                "HTTP server ignored Range; a full download was not authorized".into(),
            ));
        }
        if response.status() == StatusCode::PRECONDITION_FAILED {
            return Err(self.changed("HTTP source version changed"));
        }
        if response.status() != StatusCode::PARTIAL_CONTENT {
            return Err(Error::Unsupported(format!(
                "HTTP range status {}",
                response.status()
            )));
        }
        for name in [
            header::ETAG,
            header::CONTENT_RANGE,
            header::CONTENT_LENGTH,
            header::CONTENT_ENCODING,
        ] {
            if response.headers().get_all(name).iter().count() > 1 {
                return Err(self.changed("ambiguous HTTP range headers"));
            }
        }
        if identity(response.headers()).is_err() {
            return Err(self.changed("HTTP range changed content encoding"));
        }
        if response.headers().get(header::ETAG) != Some(&self.etag) {
            return Err(self.changed("HTTP source ETag changed or missing"));
        }
        let expected = format!("bytes {offset}-{}/{length}", end - 1, length = self.length);
        if response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            != Some(expected.as_str())
        {
            return Err(self.changed("HTTP Content-Range does not match pinned request"));
        }
        if response.headers().contains_key(header::CONTENT_LENGTH)
            && decimal(response.headers().get(header::CONTENT_LENGTH))? != bytes.len() as u64
        {
            return Err(self.changed("HTTP response length differs from requested range"));
        }
        // The destination already has the caller's bounded allocation. Stream
        // directly into it and probe exactly one additional byte for overflow.
        let mut response = response;
        let mut done = 0;
        while done < bytes.len() {
            let n = response.read(&mut bytes[done..]).map_err(|error| {
                self.invalidated.store(true, Ordering::Release);
                Error::Io(error)
            })?;
            self.returned.fetch_add(n as u64, Ordering::Relaxed);
            if n == 0 {
                return Err(self.changed("short HTTP range response"));
            }
            done += n;
        }
        let mut extra = [0];
        let n = response.read(&mut extra).map_err(|error| {
            self.invalidated.store(true, Ordering::Release);
            Error::Io(error)
        })?;
        self.returned.fetch_add(n as u64, Ordering::Relaxed);
        if n != 0 {
            return Err(self.changed("oversized HTTP range response"));
        }
        self.len()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };
    fn server<T: AsRef<[u8]> + Send + 'static>(
        responses: Vec<T>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/archive.sac", listener.local_addr().unwrap());
        let join = thread::spawn(move || {
            responses
                .into_iter()
                .map(|response| {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut request = Vec::new();
                    let mut byte = [0];
                    while !request.ends_with(b"\r\n\r\n") {
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                        assert!(request.len() < 16384);
                    }
                    stream.write_all(response.as_ref()).unwrap();
                    String::from_utf8(request).unwrap().to_ascii_lowercase()
                })
                .collect()
        });
        (url, join)
    }
    fn head() -> String {
        "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n".into()
    }
    fn range(extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 206 Partial Content\r\nETag: \"v1\"\r\nContent-Range: bytes 2-5/8\r\nConnection: close\r\n{extra}\r\n{body}"
        )
    }
    #[test]
    fn exact_conditional_ranges_and_budgets() {
        let (url, join) = server(vec![head(), range("Content-Length: 4\r\n", "cdef")]);
        let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
        let mut data = [0; 4];
        source.read_exact_at(2, &mut data).unwrap();
        assert_eq!(&data, b"cdef");
        assert!(source.read_exact_at(7, &mut data).is_err());
        let stats = source.statistics();
        assert_eq!(
            (
                stats.discovery_requests,
                stats.range_requests,
                stats.requested_bytes,
                stats.response_bytes,
                stats.logical_bytes
            ),
            (1, 1, 4, 4, 4)
        );
        assert!(stats.cache_resident_bytes <= source.limits.max_cache_bytes);
        let requests = join.join().unwrap();
        assert!(requests[0].starts_with("head "));
        assert!(requests[1].contains("if-match: \"v1\""));
        assert!(requests[1].contains("range: bytes=2-5"));
    }
    #[test]
    fn reject_changed_ignored_mismatched_encoded_and_oversized_responses() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nabcdefgh".into(),
            range("Content-Length: 4\r\n", "cdef").replace("\"v1\"", "\"v2\""),
            range("Content-Length: 4\r\n", "cdef").replace("bytes 2-5/8", "bytes 2-5/9"),
            range("Content-Length: 4\r\nContent-Encoding: gzip\r\n", "cdef"),
            range("", "cdefg"),
            range("Content-Length: 4\r\n", "cde"),
        ] {
            let (url, join) = server(vec![head(), response]);
            let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
            assert!(source.read_exact_at(2, &mut [0; 4]).is_err());
            join.join().unwrap();
        }
    }
    #[test]
    fn reject_weak_versions_and_budget_before_range_request() {
        let (url, join) = server(vec![head().replace("ETag: \"v1\"", "ETag: W/\"v1\"")]);
        assert!(HttpSource::open(&url, HttpLimits::default()).is_err());
        join.join().unwrap();
        let (url, join) = server(vec![head()]);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_range_bytes: 3,
                ..HttpLimits::default()
            },
        )
        .unwrap();
        assert!(matches!(
            source.read_exact_at(2, &mut [0; 4]),
            Err(Error::Limit(_))
        ));
        assert_eq!(source.statistics().range_requests, 0);
        join.join().unwrap();
    }

    #[test]
    fn actual_live_admission_uses_one_discovery_and_two_conditional_ranges() {
        use crate::v1::{Header, MemoryStore, Reader, resources::ArchiveBuilder};
        let mut memory = MemoryStore::new(Header::new([1; 16], [2; 16]));
        let snapshot = ArchiveBuilder::new(&mut memory).finish().unwrap();
        memory.publish(snapshot).unwrap();
        let bytes = memory.as_bytes();
        let first = crate::v1::BOOTSTRAP_SIZE;
        let control_start =
            crate::v1::wire::control_start(12288, bytes.len() as u64).unwrap() as usize;
        let mut responses=vec![format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"live-v1\"\r\nConnection: close\r\n\r\n",bytes.len()).into_bytes()];
        for (start, end) in [(0, first), (control_start, bytes.len())] {
            let mut response=format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nETag: \"live-v1\"\r\nConnection: close\r\n\r\n",end-start,start,end-1,bytes.len()).into_bytes();
            response.extend_from_slice(&bytes[start..end]);
            responses.push(response);
        }
        let (url, join) = server(responses);
        let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
        let reader = Reader::open_at(&source).unwrap();
        assert_eq!(reader.snapshot().unwrap().hash, snapshot.hash);
        let stats = source.statistics();
        assert_eq!(stats.discovery_requests, 1);
        assert_eq!(stats.range_requests, 2);
        assert!(stats.response_bytes <= 76 * 1024);
        reader.get_at(&source, reader.snapshot().unwrap()).unwrap();
        let mut wrong = reader.snapshot().unwrap();
        wrong.hash.0[0] ^= 1;
        assert!(reader.get_at(&source, wrong).is_err());
        assert_eq!(source.statistics().range_requests, 2);
        assert_eq!(source.statistics().cache_hits, 2);
        let requests = join.join().unwrap();
        assert_eq!(requests.len(), 3);
        assert!(
            requests[1..]
                .iter()
                .all(|r| r.contains("if-match: \"live-v1\""))
        );
    }

    #[test]
    fn version_change_permanently_invalidates_view() {
        let (url, join) = server(vec![
            head(),
            range("Content-Length: 4\r\n", "cdef").replace("\"v1\"", "\"v2\""),
        ]);
        let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
        assert!(source.read_exact_at(2, &mut [0; 4]).is_err());
        assert!(source.len().is_err());
        assert!(source.read_exact_at(2, &mut [0; 4]).is_err());
        assert_eq!(source.statistics().range_requests, 1);
        join.join().unwrap();
    }
    fn range_at(start: usize, end: usize, body: &str) -> String {
        format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nETag: \"v1\"\r\nContent-Range: bytes {}-{}/8\r\nConnection: close\r\n\r\n{body}",
            end - start,
            start,
            end - 1
        )
    }
    #[test]
    fn raw_cache_hits_subranges_and_repeated_reads_without_new_requests() {
        let (url, join) = server(vec![head(), range_at(2, 6, "cdef")]);
        let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
        source.read_exact_at(2, &mut [0; 4]).unwrap();
        let mut part = [0; 2];
        source.read_exact_at(3, &mut part).unwrap();
        assert_eq!(&part, b"de");
        source.read_exact_at(2, &mut [0; 4]).unwrap();
        let stats = source.statistics();
        assert_eq!(
            (
                stats.range_requests,
                stats.requested_bytes,
                stats.response_bytes,
                stats.logical_bytes,
                stats.cache_hits
            ),
            (1, 4, 4, 10, 2)
        );
        assert_eq!(stats.cache_payload_bytes, 4);
        assert!(stats.cache_resident_bytes <= source.limits.max_cache_bytes);
        assert_eq!(join.join().unwrap().len(), 2);
    }
    #[test]
    fn lru_eviction_and_disabled_cache_never_exceed_the_budget() {
        let (url, join) = server(vec![
            head(),
            range_at(0, 2, "ab"),
            range_at(2, 4, "cd"),
            range_at(4, 6, "ef"),
            range_at(2, 4, "cd"),
        ]);
        let budget = 2 * (std::mem::size_of::<CacheEntry>() + 128);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_cache_bytes: budget,
                ..HttpLimits::default()
            },
        )
        .unwrap();
        for offset in [0, 2, 0, 4, 0, 2] {
            source.read_exact_at(offset, &mut [0; 2]).unwrap();
            assert!(source.statistics().cache_resident_bytes <= budget);
        }
        assert_eq!(source.statistics().range_requests, 4);
        assert_eq!(source.statistics().cache_hits, 2);
        join.join().unwrap();
        let (url, join) = server(vec![head(), range_at(2, 6, "cdef"), range_at(2, 6, "cdef")]);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_cache_bytes: 0,
                ..HttpLimits::interactive()
            },
        )
        .unwrap();
        for _ in 0..2 {
            source.read_exact_at(2, &mut [0; 4]).unwrap();
        }
        assert_eq!(source.statistics().cache_resident_bytes, 0);
        assert_eq!(source.statistics().range_requests, 2);
        join.join().unwrap();
        let mut cache = RawCache::new(1024);
        let capacity = cache.capacity();
        cache.insert(0, vec![0; capacity].into_boxed_slice());
        cache.prepare(capacity);
        assert_eq!(cache.payload_bytes, 0);
        assert!(cache.metadata_bytes + capacity <= 1024);
    }
    #[test]
    fn backward_coalescing_is_bounded_and_accounts_wire_and_logical_bytes() {
        let (url, join) = server(vec![head(), range_at(2, 6, "cdef")]);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_range_bytes: 4,
                ..HttpLimits::interactive()
            },
        )
        .unwrap();
        let mut data = [0; 2];
        source.read_exact_at(4, &mut data).unwrap();
        assert_eq!(&data, b"ef");
        assert_eq!(
            (
                source.statistics().logical_bytes,
                source.statistics().response_bytes
            ),
            (2, 4)
        );
        source.read_exact_at(2, &mut data).unwrap();
        assert_eq!(&data, b"cd");
        let stats = source.statistics();
        assert_eq!(
            (
                stats.range_requests,
                stats.requested_bytes,
                stats.response_bytes,
                stats.logical_bytes,
                stats.cache_hits
            ),
            (1, 4, 4, 4, 1)
        );
        assert!(join.join().unwrap()[1].contains("range: bytes=2-5"));
    }
    #[test]
    fn aggregate_wire_budget_rejects_before_get() {
        let (url, join) = server(vec![head()]);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_wire_bytes: 4,
                ..HttpLimits::default()
            },
        )
        .unwrap();
        assert!(matches!(
            source.read_exact_at(2, &mut [0; 4]),
            Err(Error::Limit(_))
        ));
        assert_eq!(source.statistics().range_requests, 0);
        join.join().unwrap();
        let (url, join) = server(vec![head(), range_at(2, 6, "cdef")]);
        let source = HttpSource::open(
            &url,
            HttpLimits {
                max_wire_bytes: 7,
                ..HttpLimits::default()
            },
        )
        .unwrap();
        source.read_exact_at(2, &mut [0; 4]).unwrap();
        assert!(matches!(
            source.read_exact_at(0, &mut [0; 2]),
            Err(Error::Limit(_))
        ));
        source.read_exact_at(2, &mut [0; 4]).unwrap();
        assert_eq!(source.statistics().range_requests, 1);
        assert_eq!(source.statistics().cache_hits, 1);
        join.join().unwrap();
    }
    #[test]
    fn observed_version_change_invalidates_even_previously_cached_bytes() {
        let (url, join) = server(vec![
            head(),
            range_at(2, 6, "cdef"),
            range_at(0, 2, "ab").replace("\"v1\"", "\"v2\""),
        ]);
        let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
        source.read_exact_at(2, &mut [0; 4]).unwrap();
        assert!(source.read_exact_at(0, &mut [0; 2]).is_err());
        assert!(source.read_exact_at(2, &mut [0; 4]).is_err());
        assert_eq!(source.statistics().range_requests, 2);
        assert_eq!(source.statistics().cache_payload_bytes, 0);
        join.join().unwrap();
    }
    #[test]
    fn redirects_and_ambiguous_pin_headers_are_rejected() {
        let redirect="HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/other\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned();
        for discovery in [
            redirect.clone(),
            head().replace("ETag: \"v1\"", "ETag: \"v1\"\r\nETag: \"v2\""),
        ] {
            let (url, join) = server(vec![discovery]);
            assert!(HttpSource::open(&url, HttpLimits::default()).is_err());
            assert_eq!(join.join().unwrap().len(), 1);
        }
        for response in [
            redirect,
            range_at(2, 6, "cdef").replace("ETag: \"v1\"", "ETag: \"v1\"\r\nETag: \"v2\""),
        ] {
            let (url, join) = server(vec![head(), response]);
            let source = HttpSource::open(&url, HttpLimits::default()).unwrap();
            assert!(source.read_exact_at(2, &mut [0; 4]).is_err());
            assert_eq!(join.join().unwrap().len(), 2);
        }
    }
    #[test]
    fn interactive_actual_extent_and_sixteen_kib_shard_share_one_get() {
        use crate::v1::{
            MemoryStore, Reader,
            resources::{ArchiveBuilder, path_from_str},
        };
        let mut memory = MemoryStore::sealed();
        let mut hot = vec![0; 16384];
        let mut padding = vec![0; 131072];
        blake3::Hasher::new()
            .update(b"HTTP hot shard")
            .finalize_xof()
            .fill(&mut hot);
        blake3::Hasher::new()
            .update(b"HTTP trailing payload")
            .finalize_xof()
            .fill(&mut padding);
        let mut builder = ArchiveBuilder::new(&mut memory);
        builder.set_page_limit(8192).unwrap();
        builder
            .add_file(&path_from_str("hot").unwrap(), &hot)
            .unwrap();
        builder
            .add_file(&path_from_str("padding").unwrap(), &padding)
            .unwrap();
        let snapshot = builder.finish().unwrap();
        memory.publish(snapshot).unwrap();
        let bytes = memory.as_bytes();
        let local = Reader::open_at(&bytes).unwrap();
        let root = local.get_at(&bytes, local.snapshot().unwrap()).unwrap();
        let directory = local.get_at(&bytes, root.children[0]).unwrap();
        let extent = directory.children[0];
        let shard = local.get_at(&bytes, extent).unwrap().children[0];
        let control = crate::v1::wire::control_start(128, bytes.len() as u64).unwrap() as usize;
        assert!(extent.address.offset + u64::from(extent.address.length) < control as u64);
        let start = extent.address.offset.saturating_sub(32768) as usize;
        let end = extent.address.offset as usize + extent.address.length as usize;
        let mut responses=vec![format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",bytes.len()).into_bytes()];
        for (start, end) in [
            (0, crate::v1::BOOTSTRAP_SIZE),
            (control, bytes.len()),
            (start, end),
        ] {
            let mut response=format!("HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nETag: \"v1\"\r\nConnection: close\r\n\r\n",end-start,start,end-1,bytes.len()).into_bytes();
            response.extend_from_slice(&bytes[start..end]);
            responses.push(response);
        }
        let (url, join) = server(responses);
        let source = HttpSource::open(&url, HttpLimits::interactive()).unwrap();
        let reader = Reader::open_at(&source).unwrap();
        assert_eq!(source.statistics().range_requests, 2);
        assert!(source.statistics().response_bytes <= 76 * 1024);
        reader.get_at(&source, extent).unwrap();
        let after_extent = source.statistics();
        assert_eq!(after_extent.range_requests, 3);
        let object = reader.get_at(&source, shard).unwrap();
        assert_eq!(object.bytes, hot);
        assert_eq!(source.statistics().range_requests, 3);
        assert_eq!(
            source.statistics().response_bytes,
            after_extent.response_bytes
        );
        assert_eq!(join.join().unwrap().len(), 4);
    }
}
